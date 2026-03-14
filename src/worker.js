// Pineapple Tours Live Dashboard — Cloudflare Worker
// dashboard.pineappletours.com.au
// Live data: Rezdy bookings, Stripe revenue, PageSpeed

const CF_ACCESS_AUD = "6242de50878373502990b8b40d2b33f1d556988a5a829e06a81f3dfa63da7d5d";
const CF_JWKS_URL = "https://pineapples.cloudflareaccess.com/cdn-cgi/access/certs";
const PASSWORD = "pineapple2026";
const COOKIE_NAME = "oc_auth";
const COOKIE_VALUE = "granted_petermyers";

async function validateCFAccessJWT(request) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return false;
  try {
    const jwksRes = await fetch(CF_JWKS_URL);
    const jwks = await jwksRes.json();
    const [headerB64] = token.split(".");
    const header = JSON.parse(atob(headerB64.replace(/-/g,"+").replace(/_/g,"/")));
    const key = jwks.keys.find(k => k.kid === header.kid);
    if (!key) return false;
    const cryptoKey = await crypto.subtle.importKey("jwk", key, {name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"}, false, ["verify"]);
    const [, payloadB64, sigB64] = token.split(".");
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = Uint8Array.from(atob(sigB64.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, signingInput);
    if (!valid) return false;
    const payload = JSON.parse(atob(payloadB64.replace(/-/g,"+").replace(/_/g,"/")));
    if (payload.aud !== CF_ACCESS_AUD && !payload.aud?.includes?.(CF_ACCESS_AUD)) return false;
    if (payload.exp < Math.floor(Date.now() / 1000)) return false;
    return true;
  } catch(e) { return false; }
}

// Fetch live Rezdy data
async function getRezdyData(apiKey) {
  try {
    const now = new Date();
    const weekAgo = new Date(now - 7*24*60*60*1000);
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const fmt = d => d.toISOString().slice(0,10);

    const [weekRes, mtdRes, upcomingRes] = await Promise.all([
      fetch(`https://api.rezdy.com/v1/bookings?apiKey=${apiKey}&limitNum=100&createdAfterDate=${fmt(weekAgo)}`),
      fetch(`https://api.rezdy.com/v1/bookings?apiKey=${apiKey}&limitNum=100&createdAfterDate=${fmt(monthStart)}`),
      fetch(`https://api.rezdy.com/v1/bookings?apiKey=${apiKey}&limitNum=10&afterDateTime=${now.toISOString().slice(0,10)}T00:00:00&status=CONFIRMED`)
    ]);

    const [weekData, mtdData, upcomingData] = await Promise.all([weekRes.json(), mtdRes.json(), upcomingRes.json()]);

    const weekBookings = weekData.bookings || [];
    const mtdBookings = mtdData.bookings || [];
    const upcoming = upcomingData.bookings || [];

    const weekConfirmed = weekBookings.filter(b => b.status === 'CONFIRMED');
    const mtdConfirmed = mtdBookings.filter(b => b.status === 'CONFIRMED');
    const weekRevenue = weekConfirmed.reduce((s,b) => s + parseFloat(b.totalAmount||0), 0);
    const mtdRevenue = mtdConfirmed.reduce((s,b) => s + parseFloat(b.totalAmount||0), 0);
    const weekCancelled = weekBookings.filter(b => b.status === 'CANCELLED').length;

    return {
      weekBookings: weekConfirmed.length,
      weekRevenue: weekRevenue.toFixed(2),
      weekCancelled,
      mtdBookings: mtdConfirmed.length,
      mtdRevenue: mtdRevenue.toFixed(2),
      upcoming: upcoming.slice(0,5).map(b => ({
        ref: b.orderNumber,
        name: b.customer ? `${b.customer.firstName} ${b.customer.lastName}` : 'Guest',
        tour: b.items?.[0]?.productName || 'Tour',
        date: b.items?.[0]?.startTimeLocal?.slice(0,10) || '—',
        amount: parseFloat(b.totalAmount||0).toFixed(2)
      }))
    };
  } catch(e) {
    return { error: e.message };
  }
}

// Fetch PageSpeed score
async function getPageSpeed() {
  try {
    const res = await fetch('https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://pineappletours.com.au&strategy=mobile&category=performance&category=seo');
    const d = await res.json();
    const cats = d.lighthouseResult?.categories || {};
    return {
      performance: Math.round((cats.performance?.score||0)*100),
      seo: Math.round((cats.seo?.score||0)*100),
      lcp: d.lighthouseResult?.audits?.['largest-contentful-paint']?.displayValue || '—',
      cls: d.lighthouseResult?.audits?.['cumulative-layout-shift']?.displayValue || '—',
      fid: d.lighthouseResult?.audits?.['total-blocking-time']?.displayValue || '—'
    };
  } catch(e) {
    return { performance: '—', seo: '—', lcp: '—', cls: '—', fid: '—' };
  }
}

function scoreColor(n) {
  if (n === '—') return '#6b7280';
  if (n >= 90) return '#27c27b';
  if (n >= 50) return '#f5a623';
  return '#e05252';
}

function renderDashboard(rezdy, speed) {
  const now = new Date().toLocaleString('en-AU', {timeZone:'Australia/Brisbane',dateStyle:'medium',timeStyle:'short'});
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="300">
<title>Pineapple Tours Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0f1117;color:#e8eaf0;font-family:'Inter',system-ui,sans-serif;min-height:100vh;padding:20px}
  .wrap{max-width:1200px;margin:0 auto}
  .header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;flex-wrap:wrap;gap:10px}
  .header-left{display:flex;align-items:center;gap:10px}
  .logo{width:36px;height:36px;border-radius:8px;background:#f5a623;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
  .title{font-size:20px;font-weight:700}
  .subtitle{font-size:12px;color:#6b7280;margin-top:2px}
  .live-badge{display:inline-flex;align-items:center;gap:5px;background:#101a10;border:1px solid #27c27b44;border-radius:6px;padding:3px 9px;font-size:11px;color:#27c27b}
  .live-dot{width:6px;height:6px;border-radius:50%;background:#27c27b;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
  .badges{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  .badge{border-radius:6px;padding:3px 9px;font-size:11px;font-weight:600}
  .badge-red{background:#e0525222;color:#e05252;border:1px solid #e0525244}
  .badge-orange{background:#f5a62322;color:#f5a623;border:1px solid #f5a62344}
  .badge-green{background:#27c27b22;color:#27c27b;border:1px solid #27c27b44}
  .badge-blue{background:#4d9fff22;color:#4d9fff;border:1px solid #4d9fff44}
  .tabs{display:flex;gap:4px;border-bottom:1px solid #252840;margin-bottom:18px;overflow-x:auto}
  .tab{background:transparent;color:#9ca3af;border:none;border-radius:8px 8px 0 0;padding:8px 18px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .15s}
  .tab.active{background:#f5a623;color:#000}
  .tab:hover:not(.active){color:#e8eaf0}
  .grid{display:grid;gap:14px}
  .grid-2{grid-template-columns:1fr 1fr}
  .grid-3{grid-template-columns:1fr 1fr 1fr}
  .grid-4{grid-template-columns:1fr 1fr 1fr 1fr}
  .span2{grid-column:span 2}
  .span3{grid-column:span 3}
  .span4{grid-column:span 4}
  @media(max-width:700px){.grid-2,.grid-3,.grid-4{grid-template-columns:1fr}.span2,.span3,.span4{grid-column:span 1}}
  .card{background:#1a1d2e;border:1px solid #252840;border-radius:12px;padding:16px}
  .card-urgent{background:#1e0d0d;border-color:#5a2020}
  .card-good{background:#0d1a10;border-color:#1a4a25}
  .section-title{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;color:#f5a623}
  .st-red{color:#e05252}.st-blue{color:#4d9fff}.st-green{color:#27c27b}.st-purple{color:#9b6dff}
  .kpi-box{background:#12151f;border-radius:10px;padding:14px;text-align:center;border:1px solid #252840}
  .kpi-value{font-size:26px;font-weight:800;line-height:1}
  .kpi-label{font-size:10px;color:#9ca3af;margin-top:5px;text-transform:uppercase;letter-spacing:.5px}
  .kpi-sub{font-size:11px;margin-top:3px}
  .kpi-trend{font-size:10px;margin-top:2px}
  .row{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:7px;gap:8px}
  .row-label{font-size:12px;color:#9ca3af;flex-shrink:0}
  .row-value{font-size:12px;font-weight:600;text-align:right}
  .booking-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #252840;gap:8px}
  .booking-row:last-child{border-bottom:none}
  .booking-name{font-size:12px;font-weight:600}
  .booking-detail{font-size:10px;color:#6b7280;margin-top:1px}
  .booking-amount{font-size:12px;font-weight:700;color:#27c27b;white-space:nowrap}
  .booking-date{font-size:10px;color:#4d9fff;white-space:nowrap}
  .progress-bar{height:6px;border-radius:3px;background:#252840;margin-top:5px;overflow:hidden}
  .progress-fill{height:100%;border-radius:3px;transition:width .5s}
  .highlight{border-radius:8px;padding:10px;margin-top:8px}
  .hl-green{background:#101a10;border:1px solid #27c27b44}
  .hl-orange{background:#1a1200;border:1px solid #f5a62344}
  .hl-red{background:#1e0d0d;border:1px solid #e0525244}
  .hl-title{font-size:11px;font-weight:700;margin-bottom:3px}
  .hl-text{font-size:11px;color:#e8eaf0;line-height:1.5}
  .speed-ring{display:inline-flex;align-items:center;justify-content:center;width:60px;height:60px;border-radius:50%;border:3px solid;font-size:18px;font-weight:800}
  .tag{display:inline-block;background:#0d1520;color:#4d9fff;font-family:monospace;font-size:10px;padding:2px 6px;border-radius:4px;margin:2px}
  .phase-item{font-size:11px;color:#9ca3af;display:flex;gap:6px;margin-bottom:4px}
  .refresh-note{font-size:10px;color:#6b7280;text-align:right;margin-bottom:8px}
  hr{border:none;border-top:1px solid #252840;margin:10px 0}
  .panel{display:none}
  .panel.active{display:block}
  .footer{margin-top:24px;text-align:center;font-size:10px;color:#6b7280}
  .security-badge{display:inline-flex;align-items:center;gap:4px;background:#101a10;border:1px solid #27c27b44;border-radius:6px;padding:3px 8px;font-size:10px;color:#27c27b}
  .empty-state{text-align:center;color:#6b7280;font-size:12px;padding:20px}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="header-left">
      <div class="logo">🍍</div>
      <div>
        <div class="title">Pineapple Tours</div>
        <div class="subtitle">Live Operations Dashboard · Updated ${now}</div>
      </div>
    </div>
    <div class="badges">
      <span class="live-badge"><span class="live-dot"></span>LIVE</span>
      <span class="badge badge-green">Rezdy Connected</span>
      <span class="security-badge">🔒 CF Access</span>
    </div>
  </div>

  <div class="refresh-note">⟳ Auto-refreshes every 5 minutes</div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('overview',this)">Overview</button>
    <button class="tab" onclick="showTab('bookings',this)">Bookings</button>
    <button class="tab" onclick="showTab('seo',this)">SEO & Speed</button>
    <button class="tab" onclick="showTab('marketing',this)">Marketing</button>
    <button class="tab" onclick="showTab('tech',this)">Tech</button>
  </div>

  <!-- OVERVIEW -->
  <div id="panel-overview" class="panel active">
    <div class="grid">
      <!-- Live KPIs -->
      <div class="grid grid-4">
        <div class="kpi-box">
          <div class="kpi-value" style="color:#27c27b">${rezdy.error ? '—' : rezdy.weekBookings}</div>
          <div class="kpi-label">Bookings This Week</div>
          <div class="kpi-sub" style="color:#27c27b">${rezdy.error ? 'API error' : rezdy.weekCancelled + ' cancelled'}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#f5a623">${rezdy.error ? '—' : '$' + Number(rezdy.weekRevenue).toLocaleString('en-AU',{minimumFractionDigits:0,maximumFractionDigits:0})}</div>
          <div class="kpi-label">Revenue This Week</div>
          <div class="kpi-sub" style="color:#6b7280">Rezdy confirmed</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#4d9fff">${rezdy.error ? '—' : rezdy.mtdBookings}</div>
          <div class="kpi-label">Bookings MTD</div>
          <div class="kpi-sub" style="color:#6b7280">Confirmed only</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#9b6dff">${rezdy.error ? '—' : '$' + Number(rezdy.mtdRevenue).toLocaleString('en-AU',{minimumFractionDigits:0,maximumFractionDigits:0})}</div>
          <div class="kpi-label">Revenue MTD</div>
          <div class="kpi-sub" style="color:#6b7280">Rezdy confirmed</div>
        </div>
      </div>

      <div class="grid grid-3">
        <!-- Upcoming bookings -->
        <div class="card">
          <div class="section-title st-green">✅ Upcoming Confirmed</div>
          ${rezdy.upcoming && rezdy.upcoming.length > 0
            ? rezdy.upcoming.map(b => `
              <div class="booking-row">
                <div>
                  <div class="booking-name">${b.name}</div>
                  <div class="booking-detail">${b.tour.slice(0,35)}${b.tour.length>35?'...':''}</div>
                </div>
                <div style="text-align:right">
                  <div class="booking-date">${b.date}</div>
                  <div class="booking-amount">$${Number(b.amount).toLocaleString()}</div>
                </div>
              </div>`).join('')
            : '<div class="empty-state">No upcoming bookings found</div>'}
        </div>

        <!-- Escalations -->
        <div class="card card-urgent">
          <div class="section-title st-red">🔴 Escalations</div>
          <div class="booking-row">
            <div><div class="booking-name">ATS Pacific / Frohwerk</div><div class="booking-detail">HOHO + Glow Worm · 15 Apr · TSTFRJ6485</div></div>
            <span class="badge badge-red">UNANSWERED</span>
          </div>
          <div class="booking-row">
            <div><div class="booking-name">Maddison Staader (ATIA)</div><div class="booking-detail">50-pax Canungra · 28 Aug · ~$8,250</div></div>
            <span class="badge badge-red">NEEDS TIMES</span>
          </div>
          <div class="booking-row">
            <div><div class="booking-name">Inside Australia Travel</div><div class="booking-detail">Bos party · 5 Apr · PTQVVF7Y</div></div>
            <span class="badge badge-orange">PREPAY DUE</span>
          </div>
        </div>

        <!-- Site speed snapshot -->
        <div class="card">
          <div class="section-title">⚡ Site Speed (Mobile)</div>
          <div style="display:flex;justify-content:space-around;align-items:center;margin-bottom:14px">
            <div style="text-align:center">
              <div class="speed-ring" style="border-color:${scoreColor(speed.performance)};color:${scoreColor(speed.performance)}">${speed.performance}</div>
              <div style="font-size:10px;color:#6b7280;margin-top:4px">Performance</div>
            </div>
            <div style="text-align:center">
              <div class="speed-ring" style="border-color:${scoreColor(speed.seo)};color:${scoreColor(speed.seo)}">${speed.seo}</div>
              <div style="font-size:10px;color:#6b7280;margin-top:4px">SEO Score</div>
            </div>
          </div>
          <div class="row"><span class="row-label">LCP</span><span class="row-value">${speed.lcp}</span></div>
          <div class="row"><span class="row-label">CLS</span><span class="row-value">${speed.cls}</span></div>
          <div class="row" style="margin-bottom:0"><span class="row-label">TBT</span><span class="row-value">${speed.fid}</span></div>
          ${speed.performance !== '—' && speed.performance < 50
            ? '<div class="highlight hl-red"><div class="hl-title" style="color:#e05252">⚠️ Performance critical</div><div class="hl-text">Mobile score below 50 — urgently needs optimisation</div></div>'
            : speed.performance !== '—' && speed.performance < 90
            ? '<div class="highlight hl-orange"><div class="hl-title" style="color:#f5a623">Needs improvement</div><div class="hl-text">Performance below 90 — image optimisation + caching recommended</div></div>'
            : ''}
        </div>
      </div>

      <!-- Quick actions -->
      <div class="grid grid-3">
        <div class="card">
          <div class="section-title">💰 Finance Alerts</div>
          <div class="highlight hl-red">
            <div class="hl-title" style="color:#e05252">Tamborine Intl Invoice</div>
            <div class="hl-text">$440 OVERDUE · HEN4901 · Was due 6 Mar</div>
          </div>
          <div class="highlight hl-orange" style="margin-top:8px">
            <div class="hl-title" style="color:#f5a623">Westpac Dispute</div>
            <div class="hl-text">CS138010101 · Follow up required</div>
          </div>
        </div>
        <div class="card">
          <div class="section-title">👥 Team</div>
          <div class="row"><span class="row-label">Bookings</span><span class="row-value">India · Tyler · Sharon</span></div>
          <div class="row"><span class="row-label">SEEK hiring</span><span class="row-value" style="color:#f5a623">11 applicants</span></div>
          <div class="row" style="margin-bottom:0"><span class="row-label">Role</span><span class="row-value">Tour Guide & Driver</span></div>
          <div class="highlight hl-green" style="margin-top:8px">
            <div class="hl-title" style="color:#27c27b">Disaster Assistance Grant</div>
            <div class="hl-text">Ready to sign — Emma Bloem · SBFCS</div>
          </div>
        </div>
        <div class="card">
          <div class="section-title">🔗 Quick Links</div>
          <div style="display:grid;gap:6px">
            <a href="https://beta.rezdy.com" target="_blank" style="display:block;background:#12151f;border:1px solid #252840;border-radius:6px;padding:8px 12px;font-size:12px;color:#e8eaf0;text-decoration:none">📋 Rezdy Dashboard</a>
            <a href="https://dashboard.stripe.com" target="_blank" style="display:block;background:#12151f;border:1px solid #252840;border-radius:6px;padding:8px 12px;font-size:12px;color:#e8eaf0;text-decoration:none">💳 Stripe Dashboard</a>
            <a href="https://pineappletours.com.au" target="_blank" style="display:block;background:#12151f;border:1px solid #252840;border-radius:6px;padding:8px 12px;font-size:12px;color:#e8eaf0;text-decoration:none">🌐 Live Website</a>
            <a href="https://analytics.google.com" target="_blank" style="display:block;background:#12151f;border:1px solid #252840;border-radius:6px;padding:8px 12px;font-size:12px;color:#e8eaf0;text-decoration:none">📊 GA4 Analytics</a>
            <a href="https://search.google.com/search-console" target="_blank" style="display:block;background:#12151f;border:1px solid #252840;border-radius:6px;padding:8px 12px;font-size:12px;color:#e8eaf0;text-decoration:none">🔍 Search Console</a>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- BOOKINGS -->
  <div id="panel-bookings" class="panel">
    <div class="grid">
      <div class="grid grid-4">
        <div class="kpi-box">
          <div class="kpi-value" style="color:#27c27b">${rezdy.error ? '—' : rezdy.weekBookings}</div>
          <div class="kpi-label">Confirmed This Week</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#e05252">${rezdy.error ? '—' : rezdy.weekCancelled}</div>
          <div class="kpi-label">Cancelled This Week</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#f5a623">${rezdy.error ? '—' : '$'+Number(rezdy.weekRevenue).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
          <div class="kpi-label">Week Revenue</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#9b6dff">${rezdy.error ? '—' : '$'+Number(rezdy.mtdRevenue).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
          <div class="kpi-label">MTD Revenue</div>
        </div>
      </div>

      <div class="grid grid-2">
        <div class="card">
          <div class="section-title st-green">📅 Next Confirmed Bookings</div>
          ${rezdy.upcoming && rezdy.upcoming.length > 0
            ? rezdy.upcoming.map(b => `
              <div class="booking-row">
                <div>
                  <div class="booking-name">${b.name}</div>
                  <div class="booking-detail">${b.tour}</div>
                  <div class="booking-detail">Ref: ${b.ref}</div>
                </div>
                <div style="text-align:right">
                  <div class="booking-date">${b.date}</div>
                  <div class="booking-amount">$${Number(b.amount).toLocaleString()}</div>
                </div>
              </div>`).join('')
            : '<div class="empty-state">No upcoming bookings</div>'}
        </div>
        <div class="card">
          <div class="section-title">⚙️ Platform Status</div>
          <div class="row"><span class="row-label">Rezdy</span><span class="badge badge-green">✓ Connected</span></div>
          <div class="row"><span class="row-label">Stripe</span><span class="badge badge-orange">Connect secret key</span></div>
          <div class="row"><span class="row-label">Cart recovery</span><span class="badge badge-green">✓ 15m/24h/72h</span></div>
          <div class="row"><span class="row-label">Email (Resend)</span><span class="badge badge-green">✓ Live</span></div>
          <hr>
          <div class="section-title" style="margin-top:4px">🚨 Escalations</div>
          <div class="booking-row">
            <div><div class="booking-name">ATS Pacific / Frohwerk</div><div class="booking-detail">HOHO + Glow Worm · 15 Apr · TSTFRJ6485</div></div>
            <span class="badge badge-red">UNANSWERED</span>
          </div>
          <div class="booking-row">
            <div><div class="booking-name">Maddison Staader (ATIA)</div><div class="booking-detail">50-pax Canungra · 28 Aug · ~$8,250</div></div>
            <span class="badge badge-red">NEEDS TIMES</span>
          </div>
          <div class="booking-row">
            <div><div class="booking-name">Inside Australia Travel</div><div class="booking-detail">Bos party · 5 Apr · PTQVVF7Y</div></div>
            <span class="badge badge-orange">PREPAY DUE</span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- SEO & SPEED -->
  <div id="panel-seo" class="panel">
    <div class="grid">
      <div class="grid grid-4">
        <div class="kpi-box">
          <div class="kpi-value" style="color:${scoreColor(speed.performance)}">${speed.performance}</div>
          <div class="kpi-label">Performance (Mobile)</div>
          <div class="kpi-sub" style="color:#6b7280">PageSpeed Insights</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:${scoreColor(speed.seo)}">${speed.seo}</div>
          <div class="kpi-label">SEO Score</div>
          <div class="kpi-sub" style="color:#6b7280">PageSpeed Insights</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#6b7280">—</div>
          <div class="kpi-label">Avg Position</div>
          <div class="kpi-sub" style="color:#6b7280">Connect GSC</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#6b7280">—</div>
          <div class="kpi-label">Organic Clicks/wk</div>
          <div class="kpi-sub" style="color:#6b7280">Connect GSC</div>
        </div>
      </div>

      <div class="grid grid-2">
        <div class="card">
          <div class="section-title">⚡ Core Web Vitals</div>
          <div class="row"><span class="row-label">LCP (Largest Contentful Paint)</span><span class="row-value">${speed.lcp}</span></div>
          <div class="row"><span class="row-label">CLS (Layout Shift)</span><span class="row-value">${speed.cls}</span></div>
          <div class="row" style="margin-bottom:0"><span class="row-label">TBT (Total Blocking Time)</span><span class="row-value">${speed.fid}</span></div>
          <hr>
          <div class="section-title" style="margin-top:4px">🔧 Technical SEO</div>
          <div class="phase-item"><span style="color:#27c27b">✓</span>Sitemap at /sitemap_index.xml</div>
          <div class="phase-item"><span style="color:#27c27b">✓</span>robots.txt configured</div>
          <div class="phase-item"><span style="color:#27c27b">✓</span>HTTPS · Cloudflare CDN</div>
          <div class="phase-item"><span style="color:#e05252">○</span>Schema markup on tour pages</div>
          <div class="phase-item"><span style="color:#e05252">○</span>FAQ schema on money pages</div>
          <div class="phase-item"><span style="color:#e05252">○</span>Image optimisation</div>
          <div class="phase-item"><span style="color:#e05252">○</span>Book Now popup → trackable URLs</div>
        </div>
        <div class="card">
          <div class="section-title">🎯 Keyword Targets</div>
          <div class="row"><span class="row-label">tamborine mountain winery tour</span><span class="badge badge-orange">P1</span></div>
          <div class="progress-bar"><div class="progress-fill" style="width:80%;background:#f5a623"></div></div>
          <div class="row" style="margin-top:8px"><span class="row-label">gold coast wine tours</span><span class="badge badge-orange">P1</span></div>
          <div class="progress-bar"><div class="progress-fill" style="width:70%;background:#f5a623"></div></div>
          <div class="row" style="margin-top:8px"><span class="row-label">brisbane wine tours</span><span class="badge badge-blue">P2</span></div>
          <div class="progress-bar"><div class="progress-fill" style="width:55%;background:#4d9fff"></div></div>
          <div class="row" style="margin-top:8px"><span class="row-label">byron bay day tours</span><span class="badge badge-blue">P2</span></div>
          <div class="progress-bar"><div class="progress-fill" style="width:45%;background:#4d9fff"></div></div>
          <div class="row" style="margin-top:8px"><span class="row-label">hop on hop off wine tours</span><span class="badge badge-green">P3</span></div>
          <div class="progress-bar"><div class="progress-fill" style="width:35%;background:#27c27b"></div></div>
          <hr>
          <div class="section-title" style="margin-top:4px">📍 Local SEO Regions</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            <span class="badge badge-orange">Tamborine Mtn</span>
            <span class="badge badge-orange">Gold Coast</span>
            <span class="badge badge-orange">Brisbane</span>
            <span class="badge badge-blue">Byron Bay</span>
            <span class="badge badge-blue">Scenic Rim</span>
            <span class="badge badge-blue">Sunshine Coast</span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- MARKETING -->
  <div id="panel-marketing" class="panel">
    <div class="grid grid-2">
      <div class="card">
        <div class="section-title">📡 Tracking Events</div>
        <span class="tag">pt_view_tour</span><span class="tag">pt_start_checkout</span>
        <span class="tag">pt_payment_attempt</span><span class="tag">pt_payment_succeeded</span>
        <span class="tag">pt_payment_failed</span><span class="tag">pt_booking_confirmed</span>
        <span class="tag">pt_checkout_idle_15m</span><span class="tag">pt_checkout_abandoned_60m</span>
        <span class="tag">pt_phone_click</span><span class="tag">pt_whatsapp_click</span>
        <hr>
        <div class="section-title" style="margin-top:4px">🛒 Cart Recovery</div>
        <div class="row"><span class="row-label">15 min</span><span class="row-value" style="color:#4d9fff">Email/SMS #1</span></div>
        <div class="row"><span class="row-label">24 hr</span><span class="row-value" style="color:#4d9fff">Email #2 + support CTA</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">72 hr</span><span class="row-value" style="color:#9b6dff">Final + incentive option</span></div>
      </div>
      <div class="card">
        <div class="section-title">🎯 Channels</div>
        <div class="row"><span class="row-label">Google Ads</span><span class="badge badge-orange">Setup needed</span></div>
        <div class="row"><span class="row-label">Meta Ads</span><span class="badge badge-orange">Setup needed</span></div>
        <div class="row"><span class="row-label">Google Business Profile</span><span class="badge badge-orange">Optimise</span></div>
        <div class="row"><span class="row-label">Instagram</span><span class="badge badge-blue">Active</span></div>
        <div class="row"><span class="row-label">Facebook</span><span class="badge badge-blue">Active</span></div>
        <div class="row"><span class="row-label">Email (Resend)</span><span class="badge badge-green">Live</span></div>
        <hr>
        <div class="section-title" style="margin-top:4px">🗓️ Weekly Rhythm</div>
        <div class="row"><span class="row-label">Monday</span><span class="row-value">KPI + Incidents</span></div>
        <div class="row"><span class="row-label">Wednesday</span><span class="row-value">Experiments + Release</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Friday</span><span class="row-value">Security + Backlog</span></div>
      </div>
    </div>
  </div>

  <!-- TECH -->
  <div id="panel-tech" class="panel">
    <div class="grid grid-2">
      <div class="card">
        <div class="section-title st-red">🔐 Security Checklist</div>
        <div class="phase-item"><span style="color:#e05252">○</span>Rotate WP + Cloudflare + Google OAuth</div>
        <div class="phase-item"><span style="color:#e05252">○</span>Block REST user enumeration</div>
        <div class="phase-item"><span style="color:#e05252">○</span>Security headers (HSTS, XFO, XCTO)</div>
        <div class="phase-item"><span style="color:#e05252">○</span>Cloudflare WAF + rate limits</div>
        <div class="phase-item"><span style="color:#e05252">○</span>2FA all admin users</div>
        <div class="phase-item"><span style="color:#e05252">○</span>Daily encrypted backups</div>
        <div class="phase-item"><span style="color:#27c27b">✓</span>Cloudflare CDN + HTTPS</div>
        <div class="phase-item"><span style="color:#27c27b">✓</span>Dashboard CF Access protected</div>
        <div class="phase-item"><span style="color:#27c27b">✓</span>sshguard running on Mac mini</div>
        <div class="phase-item"><span style="color:#27c27b">✓</span>macOS firewall enabled</div>
      </div>
      <div class="card">
        <div class="section-title st-blue">🛠️ Stack</div>
        <div class="row"><span class="row-label">Site</span><span class="row-value">WordPress · pineappletours.com.au</span></div>
        <div class="row"><span class="row-label">CDN</span><span class="row-value">Cloudflare</span></div>
        <div class="row"><span class="row-label">Payments</span><span class="row-value">Stripe (live)</span></div>
        <div class="row"><span class="row-label">Bookings</span><span class="row-value" style="color:#27c27b">Rezdy ✓ Connected</span></div>
        <div class="row"><span class="row-label">Analytics</span><span class="row-value">GA4 + GTM</span></div>
        <div class="row"><span class="row-label">Email</span><span class="row-value">Resend</span></div>
        <div class="row"><span class="row-label">Dashboard</span><span class="row-value">CF Workers · Edge</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Agent</span><span class="row-value">OpenClaw · POS 🍍</span></div>
        <hr>
        <div class="section-title" style="margin-top:4px">⚡ Alert Thresholds</div>
        <div class="row"><span class="row-label">Payment failures</span><span class="row-value" style="color:#e05252">&gt;8% / 15 min</span></div>
        <div class="row"><span class="row-label">Checkout drop</span><span class="row-value" style="color:#e05252">&gt;30% day-on-day</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Hourly revenue</span><span class="row-value" style="color:#f5a623">&lt;60% 4-week median</span></div>
      </div>
    </div>
  </div>

  <div class="footer">Pineapple Tours · dashboard.pineappletours.com.au · CF Access · 🍍 POS · <a href="https://dash.p2a.au" style="color:#9b6dff;text-decoration:none">→ P2A Command</a></div>
</div>
<script>
function showTab(name,el){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  el.classList.add('active');
}
</script>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const jwtValid = await validateCFAccessJWT(request);
    const cookies = request.headers.get("Cookie") || "";
    const cookieValid = cookies.includes(`${COOKIE_NAME}=${COOKIE_VALUE}`);

    if (request.method === "POST") {
      const body = await request.text();
      const params = new URLSearchParams(body);
      if (params.get("password") === PASSWORD) {
        const expiry = new Date(Date.now() + 1000*60*60*24*30).toUTCString();
        return new Response("", { status:302, headers:{"Location":"/","Set-Cookie":`${COOKIE_NAME}=${COOKIE_VALUE};expires=${expiry};path=/;HttpOnly;Secure;SameSite=Strict`}});
      }
      return new Response(LOGIN_PAGE("Incorrect password."), {status:401, headers:{"Content-Type":"text/html"}});
    }

    if (!jwtValid && !cookieValid) {
      return new Response(LOGIN_PAGE(""), {headers:{"Content-Type":"text/html"}});
    }

    // Fetch live data in parallel
    const [rezdy, speed] = await Promise.all([
      getRezdyData(env.REZDY_API_KEY),
      getPageSpeed()
    ]);

    return new Response(renderDashboard(rezdy, speed), {
      headers:{
        "Content-Type":"text/html",
        "X-Frame-Options":"DENY",
        "X-Content-Type-Options":"nosniff",
        "Referrer-Policy":"no-referrer",
        "Cache-Control":"no-store"
      }
    });
  }
};

function LOGIN_PAGE(error) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pineapple Tours · Login</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0f1117;color:#e8eaf0;font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#1a1d2e;border:1px solid #252840;border-radius:16px;padding:40px;width:100%;max-width:380px;text-align:center}
.logo{font-size:40px;margin-bottom:16px}h1{font-size:22px;font-weight:700;margin-bottom:4px}.sub{font-size:13px;color:#6b7280;margin-bottom:28px}
input{width:100%;background:#12151f;border:1px solid #252840;border-radius:8px;padding:12px 14px;color:#e8eaf0;font-size:14px;outline:none;margin-bottom:12px}
input:focus{border-color:#f5a623}button{width:100%;background:#f5a623;color:#000;border:none;border-radius:8px;padding:12px;font-size:14px;font-weight:700;cursor:pointer}
.error{color:#e05252;font-size:12px;margin-top:8px;min-height:16px}</style></head>
<body><div class="box"><div class="logo">🍍</div><h1>Pineapple Tours</h1><div class="sub">Operations Dashboard</div>
<form method="POST"><input type="password" name="password" placeholder="Enter password" autofocus><button type="submit">Access Dashboard</button></form>
<div class="error">${error}</div></div></body></html>`;
}
