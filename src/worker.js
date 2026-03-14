// Pineapple Tours Live Dashboard — Cloudflare Worker v2
// dashboard.pineappletours.com.au
// Features: Date range selector, Dark/Light mode, Combined Rezdy+Stripe view

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

// Fetch live Stripe data for a given day range
async function getStripeData(apiKey, days) {
  try {
    const now = Math.floor(Date.now()/1000);
    const rangeStart = now - days*24*60*60;
    const headers = { 'Authorization': 'Basic ' + btoa(apiKey + ':') };

    const [rangeRes, balanceRes] = await Promise.all([
      fetch(`https://api.stripe.com/v1/charges?created[gte]=${rangeStart}&limit=100`, {headers}),
      fetch('https://api.stripe.com/v1/balance', {headers})
    ]);

    const [rangeData, balData] = await Promise.all([rangeRes.json(), balanceRes.json()]);

    const charges = (rangeData.data||[]).filter(c => c.paid && !c.refunded);
    const revenue = charges.reduce((s,c) => s + c.amount, 0) / 100;

    const available = (balData.available||[]).find(b => b.currency==='aud')?.amount/100 || 0;
    const pending = (balData.pending||[]).find(b => b.currency==='aud')?.amount/100 || 0;

    return {
      revenue: revenue.toFixed(2),
      count: charges.length,
      available: available.toFixed(2),
      pending: pending.toFixed(2)
    };
  } catch(e) { return { error: e.message }; }
}

// Fetch live Rezdy data for a given day range
async function getRezdyData(apiKey, days) {
  try {
    const now = new Date();
    const rangeStart = new Date(now - days*24*60*60*1000);
    const fmt = d => d.toISOString().slice(0,10);

    const [rangeRes, upcomingRes] = await Promise.all([
      fetch(`https://api.rezdy.com/v1/bookings?apiKey=${apiKey}&limitNum=100&createdAfterDate=${fmt(rangeStart)}`),
      fetch(`https://api.rezdy.com/v1/bookings?apiKey=${apiKey}&limitNum=10&afterDateTime=${fmt(now)}T00:00:00&status=CONFIRMED`)
    ]);

    const [rangeData, upcomingData] = await Promise.all([rangeRes.json(), upcomingRes.json()]);

    const bookings = rangeData.bookings || [];
    const upcoming = upcomingData.bookings || [];

    const confirmed = bookings.filter(b => b.status === 'CONFIRMED');
    const cancelled = bookings.filter(b => b.status === 'CANCELLED').length;
    const revenue = confirmed.reduce((s,b) => s + parseFloat(b.totalAmount||0), 0);

    return {
      bookings: confirmed.length,
      revenue: revenue.toFixed(2),
      cancelled,
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

function scoreColor(n, dark=true) {
  if (n === '—') return dark ? '#6b7280' : '#9ca3af';
  if (n >= 90) return '#27c27b';
  if (n >= 50) return '#f5a623';
  return '#e05252';
}

function rangeName(days) {
  if (days === 1) return 'Today';
  if (days === 7) return '7 Days';
  if (days === 30) return '30 Days';
  if (days === 90) return '90 Days';
  return `${days} Days`;
}

function renderDashboard(rezdy, stripe, speed, days) {
  const now = new Date().toLocaleString('en-AU', {timeZone:'Australia/Brisbane',dateStyle:'medium',timeStyle:'short'});
  const rng = rangeName(days);

  // Sales breakdown calculation
  const rezdyRev = parseFloat(rezdy.revenue || 0);
  const stripeRev = parseFloat(stripe.revenue || 0);
  const directPct = rezdyRev > 0 ? Math.round((stripeRev / rezdyRev) * 100) : 0;
  const agentPct = 100 - directPct;

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="300">
<title>Pineapple Tours Dashboard</title>
<style>
  :root {
    --bg: #0f1117;
    --card: #1a1d2e;
    --card-border: #252840;
    --text: #e8eaf0;
    --text-muted: #6b7280;
    --text-sub: #9ca3af;
    --kpi-bg: #12151f;
    --input-bg: #12151f;
    --link-bg: #12151f;
    --tab-border: #252840;
    --hr: #252840;
    --booking-border: #252840;
    --card-urgent-bg: #1e0d0d;
    --card-urgent-border: #5a2020;
    --card-good-bg: #0d1a10;
    --card-good-border: #1a4a25;
    --hl-green-bg: #101a10;
    --hl-green-border: #27c27b44;
    --hl-orange-bg: #1a1200;
    --hl-orange-border: #f5a62344;
    --hl-red-bg: #1e0d0d;
    --hl-red-border: #e0525244;
    --live-bg: #101a10;
    --sec-bg: #101a10;
    --tag-bg: #0d1520;
  }
  [data-theme="light"] {
    --bg: #f8f9fa;
    --card: #ffffff;
    --card-border: #e5e7eb;
    --text: #111827;
    --text-muted: #6b7280;
    --text-sub: #4b5563;
    --kpi-bg: #f3f4f6;
    --input-bg: #f3f4f6;
    --link-bg: #f3f4f6;
    --tab-border: #e5e7eb;
    --hr: #e5e7eb;
    --booking-border: #e5e7eb;
    --card-urgent-bg: #fff5f5;
    --card-urgent-border: #fca5a5;
    --card-good-bg: #f0fdf4;
    --card-good-border: #86efac;
    --hl-green-bg: #f0fdf4;
    --hl-green-border: #86efac;
    --hl-orange-bg: #fffbeb;
    --hl-orange-border: #fcd34d;
    --hl-red-bg: #fff5f5;
    --hl-red-border: #fca5a5;
    --live-bg: #f0fdf4;
    --sec-bg: #f0fdf4;
    --tag-bg: #e0e7ff;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;min-height:100vh;padding:20px;transition:background .2s,color .2s}
  .wrap{max-width:1200px;margin:0 auto}
  .header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;flex-wrap:wrap;gap:10px}
  .header-left{display:flex;align-items:center;gap:10px}
  .logo{width:36px;height:36px;border-radius:8px;background:#f5a623;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
  .title{font-size:20px;font-weight:700}
  .subtitle{font-size:12px;color:var(--text-muted);margin-top:2px}
  .header-right{display:flex;flex-direction:column;align-items:flex-end;gap:8px}
  .header-controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
  .live-badge{display:inline-flex;align-items:center;gap:5px;background:var(--live-bg);border:1px solid #27c27b44;border-radius:6px;padding:3px 9px;font-size:11px;color:#27c27b}
  .live-dot{width:6px;height:6px;border-radius:50%;background:#27c27b;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
  .badges{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  .badge{border-radius:6px;padding:3px 9px;font-size:11px;font-weight:600}
  .badge-red{background:#e0525222;color:#e05252;border:1px solid #e0525244}
  .badge-orange{background:#f5a62322;color:#f5a623;border:1px solid #f5a62344}
  .badge-green{background:#27c27b22;color:#27c27b;border:1px solid #27c27b44}
  .badge-blue{background:#4d9fff22;color:#4d9fff;border:1px solid #4d9fff44}
  /* Date range buttons */
  .range-btns{display:flex;gap:4px;background:var(--kpi-bg);border:1px solid var(--card-border);border-radius:8px;padding:3px}
  .range-btn{background:transparent;border:none;border-radius:6px;padding:4px 12px;font-size:11px;font-weight:600;cursor:pointer;color:var(--text-sub);transition:all .15s}
  .range-btn.active{background:#f5a623;color:#000}
  .range-btn:hover:not(.active){background:var(--card);color:var(--text)}
  /* Theme toggle */
  .theme-btn{background:var(--kpi-bg);border:1px solid var(--card-border);border-radius:8px;padding:5px 10px;font-size:14px;cursor:pointer;color:var(--text);transition:all .15s;line-height:1}
  .theme-btn:hover{border-color:#f5a623}
  .tabs{display:flex;gap:4px;border-bottom:1px solid var(--tab-border);margin-bottom:18px;overflow-x:auto}
  .tab{background:transparent;color:var(--text-sub);border:none;border-radius:8px 8px 0 0;padding:8px 18px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .15s}
  .tab.active{background:#f5a623;color:#000}
  .tab:hover:not(.active){color:var(--text)}
  .grid{display:grid;gap:14px}
  .grid-2{grid-template-columns:1fr 1fr}
  .grid-3{grid-template-columns:1fr 1fr 1fr}
  .grid-4{grid-template-columns:1fr 1fr 1fr 1fr}
  .span2{grid-column:span 2}
  .span3{grid-column:span 3}
  .span4{grid-column:span 4}
  @media(max-width:700px){.grid-2,.grid-3,.grid-4{grid-template-columns:1fr}.span2,.span3,.span4{grid-column:span 1}}
  .card{background:var(--card);border:1px solid var(--card-border);border-radius:12px;padding:16px}
  .card-urgent{background:var(--card-urgent-bg);border-color:var(--card-urgent-border)}
  .card-good{background:var(--card-good-bg);border-color:var(--card-good-border)}
  .section-title{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;color:#f5a623}
  .st-red{color:#e05252}.st-blue{color:#4d9fff}.st-green{color:#27c27b}.st-purple{color:#9b6dff}
  .kpi-box{background:var(--kpi-bg);border-radius:10px;padding:14px;text-align:center;border:1px solid var(--card-border)}
  .kpi-value{font-size:26px;font-weight:800;line-height:1}
  .kpi-label{font-size:10px;color:var(--text-muted);margin-top:5px;text-transform:uppercase;letter-spacing:.5px}
  .kpi-sub{font-size:11px;margin-top:3px}
  .row{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:7px;gap:8px}
  .row-label{font-size:12px;color:var(--text-sub);flex-shrink:0}
  .row-value{font-size:12px;font-weight:600;text-align:right}
  .booking-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--booking-border);gap:8px}
  .booking-row:last-child{border-bottom:none}
  .booking-name{font-size:12px;font-weight:600}
  .booking-detail{font-size:10px;color:var(--text-muted);margin-top:1px}
  .booking-amount{font-size:12px;font-weight:700;color:#27c27b;white-space:nowrap}
  .booking-date{font-size:10px;color:#4d9fff;white-space:nowrap}
  .progress-bar{height:6px;border-radius:3px;background:var(--card-border);margin-top:5px;overflow:hidden}
  .progress-fill{height:100%;border-radius:3px;transition:width .5s}
  .split-bar{height:12px;border-radius:6px;background:var(--card-border);overflow:hidden;display:flex}
  .split-direct{background:#27c27b;border-radius:6px 0 0 6px;transition:width .5s}
  .split-agent{background:#f5a623;border-radius:0 6px 6px 0;flex:1}
  .highlight{border-radius:8px;padding:10px;margin-top:8px}
  .hl-green{background:var(--hl-green-bg);border:1px solid var(--hl-green-border)}
  .hl-orange{background:var(--hl-orange-bg);border:1px solid var(--hl-orange-border)}
  .hl-red{background:var(--hl-red-bg);border:1px solid var(--hl-red-border)}
  .hl-title{font-size:11px;font-weight:700;margin-bottom:3px}
  .hl-text{font-size:11px;color:var(--text);line-height:1.5}
  .speed-ring{display:inline-flex;align-items:center;justify-content:center;width:60px;height:60px;border-radius:50%;border:3px solid;font-size:18px;font-weight:800}
  .tag{display:inline-block;background:var(--tag-bg);color:#4d9fff;font-family:monospace;font-size:10px;padding:2px 6px;border-radius:4px;margin:2px}
  .phase-item{font-size:11px;color:var(--text-sub);display:flex;gap:6px;margin-bottom:4px}
  .refresh-note{font-size:10px;color:var(--text-muted);text-align:right;margin-bottom:8px}
  hr{border:none;border-top:1px solid var(--hr);margin:10px 0}
  .panel{display:none}
  .panel.active{display:block}
  .footer{margin-top:24px;text-align:center;font-size:10px;color:var(--text-muted)}
  .security-badge{display:inline-flex;align-items:center;gap:4px;background:var(--sec-bg);border:1px solid #27c27b44;border-radius:6px;padding:3px 8px;font-size:10px;color:#27c27b}
  .empty-state{text-align:center;color:var(--text-muted);font-size:12px;padding:20px}
  a{color:inherit}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="header-left">
      <div class="logo">🍍</div>
      <div>
        <div class="title">Pineapple Tours</div>
        <div class="subtitle">Operations Dashboard · Updated ${now}</div>
      </div>
    </div>
    <div class="header-right">
      <div class="header-controls">
        <div class="badges">
          <span class="live-badge"><span class="live-dot"></span>LIVE</span>
          <span class="badge badge-green">Rezdy ✓</span>
          <span class="badge badge-blue">Stripe ✓</span>
          <span class="security-badge">🔒 CF Access</span>
        </div>
        <button class="theme-btn" id="themeBtn" onclick="toggleTheme()" title="Toggle dark/light mode">🌙</button>
      </div>
      <div class="range-btns">
        <button class="range-btn${days===1?' active':''}" onclick="setRange(1)">Today</button>
        <button class="range-btn${days===7?' active':''}" onclick="setRange(7)">7 Days</button>
        <button class="range-btn${days===30?' active':''}" onclick="setRange(30)">30 Days</button>
        <button class="range-btn${days===90?' active':''}" onclick="setRange(90)">90 Days</button>
      </div>
    </div>
  </div>

  <div class="refresh-note">⟳ Auto-refreshes every 5 minutes · Showing: <strong>${rng}</strong></div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('overview',this)">Overview</button>
    <button class="tab" onclick="showTab('bookings',this)">Bookings</button>
    <button class="tab" onclick="showTab('seo',this)">SEO &amp; Speed</button>
    <button class="tab" onclick="showTab('marketing',this)">Marketing</button>
    <button class="tab" onclick="showTab('tech',this)">Tech</button>
  </div>

  <!-- OVERVIEW -->
  <div id="panel-overview" class="panel active">
    <div class="grid">
      <!-- Live KPIs row -->
      <div class="grid grid-4">
        <div class="kpi-box">
          <div class="kpi-value" style="color:#27c27b">${rezdy.error ? '—' : rezdy.bookings}</div>
          <div class="kpi-label">Rezdy Bookings</div>
          <div class="kpi-sub" style="color:${(rezdy.cancelled||0) > 5 ? '#e05252' : 'var(--text-muted)'}">${rezdy.error ? 'Rezdy error' : (rezdy.cancelled||0) + ' cancelled'}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#f5a623">${rezdy.error ? '—' : '$' + Number(rezdy.revenue).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
          <div class="kpi-label">Rezdy Revenue</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${rezdy.error ? 'Error' : 'All channels · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#9b6dff">${stripe.error ? '—' : '$' + Number(stripe.revenue).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
          <div class="kpi-label">Stripe Revenue</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${stripe.error ? 'Stripe error' : (stripe.count||0) + ' direct payments'}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:${Number(stripe.available) < 0 ? '#e05252' : '#4d9fff'}">${stripe.error ? '—' : '$' + Number(stripe.available).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
          <div class="kpi-label">Stripe Balance</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${stripe.error ? '' : '$' + Number(stripe.pending).toLocaleString('en-AU',{maximumFractionDigits:0}) + ' pending'}</div>
        </div>
      </div>

      <!-- Sales Breakdown -->
      <div class="card">
        <div class="section-title">📊 Sales Breakdown · ${rng}</div>
        <div class="grid grid-2">
          <div>
            <div class="row">
              <span class="row-label">Direct (Stripe / Online)</span>
              <span class="row-value" style="color:#27c27b">${stripe.error ? '—' : '$' + Number(stripe.revenue).toLocaleString('en-AU',{maximumFractionDigits:0})} <span style="color:var(--text-muted);font-weight:400">(${directPct}%)</span></span>
            </div>
            <div class="row">
              <span class="row-label">Agent / Other (Rezdy total)</span>
              <span class="row-value" style="color:#f5a623">${rezdy.error ? '—' : '$' + Number(rezdy.revenue).toLocaleString('en-AU',{maximumFractionDigits:0})}</span>
            </div>
            <div style="margin-top:8px;margin-bottom:4px;font-size:10px;color:var(--text-muted)">Direct vs Agent</div>
            <div class="split-bar">
              <div class="split-direct" style="width:${directPct}%"></div>
              <div class="split-agent"></div>
            </div>
            <div style="display:flex;gap:16px;margin-top:6px">
              <span style="font-size:10px;color:#27c27b">● Direct ${directPct}%</span>
              <span style="font-size:10px;color:#f5a623">● Agent/Other ${agentPct}%</span>
            </div>
          </div>
          <div style="display:flex;flex-direction:column;justify-content:center">
            <div class="highlight hl-orange">
              <div class="hl-title" style="color:#f5a623">🏦 Banking reconciliation</div>
              <div class="hl-text">Stripe charges (direct) vs Rezdy total (all channels incl. agents). Full reconciliation coming soon.</div>
            </div>
          </div>
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
              <div style="font-size:10px;color:var(--text-muted);margin-top:4px">Performance</div>
            </div>
            <div style="text-align:center">
              <div class="speed-ring" style="border-color:${scoreColor(speed.seo)};color:${scoreColor(speed.seo)}">${speed.seo}</div>
              <div style="font-size:10px;color:var(--text-muted);margin-top:4px">SEO Score</div>
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
          <div class="row" style="margin-bottom:0"><span class="row-label">Role</span><span class="row-value">Tour Guide &amp; Driver</span></div>
          <div class="highlight hl-green" style="margin-top:8px">
            <div class="hl-title" style="color:#27c27b">Disaster Assistance Grant</div>
            <div class="hl-text">Ready to sign — Emma Bloem · SBFCS</div>
          </div>
        </div>
        <div class="card">
          <div class="section-title">🔗 Quick Links</div>
          <div style="display:grid;gap:6px">
            <a href="https://beta.rezdy.com" target="_blank" style="display:block;background:var(--link-bg);border:1px solid var(--card-border);border-radius:6px;padding:8px 12px;font-size:12px;color:var(--text);text-decoration:none">📋 Rezdy Dashboard</a>
            <a href="https://dashboard.stripe.com" target="_blank" style="display:block;background:var(--link-bg);border:1px solid var(--card-border);border-radius:6px;padding:8px 12px;font-size:12px;color:var(--text);text-decoration:none">💳 Stripe Dashboard</a>
            <a href="https://pineappletours.com.au" target="_blank" style="display:block;background:var(--link-bg);border:1px solid var(--card-border);border-radius:6px;padding:8px 12px;font-size:12px;color:var(--text);text-decoration:none">🌐 Live Website</a>
            <a href="https://analytics.google.com" target="_blank" style="display:block;background:var(--link-bg);border:1px solid var(--card-border);border-radius:6px;padding:8px 12px;font-size:12px;color:var(--text);text-decoration:none">📊 GA4 Analytics</a>
            <a href="https://search.google.com/search-console" target="_blank" style="display:block;background:var(--link-bg);border:1px solid var(--card-border);border-radius:6px;padding:8px 12px;font-size:12px;color:var(--text);text-decoration:none">🔍 Search Console</a>
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
          <div class="kpi-value" style="color:#27c27b">${rezdy.error ? '—' : rezdy.bookings}</div>
          <div class="kpi-label">Rezdy Confirmed</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${rezdy.error ? '' : (rezdy.cancelled||0) + ' cancelled · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#f5a623">${rezdy.error ? '—' : '$'+Number(rezdy.revenue).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
          <div class="kpi-label">Rezdy Revenue</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${rezdy.error ? '' : 'All channels · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#9b6dff">${stripe.error ? '—' : '$'+Number(stripe.revenue).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
          <div class="kpi-label">Stripe Direct</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${stripe.error ? '' : (stripe.count||0) + ' payments · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:${Number(stripe.available) < 0 ? '#e05252' : '#4d9fff'}">${stripe.error ? '—' : '$'+Number(stripe.available).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
          <div class="kpi-label">Stripe Available</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${stripe.error ? '' : '$'+Number(stripe.pending).toLocaleString('en-AU',{maximumFractionDigits:0}) + ' pending'}</div>
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
          <div class="row"><span class="row-label">Rezdy</span><span class="badge badge-green">✓ Live</span></div>
          <div class="row"><span class="row-label">Stripe</span><span class="badge badge-green">✓ Live</span></div>
          <div class="row"><span class="row-label">GA4</span><span class="badge badge-orange">Connect GA4</span></div>
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
          <div class="kpi-sub" style="color:var(--text-muted)">PageSpeed Insights</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:${scoreColor(speed.seo)}">${speed.seo}</div>
          <div class="kpi-label">SEO Score</div>
          <div class="kpi-sub" style="color:var(--text-muted)">PageSpeed Insights</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:var(--text-muted)">—</div>
          <div class="kpi-label">Avg Position</div>
          <div class="kpi-sub" style="color:var(--text-muted)">Connect GSC</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:var(--text-muted)">—</div>
          <div class="kpi-label">Organic Clicks/wk</div>
          <div class="kpi-sub" style="color:var(--text-muted)">Connect GSC</div>
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
        <div class="row"><span class="row-label">Analytics</span><span class="row-value">GA4 · Connect GA4</span></div>
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
// Tab switching
function showTab(name,el){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  el.classList.add('active');
}

// Date range
function setRange(days){
  const u = new URL(location.href);
  u.searchParams.set('range', days);
  location.href = u.toString();
}

// Theme toggle
function toggleTheme(){
  const html = document.documentElement;
  const isDark = html.getAttribute('data-theme') === 'dark';
  const newTheme = isDark ? 'light' : 'dark';
  html.setAttribute('data-theme', newTheme);
  localStorage.setItem('pt_theme', newTheme);
  document.getElementById('themeBtn').textContent = newTheme === 'dark' ? '🌙' : '☀️';
}

// Apply saved theme on load
(function(){
  const saved = localStorage.getItem('pt_theme');
  if (saved && saved !== document.documentElement.getAttribute('data-theme')) {
    document.documentElement.setAttribute('data-theme', saved);
    const btn = document.getElementById('themeBtn');
    if (btn) btn.textContent = saved === 'dark' ? '🌙' : '☀️';
  }
})();
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

    // Parse date range from query param (default 7 days)
    const url = new URL(request.url);
    const rangeParam = url.searchParams.get('range');
    const days = [1, 7, 30, 90].includes(parseInt(rangeParam)) ? parseInt(rangeParam) : 7;

    // Fetch live data in parallel
    const [rezdy, stripe, speed] = await Promise.all([
      getRezdyData(env.REZDY_API_KEY, days),
      getStripeData(env.STRIPE_SECRET_KEY, days),
      getPageSpeed()
    ]);

    return new Response(renderDashboard(rezdy, stripe, speed, days), {
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
