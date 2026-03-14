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

// Fetch abandoned cart data from KV
async function getCartData(kv) {
  try {
    const raw = await kv.get('abandoned_carts');
    if (!raw) return { error: 'No data yet' };
    return JSON.parse(raw);
  } catch(e) { return { error: e.message }; }
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

// Fetch live GA4 data using Web Crypto JWT signing
async function getGA4Data(serviceAccountJson, days) {
  try {
    // Parse service account JSON — handle escaped newlines from CF Worker secrets
    const sa = JSON.parse(serviceAccountJson.replace(/\\\\n/g, '\\n'));
    const now = Math.floor(Date.now() / 1000);

    // Build JWT header + payload (URL-safe base64, no padding)
    const b64u = s => btoa(s).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    const header = b64u(JSON.stringify({alg:"RS256",typ:"JWT"}));
    const payload = b64u(JSON.stringify({
      iss: sa.client_email,
      scope: "https://www.googleapis.com/auth/analytics.readonly",
      aud: "https://oauth2.googleapis.com/token",
      exp: now + 3600,
      iat: now
    }));

    // Import private key using Web Crypto API (available in CF Workers)
    // Handle both literal newlines and escaped \\n from Worker secrets
    const privateKey = sa.private_key.replace(/\\n/g, '\n');
    const pemBody = privateKey
      .replace(/-----BEGIN PRIVATE KEY-----/,'')
      .replace(/-----END PRIVATE KEY-----/,'')
      .replace(/\s/g,'');
    const keyData = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8', keyData.buffer,
      {name:'RSASSA-PKCS1-v1_5', hash:'SHA-256'},
      false, ['sign']
    );

    const signingInput = new TextEncoder().encode(`${header}.${payload}`);
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, signingInput);
    const sig = b64u(String.fromCharCode(...new Uint8Array(signature)));
    const jwt = `${header}.${payload}.${sig}`;

    // Exchange JWT for access token
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
    });
    const { access_token } = await tokenRes.json();

    const startDate = days === 1 ? 'today' : `${days}daysAgo`;

    // Run all GA4 queries in parallel
    const query = (body) => fetch(
      'https://analyticsdata.googleapis.com/v1beta/properties/499317801:runReport',
      {
        method: 'POST',
        headers: {'Authorization': `Bearer ${access_token}`, 'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      }
    ).then(r => r.json());

    const [channelData, totalsData, pagesData, deviceData] = await Promise.all([
      query({
        dateRanges: [{startDate, endDate:'today'}],
        metrics: [{name:'sessions'},{name:'activeUsers'},{name:'newUsers'},{name:'bounceRate'}],
        dimensions: [{name:'sessionDefaultChannelGroup'}]
      }),
      query({
        dateRanges: [{startDate, endDate:'today'}],
        metrics: [{name:'sessions'},{name:'activeUsers'},{name:'newUsers'},{name:'averageSessionDuration'},{name:'screenPageViews'}]
      }),
      query({
        dateRanges: [{startDate, endDate:'today'}],
        metrics: [{name:'sessions'},{name:'screenPageViews'}],
        dimensions: [{name:'pagePath'}],
        orderBys: [{metric:{metricName:'sessions'},desc:true}],
        limit: 8
      }),
      query({
        dateRanges: [{startDate, endDate:'today'}],
        metrics: [{name:'sessions'}],
        dimensions: [{name:'deviceCategory'}]
      })
    ]);

    const channels = (channelData.rows || []).map(r => ({
      channel: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value),
      users: parseInt(r.metricValues[1].value),
      newUsers: parseInt(r.metricValues[2].value),
      bounceRate: parseFloat(r.metricValues[3].value)
    }));

    const totRow = totalsData.rows?.[0];
    const totals = totRow ? {
      sessions: parseInt(totRow.metricValues[0].value),
      users: parseInt(totRow.metricValues[1].value),
      newUsers: parseInt(totRow.metricValues[2].value),
      avgDuration: parseFloat(totRow.metricValues[3].value),
      pageviews: parseInt(totRow.metricValues[4].value)
    } : {};

    const pages = (pagesData.rows || []).map(r => ({
      path: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value),
      views: parseInt(r.metricValues[1].value)
    }));

    const devices = (deviceData.rows || []).map(r => ({
      device: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value)
    }));

    const organicSearch = channels.find(c => c.channel === 'Organic Search') || {sessions:0};
    const paidSearch    = channels.find(c => c.channel === 'Paid Search')    || {sessions:0};
    const paidSocial    = channels.find(c => c.channel === 'Paid Social')    || {sessions:0};
    const direct        = channels.find(c => c.channel === 'Direct')         || {sessions:0};
    const mobile        = devices.find(d => d.device === 'mobile')           || {sessions:0};
    const totalDevSessions = devices.reduce((s,d) => s+d.sessions, 0);

    return { channels, totals, pages, devices, organicSearch, paidSearch, paidSocial, direct, mobile, totalDevSessions };
  } catch(e) {
    return { error: e.message, totals:{}, channels:[], pages:[], devices:[], organicSearch:{sessions:0}, paidSearch:{sessions:0}, paidSocial:{sessions:0}, direct:{sessions:0}, mobile:{sessions:0}, totalDevSessions:0 };
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

function renderDashboard(rezdy, stripe, ga4, speed, carts, days) {
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
  /* Status system */
  .status-counter{font-size:11px;color:var(--text-muted);margin-top:4px}
  .status-counter .s-urgent{color:#e05252;font-weight:700}
  .status-counter .s-done{color:#27c27b;font-weight:700}
  .status-counter .s-ignored{color:var(--text-muted);font-weight:700}
  .si{cursor:pointer;user-select:none;transition:all .15s;border-radius:8px;padding:3px 6px 3px 3px;display:flex;align-items:center;gap:6px}
  .si:hover{background:var(--kpi-bg)}
  .si[data-status="urgent"]{border:1px solid #e05252;background:var(--hl-red-bg);font-weight:700}
  .si[data-status="done"]{opacity:.5;text-decoration:line-through}
  .si[data-status="ignored"]{opacity:.3}
  .si-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;display:inline-block}
  .si[data-status="pending"] .si-dot{background:#6b7280}
  .si[data-status="urgent"] .si-dot{background:#e05252;animation:pulse 1s infinite}
  .si[data-status="done"] .si-dot{background:transparent;width:auto;height:auto}
  .si[data-status="done"] .si-dot::before{content:"✅";font-size:10px}
  .si[data-status="ignored"] .si-dot{background:#6b7280}
  .si-done-dot::before{content:"✅";font-size:10px}
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
        <div class="status-counter" id="statusCounter">Loading…</div>
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

      <!-- GA4 Web Traffic KPIs row -->
      <div class="grid grid-4">
        <div class="kpi-box">
          <div class="kpi-value" style="color:#4d9fff">${ga4.error ? '—' : (ga4.totals.sessions ?? '—').toLocaleString?.() ?? (ga4.totals.sessions ?? '—')}</div>
          <div class="kpi-label">Total Sessions</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${ga4.error ? 'GA4 error' : (ga4.totals.users ?? 0).toLocaleString() + ' users · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#27c27b">${ga4.error ? '—' : (ga4.organicSearch.sessions ?? 0).toLocaleString()}</div>
          <div class="kpi-label">Organic Sessions</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${ga4.error ? '' : 'Google organic · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#9b6dff">${ga4.error ? '—' : (ga4.paidSocial.sessions ?? 0).toLocaleString()}</div>
          <div class="kpi-label">Paid Social</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${ga4.error ? '' : 'Meta / social ads · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#f5a623">${ga4.error || !ga4.totalDevSessions ? '—' : Math.round((ga4.mobile.sessions / ga4.totalDevSessions) * 100) + '%'}</div>
          <div class="kpi-label">Mobile %</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${ga4.error ? '' : (ga4.mobile.sessions ?? 0).toLocaleString() + ' mobile sessions'}</div>
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
          <div class="section-title st-red">🔴 Escalations <span style="font-weight:400;font-size:9px;letter-spacing:0;text-transform:none;color:var(--text-muted)">(click to update status)</span></div>
          <div class="si booking-row" data-id="esc-ats-pacific" data-status="pending" onclick="cycleStatus(this)">
            <span class="si-dot"></span>
            <div><div class="booking-name">ATS Pacific / Frohwerk</div><div class="booking-detail">HOHO + Glow Worm · 15 Apr · TSTFRJ6485</div></div>
            <span class="badge badge-red">UNANSWERED</span>
          </div>
          <div class="si booking-row" data-id="esc-maddison-atia" data-status="pending" onclick="cycleStatus(this)">
            <span class="si-dot"></span>
            <div><div class="booking-name">Maddison Staader (ATIA)</div><div class="booking-detail">50-pax Canungra · 28 Aug · ~$8,250</div></div>
            <span class="badge badge-red">NEEDS TIMES</span>
          </div>
          <div class="si booking-row" data-id="esc-inside-australia" data-status="pending" onclick="cycleStatus(this)">
            <span class="si-dot"></span>
            <div><div class="booking-name">Inside Australia Travel</div><div class="booking-detail">Bos party · 5 Apr · PTQVVF7Y</div></div>
            <span class="badge badge-orange">PREPAY DUE</span>
          </div>
        </div>

        <!-- Abandoned carts -->
        <div class="card">
          <div class="section-title">🛒 Abandoned Carts</div>
          ${carts.error ? `<div class="empty-state">${carts.error}</div>` : `
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
            <div class="kpi-box" style="padding:10px">
              <div class="kpi-value" style="font-size:20px;color:#e05252">${carts.totalAbandoned || 0}</div>
              <div class="kpi-label">Total Abandoned</div>
            </div>
            <div class="kpi-box" style="padding:10px">
              <div class="kpi-value" style="font-size:20px;color:#f5a623">$${Number(carts.totalValue||0).toLocaleString('en-AU',{maximumFractionDigits:0})}</div>
              <div class="kpi-label">Lost Value</div>
            </div>
          </div>
          <div style="margin-bottom:8px">
            <div class="row"><span class="row-label">Pending action</span><span class="row-value" style="color:${carts.pendingAction>0?'#f5a623':'#27c27b'}">${carts.pendingAction} cart${carts.pendingAction!==1?'s':''}</span></div>
            <div class="row" style="margin-bottom:0"><span class="row-label">Max emails sent</span><span class="row-value" style="color:#6b7280">${carts.maxEmails} carts</span></div>
          </div>
          ${(carts.carts||[]).filter(c=>c.status==='pending').slice(0,3).map(c=>`
          <div class="booking-row">
            <div>
              <div class="booking-name" style="font-size:11px">${c.email.split('@')[0]}@…</div>
              <div class="booking-detail">Tour: ${c.tour} · ${c.sendCount}/3 emails sent</div>
            </div>
            <div class="booking-amount">$${Number(c.amount).toLocaleString()}</div>
          </div>`).join('') || '<div class="empty-state" style="padding:8px">No carts pending action</div>'}
          <div style="font-size:10px;color:#6b7280;margin-top:8px">Updated: ${carts.updatedAt ? new Date(carts.updatedAt).toLocaleString('en-AU',{timeZone:'Australia/Brisbane',dateStyle:'short',timeStyle:'short'}) : '—'}</div>
          `}
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
          <div class="si highlight hl-red" data-id="finance-tamborine-invoice" data-status="pending" onclick="cycleStatus(this)" style="cursor:pointer">
            <span class="si-dot"></span>
            <div>
              <div class="hl-title" style="color:#e05252">Tamborine Intl Invoice</div>
              <div class="hl-text">$440 OVERDUE · HEN4901 · Was due 6 Mar</div>
            </div>
          </div>
          <div class="si highlight hl-orange" data-id="finance-westpac" data-status="pending" onclick="cycleStatus(this)" style="cursor:pointer;margin-top:8px">
            <span class="si-dot"></span>
            <div>
              <div class="hl-title" style="color:#f5a623">Westpac Dispute</div>
              <div class="hl-text">CS138010101 · Follow up required</div>
            </div>
          </div>
          <div class="si highlight hl-green" data-id="finance-disaster-grant" data-status="pending" onclick="cycleStatus(this)" style="cursor:pointer;margin-top:8px">
            <span class="si-dot"></span>
            <div>
              <div class="hl-title" style="color:#27c27b">Disaster Assistance Grant</div>
              <div class="hl-text">Ready to sign — Emma Bloem · SBFCS</div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="section-title">👥 Team</div>
          <div class="row"><span class="row-label">Bookings</span><span class="row-value">India · Tyler · Sharon</span></div>
          <div class="row"><span class="row-label">SEEK hiring</span><span class="row-value" style="color:#f5a623">11 applicants</span></div>
          <div class="row" style="margin-bottom:0"><span class="row-label">Role</span><span class="row-value">Tour Guide &amp; Driver</span></div>
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
          <div class="row"><span class="row-label">GA4</span><span class="badge ${ga4.error ? 'badge-orange' : 'badge-green'}">${ga4.error ? '⚠ GA4 error' : '✓ Live'}</span></div>
          <div class="row"><span class="row-label">Cart recovery</span><span class="badge badge-green">✓ 15m/24h/72h</span></div>
          <div class="row"><span class="row-label">Email (Resend)</span><span class="badge badge-green">✓ Live</span></div>
          <hr>
          <div class="section-title" style="margin-top:4px">🚨 Escalations</div>
          <div class="si booking-row" data-id="esc-ats-pacific" data-status="pending" onclick="cycleStatus(this)">
            <span class="si-dot"></span>
            <div><div class="booking-name">ATS Pacific / Frohwerk</div><div class="booking-detail">HOHO + Glow Worm · 15 Apr · TSTFRJ6485</div></div>
            <span class="badge badge-red">UNANSWERED</span>
          </div>
          <div class="si booking-row" data-id="esc-maddison-atia" data-status="pending" onclick="cycleStatus(this)">
            <span class="si-dot"></span>
            <div><div class="booking-name">Maddison Staader (ATIA)</div><div class="booking-detail">50-pax Canungra · 28 Aug · ~$8,250</div></div>
            <span class="badge badge-red">NEEDS TIMES</span>
          </div>
          <div class="si booking-row" data-id="esc-inside-australia" data-status="pending" onclick="cycleStatus(this)">
            <span class="si-dot"></span>
            <div><div class="booking-name">Inside Australia Travel</div><div class="booking-detail">Bos party · 5 Apr · PTQVVF7Y</div></div>
            <span class="badge badge-orange">PREPAY DUE</span>
          </div>
          <div class="si booking-row" data-id="booking-joshua-maas" data-status="pending" onclick="cycleStatus(this)">
            <span class="si-dot"></span>
            <div><div class="booking-name">Joshua Maas</div><div class="booking-detail">Wedding transfer · action required</div></div>
            <span class="badge badge-orange">WEDDING TRANSFER</span>
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

      <!-- GA4 Traffic by Channel + Top Pages -->
      <div class="grid grid-2">
        <div class="card">
          <div class="section-title st-green">📊 Traffic by Channel · ${rng}</div>
          ${ga4.error
            ? `<div class="empty-state">GA4 error: ${ga4.error}</div>`
            : ga4.channels && ga4.channels.length > 0
              ? (() => {
                  const maxSess = Math.max(...ga4.channels.map(c => c.sessions), 1);
                  return ga4.channels
                    .sort((a,b) => b.sessions - a.sessions)
                    .map(c => {
                      const isOrganic = c.channel === 'Organic Search';
                      const isPaid = c.channel.startsWith('Paid');
                      const color = isOrganic ? '#27c27b' : isPaid ? '#4d9fff' : '#f5a623';
                      const pct = Math.round((c.sessions / maxSess) * 100);
                      return `<div style="margin-bottom:10px">
                        <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                          <span style="font-size:12px;color:${color};font-weight:${isOrganic?'700':'400'}">${c.channel}</span>
                          <span style="font-size:12px;font-weight:600">${c.sessions.toLocaleString()}</span>
                        </div>
                        <div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:${color}"></div></div>
                      </div>`;
                    }).join('')
                })()
              : '<div class="empty-state">No channel data available</div>'
          }
        </div>
        <div class="card">
          <div class="section-title st-blue">📄 Top Pages · ${rng}</div>
          ${ga4.error
            ? `<div class="empty-state">GA4 error: ${ga4.error}</div>`
            : ga4.pages && ga4.pages.length > 0
              ? (() => {
                  const maxSess = Math.max(...ga4.pages.map(p => p.sessions), 1);
                  return ga4.pages.map(p => {
                    const pct = Math.round((p.sessions / maxSess) * 100);
                    const shortPath = p.path.length > 40 ? p.path.slice(0,40) + '…' : p.path;
                    return `<div style="margin-bottom:9px">
                      <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                        <span style="font-size:11px;color:var(--text-sub);font-family:monospace">${shortPath}</span>
                        <span style="font-size:11px;font-weight:600;white-space:nowrap;margin-left:8px">${p.sessions.toLocaleString()} sess</span>
                      </div>
                      <div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:#4d9fff"></div></div>
                    </div>`;
                  }).join('')
                })()
              : '<div class="empty-state">No page data available</div>'
          }
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
          <div class="si phase-item" data-id="seo-schema-markup" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Schema markup on tour pages</div>
          <div class="si phase-item" data-id="seo-faq-schema" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>FAQ schema on money pages</div>
          <div class="si phase-item" data-id="seo-entity-consistency" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Entity consistency</div>
          <div class="si phase-item" data-id="seo-core-web-vitals" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Core Web Vitals audit</div>
          <div class="si phase-item" data-id="seo-duplicate-meta" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Duplicate title/meta check</div>
          <div class="si phase-item" data-id="seo-internal-links" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Internal linking audit</div>
          <div class="si phase-item" data-id="seo-image-optimisation" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Image optimisation</div>
          <div class="si phase-item" data-id="seo-booking-urls" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Book Now popup → trackable URLs</div>
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
    <div class="grid">
      <!-- GA4 Live KPIs -->
      <div class="grid grid-4">
        <div class="kpi-box">
          <div class="kpi-value" style="color:#4d9fff">${ga4.error ? '—' : (ga4.totals.sessions ?? 0).toLocaleString()}</div>
          <div class="kpi-label">Total Sessions</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${ga4.error ? 'GA4 error' : rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#27c27b">${ga4.error ? '—' : (ga4.organicSearch.sessions ?? 0).toLocaleString()}</div>
          <div class="kpi-label">Organic Sessions</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${ga4.error ? '' : 'Google organic · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#9b6dff">${ga4.error ? '—' : (ga4.paidSocial.sessions ?? 0).toLocaleString()}</div>
          <div class="kpi-label">Paid Social Sessions</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${ga4.error ? '' : 'Meta / social ads · ' + rng}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-value" style="color:#f5a623">${ga4.error ? '—' : (ga4.direct.sessions ?? 0).toLocaleString()}</div>
          <div class="kpi-label">Direct Sessions</div>
          <div class="kpi-sub" style="color:var(--text-muted)">${ga4.error ? '' : 'Direct traffic · ' + rng}</div>
        </div>
      </div>

      <!-- Channel Breakdown + Device Split -->
      <div class="grid grid-2">
        <div class="card">
          <div class="section-title st-green">📊 Channel Breakdown · ${rng}</div>
          ${ga4.error
            ? '<div class="empty-state">GA4 error: ' + ga4.error + '</div>'
            : ga4.channels && ga4.channels.length > 0
              ? (() => {
                  const totalSess = ga4.channels.reduce((s,c) => s+c.sessions, 0) || 1;
                  const maxSess = Math.max(...ga4.channels.map(c => c.sessions), 1);
                  return ga4.channels
                    .sort((a,b) => b.sessions - a.sessions)
                    .map(c => {
                      const isOrganic = c.channel === 'Organic Search';
                      const isPaidSearch = c.channel === 'Paid Search';
                      const isPaidSocial = c.channel === 'Paid Social';
                      const isDirect = c.channel === 'Direct';
                      const color = isOrganic ? '#27c27b' : isPaidSearch ? '#4d9fff' : isPaidSocial ? '#9b6dff' : isDirect ? '#f5a623' : '#6b7280';
                      const pct = Math.round((c.sessions / maxSess) * 100);
                      const sharePct = Math.round((c.sessions / totalSess) * 100);
                      return '<div style="margin-bottom:10px">'
                        + '<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
                        + '<span style="font-size:12px;color:' + color + ';font-weight:' + (isOrganic?'700':'400') + '">' + c.channel + '</span>'
                        + '<span style="font-size:12px;font-weight:600">' + c.sessions.toLocaleString() + ' <span style="color:var(--text-muted);font-weight:400">(' + sharePct + '%)</span></span>'
                        + '</div>'
                        + '<div class="progress-bar"><div class="progress-fill" style="width:' + pct + '%;background:' + color + '"></div></div>'
                        + '</div>';
                    }).join('')
                })()
              : '<div class="empty-state">No channel data available</div>'
          }
        </div>
        <div class="card">
          <div class="section-title st-blue">📱 Device Split · ${rng}</div>
          ${ga4.error
            ? '<div class="empty-state">GA4 error: ' + ga4.error + '</div>'
            : (() => {
                const total = ga4.totalDevSessions || 1;
                const devMap = {};
                (ga4.devices||[]).forEach(d => { devMap[d.device] = d.sessions; });
                const mobile = devMap['mobile'] || 0;
                const desktop = devMap['desktop'] || 0;
                const tablet = devMap['tablet'] || 0;
                const mobilePct = Math.round(mobile/total*100);
                const desktopPct = Math.round(desktop/total*100);
                const tabletPct = Math.round(tablet/total*100);
                return '<div style="margin-bottom:14px">'
                  + '<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
                  + '<span style="font-size:12px;color:#f5a623">📱 Mobile</span>'
                  + '<span style="font-size:12px;font-weight:700">' + mobilePct + '%</span>'
                  + '</div>'
                  + '<div class="progress-bar"><div class="progress-fill" style="width:' + mobilePct + '%;background:#f5a623"></div></div>'
                  + '<div style="font-size:10px;color:var(--text-muted);margin-top:2px">' + mobile.toLocaleString() + ' sessions</div>'
                  + '</div>'
                  + '<div style="margin-bottom:14px">'
                  + '<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
                  + '<span style="font-size:12px;color:#4d9fff">🖥️ Desktop</span>'
                  + '<span style="font-size:12px;font-weight:700">' + desktopPct + '%</span>'
                  + '</div>'
                  + '<div class="progress-bar"><div class="progress-fill" style="width:' + desktopPct + '%;background:#4d9fff"></div></div>'
                  + '<div style="font-size:10px;color:var(--text-muted);margin-top:2px">' + desktop.toLocaleString() + ' sessions</div>'
                  + '</div>'
                  + '<div>'
                  + '<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
                  + '<span style="font-size:12px;color:#9b6dff">⬜ Tablet</span>'
                  + '<span style="font-size:12px;font-weight:700">' + tabletPct + '%</span>'
                  + '</div>'
                  + '<div class="progress-bar"><div class="progress-fill" style="width:' + tabletPct + '%;background:#9b6dff"></div></div>'
                  + '<div style="font-size:10px;color:var(--text-muted);margin-top:2px">' + tablet.toLocaleString() + ' sessions</div>'
                  + '</div>';
              })()
          }
        </div>
      </div>

      <!-- Top Landing Pages -->
      <div class="card">
        <div class="section-title st-blue">📄 Top Landing Pages · ${rng}</div>
        ${ga4.error
          ? `<div class="empty-state">GA4 error: ${ga4.error}</div>`
          : ga4.pages && ga4.pages.length > 0
            ? (() => {
                const maxSess = Math.max(...ga4.pages.map(p => p.sessions), 1);
                const totalSess = ga4.pages.reduce((s,p) => s+p.sessions, 0) || 1;
                return `<div class="grid grid-2">` + ga4.pages.slice(0,8).map(p => {
                  const pct = Math.round((p.sessions / maxSess) * 100);
                  const sharePct = Math.round((p.sessions / totalSess) * 100);
                  const shortPath = p.path.length > 45 ? p.path.slice(0,45) + '…' : p.path;
                  return `<div style="margin-bottom:10px">
                    <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                      <span style="font-size:11px;color:var(--text-sub);font-family:monospace">${shortPath}</span>
                      <span style="font-size:11px;font-weight:600;white-space:nowrap;margin-left:8px">${p.sessions.toLocaleString()} <span style="color:var(--text-muted);font-weight:400">(${sharePct}%)</span></span>
                    </div>
                    <div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:#4d9fff"></div></div>
                  </div>`;
                }).join('') + `</div>`;
              })()
            : '<div class="empty-state">No page data available</div>'
        }
      </div>

      <!-- Tracking + Cart Recovery + Channels + Weekly Rhythm -->
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
          <div class="si row" data-id="mkt-google-ads" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span><span class="row-label">Google Ads</span><span class="badge badge-orange">Setup needed</span></div>
          <div class="si row" data-id="mkt-meta-ads" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span><span class="row-label">Meta Ads</span><span class="badge badge-orange">Setup needed</span></div>
          <div class="si row" data-id="mkt-gbp" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span><span class="row-label">Google Business Profile</span><span class="badge badge-orange">Optimise</span></div>
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
  </div>

  <!-- TECH -->
  <div id="panel-tech" class="panel">
    <div class="grid grid-2">
      <div class="card">
        <div class="section-title st-red">🔐 Security Checklist</div>
        <div class="si phase-item" data-id="sec-rotate-credentials" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Rotate WP + Cloudflare + Google OAuth</div>
        <div class="si phase-item" data-id="sec-rest-enumeration" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Block REST user enumeration</div>
        <div class="si phase-item" data-id="sec-security-headers" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Security headers (HSTS, XFO, XCTO)</div>
        <div class="si phase-item" data-id="sec-waf-rate-limits" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Cloudflare WAF + rate limits</div>
        <div class="si phase-item" data-id="sec-2fa" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>2FA all admin users</div>
        <div class="si phase-item" data-id="sec-daily-backups" data-status="pending" onclick="cycleStatus(this)"><span class="si-dot"></span>Daily encrypted backups</div>
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
        <div class="row"><span class="row-label">Analytics</span><span class="row-value" style="color:${ga4.error ? '#f5a623' : '#27c27b'}">GA4 ${ga4.error ? '⚠ ' + ga4.error : '✓ Connected'}</span></div>
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

// ── Item Status System ──────────────────────────────────────────────────────
const STATUS_KEY = 'pt_status';
const STATUS_CYCLE = ['pending','urgent','done','ignored'];

function loadStatuses() {
  try { return JSON.parse(localStorage.getItem(STATUS_KEY) || '{}'); } catch(e) { return {}; }
}
function saveStatuses(map) {
  localStorage.setItem(STATUS_KEY, JSON.stringify(map));
}

function applyStatus(el, status) {
  el.setAttribute('data-status', status);
  const dot = el.querySelector('.si-dot');
  if (dot) {
    if (status === 'done') {
      dot.className = 'si-done-dot';
    } else {
      dot.className = 'si-dot';
    }
  }
}

function cycleStatus(el) {
  const id = el.getAttribute('data-id');
  if (!id) return;
  const map = loadStatuses();
  const cur = map[id] || 'pending';
  const next = STATUS_CYCLE[(STATUS_CYCLE.indexOf(cur) + 1) % STATUS_CYCLE.length];
  map[id] = next;
  saveStatuses(map);
  // Apply to all elements with same data-id (same item may appear in multiple tabs)
  document.querySelectorAll('[data-id="'+id+'"]').forEach(e => applyStatus(e, next));
  updateStatusCounter();
}

function updateStatusCounter() {
  const map = loadStatuses();
  const vals = Object.values(map);
  const urgent = vals.filter(v=>v==='urgent').length;
  const done = vals.filter(v=>v==='done').length;
  const ignored = vals.filter(v=>v==='ignored').length;
  const el = document.getElementById('statusCounter');
  if (el) {
    el.innerHTML = urgent > 0 || done > 0 || ignored > 0
      ? '<span class="s-urgent">'+urgent+' Urgent</span> · <span class="s-done">'+done+' Done</span> · <span class="s-ignored">'+ignored+' Ignored</span>'
      : 'All items pending';
  }
}

// Initialise all status items from localStorage on load
(function initStatuses(){
  const map = loadStatuses();
  document.querySelectorAll('[data-id]').forEach(el => {
    const id = el.getAttribute('data-id');
    if (id && map[id]) applyStatus(el, map[id]);
  });
  updateStatusCounter();
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
    const [rezdy, stripe, ga4, speed, carts] = await Promise.all([
      getRezdyData(env.REZDY_API_KEY, days),
      getStripeData(env.STRIPE_SECRET_KEY, days),
      getGA4Data(env.GA4_SERVICE_ACCOUNT, days),
      getPageSpeed(),
      getCartData(env.DASH_KV)
    ]);

    return new Response(renderDashboard(rezdy, stripe, ga4, speed, carts, days), {
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
