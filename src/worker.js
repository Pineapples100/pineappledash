// OpenClaw Command Dashboard — Cloudflare Worker v2
// Cloudflare Access JWT validation + password fallback

const CF_ACCESS_AUD = "0fe8baeaf5db45e30644e10212729e9aea7a69760c686cd9226c2093e787bffc";
const CF_JWKS_URL = "https://pineapples.cloudflareaccess.com/cdn-cgi/access/certs";
const PASSWORD = "openclaw2026";
const COOKIE_NAME = "oc_auth";
const COOKIE_VALUE = "granted_petermyers";

// Validate Cloudflare Access JWT
async function validateCFAccessJWT(request) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return false;

  try {
    // Fetch JWKS
    const jwksRes = await fetch(CF_JWKS_URL);
    const jwks = await jwksRes.json();

    // Decode JWT header to get kid
    const [headerB64] = token.split(".");
    const header = JSON.parse(atob(headerB64.replace(/-/g, "+").replace(/_/g, "/")));

    // Find matching key
    const key = jwks.keys.find(k => k.kid === header.kid);
    if (!key) return false;

    // Import public key
    const cryptoKey = await crypto.subtle.importKey(
      "jwk", key,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false, ["verify"]
    );

    // Verify signature
    const [, payloadB64, sigB64] = token.split(".");
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = Uint8Array.from(atob(sigB64.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));

    const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, signingInput);
    if (!valid) return false;

    // Verify audience
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.aud !== CF_ACCESS_AUD && !payload.aud?.includes?.(CF_ACCESS_AUD)) return false;

    // Verify expiry
    if (payload.exp < Math.floor(Date.now() / 1000)) return false;

    return true;
  } catch (e) {
    return false;
  }
}

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenClaw Command · Peter Myers</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0f1117;color:#e8eaf0;font-family:'Inter',system-ui,sans-serif;min-height:100vh;padding:20px}
  .wrap{max-width:1100px;margin:0 auto}
  .header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;flex-wrap:wrap;gap:10px}
  .header-left{display:flex;align-items:center;gap:10px}
  .logo{width:36px;height:36px;border-radius:8px;background:#f5a623;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
  .title{font-size:20px;font-weight:700}
  .subtitle{font-size:12px;color:#6b7280;margin-top:2px}
  .badges{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  .badge{border-radius:6px;padding:3px 9px;font-size:11px;font-weight:600;letter-spacing:.4px}
  .badge-red{background:#e0525222;color:#e05252;border:1px solid #e0525244}
  .badge-orange{background:#f5a62322;color:#f5a623;border:1px solid #f5a62344}
  .badge-green{background:#27c27b22;color:#27c27b;border:1px solid #27c27b44}
  .badge-blue{background:#4d9fff22;color:#4d9fff;border:1px solid #4d9fff44}
  .badge-purple{background:#9b6dff22;color:#9b6dff;border:1px solid #9b6dff44}
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
  @media(max-width:700px){.grid-2,.grid-3,.grid-4{grid-template-columns:1fr}.span2,.span3{grid-column:span 1}}
  .card{background:#1a1d2e;border:1px solid #252840;border-radius:12px;padding:16px}
  .card-urgent{background:#1e0d0d;border-color:#5a2020}
  .card-legal{background:#1a0d0d;border-color:#5a2020}
  .section-title{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;color:#f5a623}
  .st-red{color:#e05252}.st-blue{color:#4d9fff}.st-purple{color:#9b6dff}.st-green{color:#27c27b}
  .row{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:7px;gap:8px}
  .row-label{font-size:12px;color:#9ca3af;flex-shrink:0}
  .row-value{font-size:12px;font-weight:600;text-align:right}
  .row-sub{font-size:10px;color:#6b7280;text-align:right}
  .dot{display:inline-block;width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-top:4px}
  .urgent-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
  @media(max-width:700px){.urgent-grid{grid-template-columns:1fr}}
  .urgent-item{background:#2a1010;border:1px solid #5a2020;border-radius:8px;padding:12px}
  .urgent-title{font-size:12px;font-weight:700;color:#e05252;margin-bottom:4px}
  .urgent-who{font-size:11px;color:#9ca3af;margin-bottom:4px}
  .urgent-detail{font-size:11px;color:#e8eaf0;margin-bottom:8px}
  .stat-grid{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px}
  @media(max-width:700px){.stat-grid{grid-template-columns:1fr 1fr}}
  .stat-box{background:#12151f;border-radius:8px;padding:10px;text-align:center}
  .stat-icon{font-size:20px;margin-bottom:4px}
  .stat-value{font-size:13px;font-weight:700}
  .stat-label{font-size:10px;color:#6b7280;margin-top:1px}
  .stat-sub{font-size:10px;color:#27c27b;margin-top:2px}
  .company-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
  .company-name{font-size:12px;font-weight:600}
  .company-detail{font-size:10px;color:#6b7280}
  .booking-item{margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid #252840}
  .booking-item:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
  .booking-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;gap:6px}
  .booking-client{font-size:11px;font-weight:700}
  .booking-detail{font-size:10px;color:#6b7280}
  .deadline-item{display:flex;gap:8px;margin-bottom:8px;align-items:flex-start}
  .deadline-date{font-size:11px;font-weight:700}
  .deadline-desc{font-size:11px;color:#9ca3af}
  .highlight{border-radius:8px;padding:10px;margin-top:10px}
  .hl-green{background:#101a10;border:1px solid #27c27b44}
  .hl-purple{background:#1e1330;border:1px solid #9b6dff44}
  .hl-orange{background:#1a1200;border:1px solid #f5a62344}
  .hl-title{font-size:11px;font-weight:700;margin-bottom:4px}
  .hl-text{font-size:11px;color:#e8eaf0}
  .check-item{display:flex;gap:8px;margin-bottom:7px;align-items:flex-start}
  .check-text{font-size:11px}
  .tag{display:inline-block;background:#0d1520;color:#4d9fff;font-family:monospace;font-size:10px;padding:2px 6px;border-radius:4px;margin:2px}
  .phase{margin-bottom:10px}
  .phase-title{font-size:11px;font-weight:700;color:#f5a623;margin-bottom:4px}
  .phase-item{font-size:11px;color:#9ca3af;display:flex;gap:6px;margin-bottom:2px}
  .kpi-grid{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px}
  @media(max-width:700px){.kpi-grid{grid-template-columns:1fr 1fr}}
  .kpi-box{background:#2a1010;border-radius:8px;padding:10px;text-align:center}
  .kpi-value{font-size:18px;font-weight:800}
  .kpi-label{font-size:10px;color:#9ca3af;margin-top:2px}
  .kpi-sub{font-size:10px;color:#6b7280}
  .rhythm-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
  @media(max-width:700px){.rhythm-grid{grid-template-columns:1fr}}
  .rhythm-card{background:#12151f;border-radius:8px;padding:12px;text-align:center;border-top:3px solid}
  .rhythm-day{font-size:13px;font-weight:700;margin-bottom:4px}
  .rhythm-focus{font-size:11px;color:#e8eaf0;margin:4px 0}
  .folder-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}
  @media(max-width:700px){.folder-grid{grid-template-columns:1fr}}
  .folder-item{background:#12151f;border-radius:6px;padding:8px}
  .folder-name{font-size:10px;color:#f5a623;font-family:monospace;margin-bottom:2px}
  .folder-count{font-size:10px;color:#6b7280}
  .panel{display:none}
  .panel.active{display:block}
  hr{border:none;border-top:1px solid #252840;margin:12px 0}
  .footer{margin-top:24px;text-align:center;font-size:10px;color:#6b7280}
  .security-badge{display:inline-flex;align-items:center;gap:4px;background:#101a10;border:1px solid #27c27b44;border-radius:6px;padding:3px 8px;font-size:10px;color:#27c27b}
</style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <div class="header-left">
      <div class="logo">🍍</div>
      <div>
        <div class="title">OpenClaw Command</div>
        <div class="subtitle">Peter Myers · Gold Coast QLD · Sat 14 Mar 2026</div>
      </div>
    </div>
    <div class="badges">
      <span class="badge badge-red">3 Urgent</span>
      <span class="badge badge-orange">2 Legal Active</span>
      <span class="badge badge-green">Live</span>
      <span class="security-badge">🔒 CF Access</span>
    </div>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('overview',this)">Overview</button>
    <button class="tab" onclick="showTab('business',this)">Business</button>
    <button class="tab" onclick="showTab('legal',this)">Legal</button>
    <button class="tab" onclick="showTab('personal',this)">Personal</button>
    <button class="tab" onclick="showTab('tech',this)">Tech</button>
  </div>

  <!-- OVERVIEW -->
  <div id="panel-overview" class="panel active">
    <div class="grid">
      <div class="card card-urgent">
        <div class="section-title st-red">🔴 Action Required Today</div>
        <div class="urgent-grid">
          <div class="urgent-item">
            <div class="urgent-title">Investor Deck Review</div>
            <div class="urgent-who">Anthony Owen · Catena Capital</div>
            <div class="urgent-detail">Hopio_SeriesA_FINAL.pptx — approve or send changes. Investors waiting.</div>
            <span class="badge badge-red">Today / Monday</span>
          </div>
          <div class="urgent-item">
            <div class="urgent-title">Disaster Assistance Grant</div>
            <div class="urgent-who">Emma Bloem · SBFCS</div>
            <div class="urgent-detail">Final version ready — sign and return to lodge.</div>
            <span class="badge badge-red">ASAP</span>
          </div>
          <div class="urgent-item">
            <div class="urgent-title">Westpac Complaint Follow-up</div>
            <div class="urgent-who">carddisputedocuments@westpac.com.au</div>
            <div class="urgent-detail">CS138010101 — courtesy follow-up received. Unmonitored inbox, call if urgent.</div>
            <span class="badge badge-orange">This week</span>
          </div>
        </div>
      </div>

      <div class="grid grid-3">
        <div class="card">
          <div class="section-title">🏢 Companies</div>
          <div class="company-row"><div><div class="company-name">Pineapple Tours</div><div class="company-detail">Tour ops · Rezdy · Bookings team</div></div><span class="badge badge-green">Operating</span></div>
          <div class="company-row"><div><div class="company-name">Hopio</div><div class="company-detail">Series A deck circulating</div></div><span class="badge badge-orange">Fundraising</span></div>
          <div class="company-row"><div><div class="company-name">HOHO Transit</div><div class="company-detail">Hop On Hop Off bus network</div></div><span class="badge badge-blue">Active</span></div>
          <div class="company-row" style="margin-bottom:0"><div><div class="company-name">JRNY</div><div class="company-detail">Platform in development</div></div><span class="badge badge-purple">Dev</span></div>
        </div>
        <div class="card">
          <div class="section-title st-red">⚖️ Legal — Active</div>
          <div style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid #252840">
            <div style="font-size:12px;font-weight:700;color:#e05252;margin-bottom:6px">Flexicommercial · NSW DC</div>
            <div class="row"><span class="row-label">Settlement offer</span><span class="row-value" style="color:#f5a623">$130,000</span></div>
            <div class="row"><span class="row-label">Offer expires</span><span class="row-value" style="color:#e05252">26 Mar 4pm</span></div>
            <div class="row"><span class="row-label">Defence deadline</span><span class="row-value" style="color:#f5a623">20 Mar 4pm</span></div>
            <div class="row" style="margin-bottom:0"><span class="row-label">Extension consent by</span><span class="row-value" style="color:#e05252">Mon 16 Mar</span></div>
          </div>
          <div style="font-size:12px;font-weight:700;color:#9b6dff;margin-bottom:6px">TAL Income Protection · AFCA</div>
          <div class="row"><span class="row-label">Case</span><span class="row-value">12-25-275731</span></div>
          <div class="row"><span class="row-label">Last submission</span><span class="row-value">5 Feb 2026</span></div>
          <div class="row" style="margin-bottom:0"><span class="row-label">Status</span><span class="row-value" style="color:#f5a623">Active at AFCA</span></div>
        </div>
        <div class="card">
          <div class="section-title st-red">📅 Upcoming Deadlines</div>
          <div class="deadline-item"><div class="dot" style="background:#e05252"></div><div><div class="deadline-date" style="color:#e05252">Mon 16 Mar</div><div class="deadline-desc">Consent to extend defence (Flexi)</div></div></div>
          <div class="deadline-item"><div class="dot" style="background:#e05252"></div><div><div class="deadline-date" style="color:#e05252">Fri 20 Mar</div><div class="deadline-desc">Defence due NSW District Court</div></div></div>
          <div class="deadline-item"><div class="dot" style="background:#f5a623"></div><div><div class="deadline-date" style="color:#f5a623">Thu 26 Mar</div><div class="deadline-desc">Settlement offer expiry $130K</div></div></div>
          <div class="deadline-item"><div class="dot" style="background:#4d9fff"></div><div><div class="deadline-date" style="color:#4d9fff">Sat 5 Apr</div><div class="deadline-desc">Inside Australia Travel — PTQVVF7Y</div></div></div>
          <div class="deadline-item"><div class="dot" style="background:#4d9fff"></div><div><div class="deadline-date" style="color:#4d9fff">Tue 15 Apr</div><div class="deadline-desc">ATS Pacific booking TSTFRJ6485</div></div></div>
          <div class="deadline-item" style="margin-bottom:0"><div class="dot" style="background:#27c27b"></div><div><div class="deadline-date" style="color:#27c27b">Fri 28 Aug</div><div class="deadline-desc">ATIA 50-pax Canungra ~$8,250</div></div></div>
        </div>
      </div>
    </div>
  </div>

  <!-- BUSINESS -->
  <div id="panel-business" class="panel">
    <div class="grid grid-2">
      <div class="card span2">
        <div class="section-title">🍍 Pineapple Tours — Operations</div>
        <div class="stat-grid">
          <div class="stat-box"><div class="stat-icon">📋</div><div class="stat-value">Rezdy</div><div class="stat-label">Booking Platform</div><div class="stat-sub">Live</div></div>
          <div class="stat-box"><div class="stat-icon">💳</div><div class="stat-value">Stripe</div><div class="stat-label">Payments</div><div class="stat-sub">Live key active</div></div>
          <div class="stat-box"><div class="stat-icon">👥</div><div class="stat-value">India + Tyler</div><div class="stat-label">Bookings Team</div><div class="stat-sub">+ Sharon</div></div>
          <div class="stat-box"><div class="stat-icon">🔍</div><div class="stat-value">11 Applicants</div><div class="stat-label">SEEK · Tour Guide & Driver</div><div class="stat-sub">#90456636</div></div>
        </div>
      </div>
      <div class="card">
        <div class="section-title">📬 Bookings Inbox — Escalations</div>
        <div class="booking-item"><div class="booking-header"><span class="booking-client">ATS Pacific / Frohwerk party</span><span class="badge badge-red">UNANSWERED</span></div><div class="booking-detail">HOHO + Glow Worm · 15 Apr · ref: TSTFRJ6485</div></div>
        <div class="booking-item"><div class="booking-header"><span class="booking-client">Maddison Staader (ATIA)</span><span class="badge badge-red">NEEDS TIMES TODAY</span></div><div class="booking-detail">50-pax Canungra · 28 Aug · ~$8,250</div></div>
        <div class="booking-item"><div class="booking-header"><span class="booking-client">Inside Australia Travel</span><span class="badge badge-orange">PREPAYMENT DUE</span></div><div class="booking-detail">John & Joann Bos · 5 Apr · ref: PTQVVF7Y</div></div>
        <div class="booking-item"><div class="booking-header"><span class="booking-client">Joshua Maas — Wedding transfer</span><span class="badge badge-green">IN PROGRESS</span></div><div class="booking-detail">SUV availability · India handling</div></div>
      </div>
      <div class="card">
        <div class="section-title st-purple">🚀 Hopio — Investor Status</div>
        <div class="row"><span class="row-label">Stage</span><span class="row-value" style="color:#9b6dff">Series A</span></div>
        <div class="row"><span class="row-label">Deck</span><span class="row-value" style="color:#f5a623">Hopio_SeriesA_FINAL.pptx</span></div>
        <div class="row"><span class="row-label">Sent by</span><span class="row-value">Anthony Owen · Catena Capital</span></div>
        <div class="row"><span class="row-label">Co-lead</span><span class="row-value">Tom Coates · TPC Capital</span></div>
        <div class="row"><span class="row-label">Meeting today</span><span class="row-value" style="color:#4d9fff">Emil Juresic 1pm</span></div>
        <div class="highlight hl-purple"><div class="hl-title" style="color:#9b6dff">Your action</div><div class="hl-text">Review deck end-to-end and give go-ahead or send edits to Anthony. Target: today or Monday.</div></div>
      </div>
      <div class="card">
        <div class="section-title">📊 Analytics Roadmap (30/60/90)</div>
        <div class="phase"><div class="phase-title">Week 1 — Now</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Credential rotation (WP, Cloudflare, Google OAuth)</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Security headers + WAF rules</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Checkout event tracking (DataLayer)</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Stripe webhook logging</div>
        </div>
        <div class="phase"><div class="phase-title">Day 8–30</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Executive dashboard live</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Abandoned cart recovery automation</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Weekly KPI review cadence</div>
        </div>
        <div class="phase" style="margin-bottom:0"><div class="phase-title">Day 31–90</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Core Web Vitals · Mobile UX</div>
          <div class="phase-item"><span style="color:#6b7280">○</span>Reconciliation controls · Forecasting</div>
        </div>
      </div>
      <div class="card">
        <div class="section-title">🏦 Finance</div>
        <div class="row"><span class="row-label">Tamborine Intl Invoice</span><div><div class="row-value" style="color:#e05252">$440 OVERDUE</div><div class="row-sub">HEN4901 · Due 6 Mar</div></div></div>
        <div class="row"><span class="row-label">Accounting FY</span><div><div class="row-value">FY2024–25</div><div class="row-sub">Varion accountants</div></div></div>
        <div class="row"><span class="row-label">Tax entities</span><div><div class="row-value">3</div><div class="row-sub">PT Pty Ltd · Holdings Trust · Personal</div></div></div>
        <div class="row"><span class="row-label">Aussie Broadband</span><div><div class="row-value" style="color:#f5a623">Invoice due</div><div class="row-sub">#56598714 · 13 Mar</div></div></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Westpac Dispute</span><div><div class="row-value" style="color:#e05252">CS138010101</div><div class="row-sub">Follow-up required</div></div></div>
      </div>
      <div class="card">
        <div class="section-title">🏗️ Property — Mt Nathan</div>
        <div class="row"><span class="row-label">Address</span><span class="row-value" style="font-size:11px">22 Nerang Murwillumbah Rd</span></div>
        <div class="row"><span class="row-label">Architecture</span><span class="row-value" style="color:#27c27b">DD01–DD03 Rev B ✓</span></div>
        <div class="row"><span class="row-label">Engineering</span><span class="row-value" style="color:#27c27b">Site classification ✓</span></div>
        <div class="row"><span class="row-label">Permits</span><span class="row-value" style="color:#f5a623">Pending</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Quotes</span><span class="row-value" style="color:#f5a623">Pending</span></div>
      </div>
    </div>
  </div>

  <!-- LEGAL -->
  <div id="panel-legal" class="panel">
    <div class="grid grid-2">
      <div class="card card-legal span2">
        <div class="section-title st-red">⚖️ Pineapple & Co vs Flexicommercial · NSW District Court 2025/00498881</div>
        <div class="kpi-grid">
          <div class="kpi-box"><div class="kpi-value" style="color:#27c27b">$130,000</div><div class="kpi-label">Settlement Offer</div><div class="kpi-sub">Inc. GST · lump sum 30 days</div></div>
          <div class="kpi-box"><div class="kpi-value" style="color:#e05252">26 Mar</div><div class="kpi-label">Offer Expires</div><div class="kpi-sub">4:00pm · Calderbank</div></div>
          <div class="kpi-box"><div class="kpi-value" style="color:#e05252">20 Mar</div><div class="kpi-label">Defence Due</div><div class="kpi-sub">4:00pm · Extension sought</div></div>
          <div class="kpi-box"><div class="kpi-value" style="color:#e05252">Mon 16 Mar</div><div class="kpi-label">Consent Deadline</div><div class="kpi-sub">Bridges Lawyers by 4pm</div></div>
        </div>
        <div class="highlight hl-green" style="margin-top:12px">
          <div class="hl-title" style="color:#27c27b">V2 Without Prejudice Letter — Ready to Issue</div>
          <div class="hl-text">Approved by Peter. Reply to Tyrone Albertyn (t.albertyn@roselitigation.com.au) to authorise issue to Bridges Lawyers.</div>
        </div>
      </div>
      <div class="card">
        <div class="section-title">📋 Case File Structure</div>
        <div class="row"><span class="row-label">01 Pleadings & Filings</span><span class="row-value" style="color:#27c27b">2 files ✓</span></div>
        <div class="row"><span class="row-label">02 Contracts & Finance</span><span class="row-value" style="color:#27c27b">14 files ✓</span></div>
        <div class="row"><span class="row-label">03 Correspondence Flexi</span><span class="row-value" style="color:#27c27b">10 files ✓</span></div>
        <div class="row"><span class="row-label">04 Evidence Timeline</span><span class="row-value" style="color:#27c27b">3 files ✓</span></div>
        <div class="row"><span class="row-label">05 QCAT</span><span class="row-value" style="color:#27c27b">35 files ✓</span></div>
        <div class="row"><span class="row-label">06 Rose Litigation</span><span class="row-value" style="color:#27c27b">3 files ✓</span></div>
        <div class="row"><span class="row-label">07 Contingent Claims</span><span class="row-value" style="color:#6b7280">Standby</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">99 Raw Archive</span><span class="row-value" style="color:#27c27b">87 files ✓</span></div>
      </div>
      <div class="card">
        <div class="section-title">🏛️ Key Parties</div>
        <div class="row"><span class="row-label">Your solicitors</span><span class="row-value">Rose Litigation Lawyers</span></div>
        <div class="row"><span class="row-label">Tyrone Albertyn</span><span class="row-value" style="font-size:10px">t.albertyn@roselitigation.com.au</span></div>
        <div class="row"><span class="row-label">Michael Robson</span><span class="row-value">Rose Litigation</span></div>
        <hr>
        <div class="row"><span class="row-label">Opposing</span><span class="row-value">Bridges Lawyers</span></div>
        <div class="row"><span class="row-label">C Brown</span><span class="row-value" style="font-size:10px">cbrown@bridgeslawyers.com.au</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">H Stathakis</span><span class="row-value" style="font-size:10px">hstathakis@bridgeslawyers.com.au</span></div>
      </div>
      <div class="card">
        <div class="section-title st-purple">🦵 TAL Income Protection · AFCA 12-25-275731</div>
        <div class="row"><span class="row-label">Insurer</span><span class="row-value">TAL Direct Pty Ltd</span></div>
        <div class="row"><span class="row-label">Policy</span><span class="row-value">Virgin IP · since 2017</span></div>
        <div class="row"><span class="row-label">Claim</span><span class="row-value">Left knee / incapacity</span></div>
        <div class="row"><span class="row-label">Last AFCA submission</span><span class="row-value" style="color:#27c27b">5 Feb 2026</span></div>
        <div class="row"><span class="row-label">TAL last response</span><span class="row-value">15 Dec 2025</span></div>
        <div class="row" style="margin-bottom:8px"><span class="row-label">Status</span><span class="row-value" style="color:#f5a623">Active at AFCA</span></div>
        <div style="font-size:11px;color:#6b7280;margin-bottom:4px">Priority exhibits</div>
        <div class="phase-item"><span style="color:#9b6dff">1.</span>Medical timeline Jan 2026</div>
        <div class="phase-item"><span style="color:#9b6dff">2.</span>AFCA submission Oct 2025</div>
        <div class="phase-item"><span style="color:#9b6dff">3.</span>PDI financial rebuttal</div>
        <div class="phase-item"><span style="color:#9b6dff">4.</span>Radiology report (Qscan)</div>
      </div>
      <div class="card span2">
        <div class="section-title">📁 Legal Folders</div>
        <div class="folder-grid">
          <div class="folder-item"><div class="folder-name">Pineapple & Co vs Flexicommercial</div><div class="folder-count">154 files · fully indexed</div></div>
          <div class="folder-item"><div class="folder-name">Left Knee · TAL · AFCA ORGANIZED</div><div class="folder-count">Fully indexed · priority bundle ready</div></div>
          <div class="folder-item"><div class="folder-name">AFCAClaim</div><div class="folder-count">Folder ready</div></div>
          <div class="folder-item"><div class="folder-name">Pineapple & Co Vs Wren Civil</div><div class="folder-count">Folder ready</div></div>
          <div class="folder-item"><div class="folder-name">InsuranceDispute</div><div class="folder-count">Folder ready</div></div>
          <div class="folder-item"><div class="folder-name">CourtProceedings</div><div class="folder-count">Folder ready</div></div>
        </div>
      </div>
    </div>
  </div>

  <!-- PERSONAL -->
  <div id="panel-personal" class="panel">
    <div class="grid grid-2">
      <div class="card">
        <div class="section-title">🏠 Property — Mt Nathan Build</div>
        <div class="row"><span class="row-label">Site</span><span class="row-value" style="font-size:11px">22 Nerang Murwillumbah Rd, Mt Nathan</span></div>
        <div class="row"><span class="row-label">Architecture</span><span class="row-value" style="color:#27c27b">DD01–DD03 Rev B ✓</span></div>
        <div class="row"><span class="row-label">Engineering</span><span class="row-value" style="color:#27c27b">Site classification ✓</span></div>
        <div class="row"><span class="row-label">Valuation</span><span class="row-value" style="color:#27c27b">On file ✓</span></div>
        <div class="row"><span class="row-label">Permits</span><span class="row-value" style="color:#f5a623">Pending</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Quotes</span><span class="row-value" style="color:#f5a623">Pending</span></div>
      </div>
      <div class="card">
        <div class="section-title st-purple">🦵 TAL / AFCA — Health Claim</div>
        <div class="row"><span class="row-label">Condition</span><span class="row-value">Left knee · income protection</span></div>
        <div class="row"><span class="row-label">Policy</span><span class="row-value" style="font-size:11px">Virgin IP 2017 · Policy 89086695</span></div>
        <div class="row"><span class="row-label">AFCA submissions</span><span class="row-value" style="color:#27c27b">4 submissions (2024–2026)</span></div>
        <div class="row"><span class="row-label">Last action</span><span class="row-value" style="color:#27c27b">Feb 2026 + addendum</span></div>
        <div class="row"><span class="row-label">TAL last</span><span class="row-value">15 Dec 2025 response</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Key evidence</span><span class="row-value" style="color:#f5a623">20 priority exhibits indexed</span></div>
      </div>
      <div class="card">
        <div class="section-title">👨‍👩‍👧 Family Structure</div>
        <div class="row"><span class="row-label">Spouse</span><span class="row-value">Pannara Myers · Co-director</span></div>
        <div class="row"><span class="row-label">Trust</span><div><div class="row-value">Pineapple Holdings Trust</div><div class="row-sub">ABN 74 105 127 292</div></div></div>
        <div class="row"><span class="row-label">Entity</span><div><div class="row-value">Pineapple & Co Pty Ltd</div><div class="row-sub">ACN 633 675 144</div></div></div>
        <div class="row"><span class="row-label">Accountant</span><span class="row-value">Varion</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Tax filings</span><span class="row-value" style="color:#27c27b">FY23 + FY24 complete ✓</span></div>
      </div>
      <div class="card">
        <div class="section-title">📂 Personal File System</div>
        <div class="row"><span class="row-label">Finance (03)</span><span class="row-value" style="font-size:11px;color:#9ca3af">FY16–FY25 · bank · BAS · tax</span></div>
        <div class="row"><span class="row-label">Family (06)</span><span class="row-value" style="font-size:11px;color:#9ca3af">Education · health · estate</span></div>
        <div class="row"><span class="row-label">Personal (07)</span><span class="row-value" style="font-size:11px;color:#9ca3af">Left knee · TAL · ideas</span></div>
        <div class="row"><span class="row-label">Research (08)</span><span class="row-value" style="font-size:11px;color:#6b7280">AI · economics · tourism</span></div>
        <div class="row"><span class="row-label">Templates (09)</span><span class="row-value" style="font-size:11px;color:#6b7280">Contracts · emails · SOPs</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Archive (10)</span><span class="row-value" style="font-size:11px;color:#6b7280">Superseded docs</span></div>
      </div>
    </div>
  </div>

  <!-- TECH -->
  <div id="panel-tech" class="panel">
    <div class="grid grid-2">
      <div class="card">
        <div class="section-title st-red">🔐 Security — Pineapple Tours (P0)</div>
        <div class="check-item"><span style="color:#e05252">○</span><span class="check-text">Rotate credentials: WP, Cloudflare token, Google OAuth</span></div>
        <div class="check-item"><span style="color:#e05252">○</span><span class="check-text">Block REST user enumeration (/wp-json/wp/v2/users*)</span></div>
        <div class="check-item"><span style="color:#e05252">○</span><span class="check-text">Security headers (HSTS, XFO, XCTO, Referrer, Permissions-Policy)</span></div>
        <div class="check-item"><span style="color:#e05252">○</span><span class="check-text">Cloudflare WAF + rate limits (wp-login, xmlrpc, wp-json)</span></div>
        <div class="check-item"><span style="color:#e05252">○</span><span class="check-text">2FA enabled for all admin users</span></div>
        <div class="check-item"><span style="color:#e05252">○</span><span class="check-text">WordPress config hardening (DISALLOW_FILE_EDIT, FORCE_SSL)</span></div>
        <div class="check-item"><span style="color:#e05252">○</span><span class="check-text">Daily encrypted backups · 30-day retention</span></div>
        <div class="check-item"><span style="color:#e05252">○</span><span class="check-text">Centralised logging + alerts (5xx, brute force, payment failures)</span></div>
        <hr>
        <div class="section-title st-green" style="margin-top:4px">✅ This Dashboard</div>
        <div class="check-item"><span style="color:#27c27b">✓</span><span class="check-text">Cloudflare Access (Google auth) — zero trust</span></div>
        <div class="check-item"><span style="color:#27c27b">✓</span><span class="check-text">JWT validation in Worker</span></div>
        <div class="check-item"><span style="color:#27c27b">✓</span><span class="check-text">HTTPS only · Cloudflare TLS</span></div>
        <div class="check-item"><span style="color:#27c27b">✓</span><span class="check-text">Static HTML · no database · no API calls</span></div>
      </div>
      <div class="card">
        <div class="section-title st-blue">📡 Tracking — DataLayer Events</div>
        <div style="margin-bottom:10px">
          <span class="tag">pt_view_tour</span><span class="tag">pt_start_checkout</span><span class="tag">pt_payment_attempt</span><span class="tag">pt_payment_succeeded</span><span class="tag">pt_payment_failed</span><span class="tag">pt_booking_confirmed</span><span class="tag">pt_checkout_idle_15m</span><span class="tag">pt_checkout_abandoned_60m</span><span class="tag">pt_stripe_api_error</span><span class="tag">pt_webhook_verification_failed</span>
        </div>
        <hr>
        <div class="section-title" style="margin-top:8px">🛒 Abandoned Cart Recovery</div>
        <div class="row"><span class="row-label">15 min</span><span class="row-value" style="color:#4d9fff">Email/SMS reminder #1</span></div>
        <div class="row"><span class="row-label">24 hr</span><span class="row-value" style="color:#4d9fff">Email #2 + support CTA</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">72 hr</span><span class="row-value" style="color:#9b6dff">Final + optional incentive</span></div>
      </div>
      <div class="card">
        <div class="section-title st-green">⚡ Alert Thresholds</div>
        <div class="row"><span class="row-label">Payment failure rate</span><span class="row-value" style="color:#e05252">&gt; 8% / 15 min</span></div>
        <div class="row"><span class="row-label">Checkout-to-booking drop</span><span class="row-value" style="color:#e05252">&gt; 30% day-on-day</span></div>
        <div class="row"><span class="row-label">Webhook failures</span><span class="row-value" style="color:#e05252">&gt; 5 in 10 min</span></div>
        <div class="row"><span class="row-label">5xx errors</span><span class="row-value" style="color:#f5a623">&gt; baseline + 3σ</span></div>
        <div class="row" style="margin-bottom:12px"><span class="row-label">Hourly revenue</span><span class="row-value" style="color:#f5a623">&lt; 60% 4-week median</span></div>
        <hr>
        <div class="section-title st-blue" style="margin-top:4px">🛠️ Tech Stack</div>
        <div class="row"><span class="row-label">Site</span><span class="row-value">WordPress · pineappletours.com.au</span></div>
        <div class="row"><span class="row-label">Hosting/CDN</span><span class="row-value">Cloudflare</span></div>
        <div class="row"><span class="row-label">Payments</span><span class="row-value">Stripe (live)</span></div>
        <div class="row"><span class="row-label">Bookings</span><span class="row-value">Rezdy API</span></div>
        <div class="row"><span class="row-label">Analytics</span><span class="row-value">GA4 + GTM</span></div>
        <div class="row" style="margin-bottom:0"><span class="row-label">Email</span><span class="row-value">Resend (branded templates)</span></div>
      </div>
      <div class="card">
        <div class="section-title">🗓️ Weekly Operating Rhythm</div>
        <div class="rhythm-grid">
          <div class="rhythm-card" style="border-top-color:#4d9fff"><div class="rhythm-day" style="color:#4d9fff">Monday</div><div class="rhythm-focus">KPI + Incidents Review</div><span class="badge badge-blue">30 min</span></div>
          <div class="rhythm-card" style="border-top-color:#9b6dff"><div class="rhythm-day" style="color:#9b6dff">Wednesday</div><div class="rhythm-focus">Experiment / Release Review</div><span class="badge badge-purple">30 min</span></div>
          <div class="rhythm-card" style="border-top-color:#27c27b"><div class="rhythm-day" style="color:#27c27b">Friday</div><div class="rhythm-focus">Security + Backlog Triage</div><span class="badge badge-green">30 min</span></div>
        </div>
        <div class="highlight hl-orange" style="margin-top:12px">
          <div class="hl-title" style="color:#f5a623">KPI Dashboard Tabs (when built)</div>
          <div class="hl-text">Tab A: Executive Snapshot · Tab B: Funnel · Tab C: Payments Health · Tab D: Reliability & Errors</div>
        </div>
      </div>
    </div>
  </div>

  <div class="footer">OpenClaw · dashboard.pineappletours.com.au · CF Access protected · Sat 14 Mar 2026</div>
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

export default {
  async fetch(request) {
    // 1. Validate Cloudflare Access JWT (primary auth)
    const jwtValid = await validateCFAccessJWT(request);

    // 2. Check password cookie (fallback / belt-and-suspenders)
    const cookies = request.headers.get("Cookie") || "";
    const cookieValid = cookies.includes(`${COOKIE_NAME}=${COOKIE_VALUE}`);

    // 3. Handle POST (password login)
    if (request.method === "POST") {
      const body = await request.text();
      const params = new URLSearchParams(body);
      if (params.get("password") === PASSWORD) {
        const expiry = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toUTCString();
        return new Response("", {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `${COOKIE_NAME}=${COOKIE_VALUE};expires=${expiry};path=/;HttpOnly;Secure;SameSite=Strict`
          }
        });
      }
      return new Response(LOGIN_PAGE("Incorrect password."), { status: 401, headers: { "Content-Type": "text/html" } });
    }

    // 4. Grant access if CF Access JWT valid OR password cookie valid
    if (jwtValid || cookieValid) {
      return new Response(HTML, {
        headers: {
          "Content-Type": "text/html",
          "X-Frame-Options": "DENY",
          "X-Content-Type-Options": "nosniff",
          "Referrer-Policy": "no-referrer",
          "Cache-Control": "no-store"
        }
      });
    }

    // 5. Show login page
    return new Response(LOGIN_PAGE(""), { headers: { "Content-Type": "text/html" } });
  }
};

function LOGIN_PAGE(error) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OpenClaw · Login</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0f1117;color:#e8eaf0;font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#1a1d2e;border:1px solid #252840;border-radius:16px;padding:40px;width:100%;max-width:380px;text-align:center}
.logo{font-size:40px;margin-bottom:16px}h1{font-size:22px;font-weight:700;margin-bottom:4px}.sub{font-size:13px;color:#6b7280;margin-bottom:28px}
input{width:100%;background:#12151f;border:1px solid #252840;border-radius:8px;padding:12px 14px;color:#e8eaf0;font-size:14px;outline:none;margin-bottom:12px}
input:focus{border-color:#f5a623}button{width:100%;background:#f5a623;color:#000;border:none;border-radius:8px;padding:12px;font-size:14px;font-weight:700;cursor:pointer}
.error{color:#e05252;font-size:12px;margin-top:8px;min-height:16px}</style></head>
<body><div class="box"><div class="logo">🍍</div><h1>OpenClaw Command</h1><div class="sub">Peter Myers · Private Dashboard</div>
<form method="POST"><input type="password" name="password" placeholder="Enter password" autofocus><button type="submit">Access Dashboard</button></form>
<div class="error">${error}</div></div></body></html>`;
}
