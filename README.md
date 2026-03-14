# 🍍 PineappleDash — OpenClaw Command Dashboard

Private command dashboard for Peter Myers / Pineapple Tours Group.

## Stack
- **Runtime:** Cloudflare Workers (Edge)
- **Auth:** Cloudflare Access (Zero Trust) + JWT validation
- **Domain:** `dashboard.pineappletours.com.au`
- **Deploy:** Wrangler v3 / GitHub Actions

## GitHub Secrets Required
| Secret | Value |
|--------|-------|
| `CF_API_TOKEN` | Cloudflare API token (Workers:Edit) |
| `CF_ACCOUNT_ID` | Your Cloudflare account ID |
