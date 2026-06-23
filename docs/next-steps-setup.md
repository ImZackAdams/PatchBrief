# Next Steps — Setup Checklist

Paused: 2026-06-19. Resume from here.

---

## Current state

- Local build works: `python -m patchbrief.cli build-feed` -> 104 total content items, 96 current public feed items, feed.html, rss.xml, sitemap.xml, feed.json
- Four CLI commands fully functional: `build-feed`, `ingest`, `digest`, `validate`
- GitHub Actions workflow exists and is configured for tests, validation, daily ingest, weekly digest, and auto-commit
- Full site structure complete: index, feed, items, pricing, checkout, watchlist, onboarding
- Multi-source pipeline wired: CISA KEV, NVD, GitHub Security Advisories, and FIRST EPSS enrichment
- Stripe monetization module wired in — all "Get Pro" buttons link to `checkout.html` as fallback until real Stripe links are configured
- Currently on branch `experiment` — workflow triggers on push to `main`

---

## Setup tasks (in recommended order)

### 1. Push to GitHub and enable GitHub Actions

The workflow won't run until the code is on `main`.

```bash
git checkout main
git merge experiment      # or open a PR from experiment → main
git push origin main
```

Then go to **github.com/ImZackAdams/PatchBrief → Actions** and confirm the workflow shows up.
Manually trigger it once with `workflow_dispatch` to confirm it runs.

---

### 2. Add GitHub Secrets

Go to: **github.com/ImZackAdams/PatchBrief → Settings → Secrets and variables → Actions → New repository secret**

Add these in order:

| Secret name | Value | Required |
|---|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key (`sk-ant-...`) | Recommended — cleaner AI-written briefs |
| `NVD_API_KEY` | NVD API key from nvd.nist.gov/developers/request-an-api-key | Optional — raises NVD rate limit from 5 to 50 req/30s |
| `GITHUB_TOKEN` | Built in during GitHub Actions; optional locally | Optional — raises GitHub Advisory API rate limits |
| `PATCHBRIEF_STRIPE_PRO_MONTHLY_URL` | Stripe payment link (step 3) | Optional until you launch Stripe |
| `PATCHBRIEF_STRIPE_PRO_YEARLY_URL` | Stripe payment link (step 3) | Optional until you launch Stripe |
| `PATCHBRIEF_STRIPE_TEAM_MONTHLY_URL` | Stripe payment link (step 3) | Optional until you launch Stripe |
| `PATCHBRIEF_STRIPE_TEAM_YEARLY_URL` | Stripe payment link (step 3) | Optional until you launch Stripe |

Without the Stripe secrets, all "Get Pro" buttons fall back to `checkout.html` — this is fine for launch.

---

### 3. Create Stripe products and payment links

Do this when you're ready to accept payment. Can skip for the initial public launch.

1. Go to **dashboard.stripe.com → Product catalog → Add product**
2. Create 4 products/prices:

| Product | Price | Billing |
|---|---|---|
| PatchBrief Pro | $9.00 | Monthly recurring |
| PatchBrief Pro | $79.00 | Yearly recurring |
| PatchBrief Team | $49.00 | Monthly recurring |
| PatchBrief Team | $399.00 | Yearly recurring |

3. For each price: **Payment links → Create payment link** → copy the URL
4. Add each URL as a GitHub Secret (see step 2 above)

After adding the secrets, re-run `build-feed` (or let the CI run). All "Get Pro" buttons will automatically use the real Stripe links instead of the checkout.html fallback.

---

### 4. Enable GitHub Pages

1. Go to **github.com/ImZackAdams/PatchBrief → Settings → Pages**
2. Source: **Deploy from a branch**
3. Branch: `main` / root
4. Save

GitHub Pages will be at `https://imzackadams.github.io/PatchBrief/` until DNS is wired.

---

### 5. Wire up DNS

The CNAME file is already set to `www.patchbrief.org`.

At your DNS registrar, create:

```
CNAME   www   ImZackAdams.github.io
```

For the apex domain (`patchbrief.org` without www), create A records pointing to GitHub Pages IPs:

```
A   @   185.199.108.153
A   @   185.199.109.153
A   @   185.199.110.153
A   @   185.199.111.153
```

Then in GitHub Pages settings, set **Custom domain** to `www.patchbrief.org` and enable **Enforce HTTPS**.

DNS propagation takes minutes to 24 hours.

---

### 6. Confirm FormSubmit email verification

The signup forms use FormSubmit (`formsubmit.co`). FormSubmit sends a verification email to `patchbrief@protonmail.com` on the first form submission.

- Open `patchbrief@protonmail.com`
- Submit the signup form once (from the live site or locally)
- Click the verification link FormSubmit sends
- After that, all form submissions will be forwarded normally

---

### 7. Register for NVD API key (optional but recommended)

Without an NVD key, the ingest pipeline is rate-limited to 5 requests per 30 seconds.
With a key, you get 50 requests per 30 seconds.

1. Go to: **nvd.nist.gov/developers/request-an-api-key**
2. Enter your email and request a key
3. Key arrives by email within a few minutes
4. Add as `NVD_API_KEY` GitHub Secret

---

### 8. Test the full pipeline locally before CI goes live

Run these in order to confirm everything works end-to-end:

```bash
# Set environment variables
export ANTHROPIC_API_KEY="sk-ant-..."
export NVD_API_KEY="..."          # optional
export GITHUB_TOKEN="..."         # optional locally; Actions provides one

# Safe test: all sources, no AI enrichment, 1-day window
python -m patchbrief.cli ingest --days 1 --no-ai --max-nvd 2 --max-github 2

# Full ingest with AI briefs (uses Anthropic API — costs tokens)
python -m patchbrief.cli ingest --days 3

# Validate content and source metadata
python -m patchbrief.cli validate

# Build the feed (needs no env vars if skipping Stripe for now)
python -m patchbrief.cli build-feed

# Generate a test digest
python -m patchbrief.cli digest \
  --days 7 \
  --max-items 5 \
  --issue 1 \
  --label "Weekly" \
  --output digest-latest.html

# Open feed.html in a browser to confirm it looks right
open feed.html    # or xdg-open feed.html on Linux
```

---

## What the daily CI does (once set up)

| Schedule | What runs |
|---|---|
| Every day at 09:00 UTC | tests → `validate` → `ingest --days 3` → `build-feed` → commits generated files |
| Every Monday at 10:00 UTC | `digest --days 7` → commits `digest-latest.html` |
| Push to main (content/feed-items/, templates/, patchbrief/) | tests, validation, and `build-feed` |
| Manual `workflow_dispatch` | configurable: sources, ingest, build, digest, or digest-only |

The workflow auto-commits with `git push`, so GitHub Pages re-deploys automatically after each run.

---

## What's not set up yet

| Item | Status |
|---|---|
| Email delivery for paid digest subscribers | Manual/import workflow until an email platform is connected |
| Watchlist filtering for paid users | Pilot is collect-only until paid subscriber volume justifies automation |
| Stripe webhook handling | Not needed yet — no subscriptions active |

---

## Files that need secrets to work fully

| File | Secret(s) needed | Fallback behavior without |
|---|---|---|
| `templates/feed.html.template` | `PATCHBRIEF_STRIPE_PRO_*_URL` | Links go to `checkout.html` instead |
| `templates/item.html.template` | `PATCHBRIEF_STRIPE_PRO_*_URL` | Links go to `checkout.html` instead |
| `patchbrief/cli.py` (`ingest`) | `ANTHROPIC_API_KEY` | Fails — required for AI brief writing |
| `patchbrief/cli.py` (`ingest`) | `NVD_API_KEY` | Works but rate-limited |
| `.github/workflows/build-feed.yml` | All of the above | Ingest step fails; build step works without Stripe |
