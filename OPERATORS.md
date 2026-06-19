# PatchBrief — Operator's Manual

This document covers everything needed to run, maintain, and extend the PatchBrief security intelligence feed.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Local Setup](#local-setup)
3. [Daily Operations](#daily-operations)
4. [CLI Reference](#cli-reference)
5. [GitHub Actions Automation](#github-actions-automation)
6. [Secret Configuration](#secret-configuration)
7. [Writing Feed Items by Hand](#writing-feed-items-by-hand)
8. [Feed Item Field Reference](#feed-item-field-reference)
9. [Monetization Setup](#monetization-setup)
10. [Troubleshooting](#troubleshooting)

---

## How It Works

PatchBrief is a static site generator. There is no server, no database, and no runtime. The full pipeline is:

```
Data sources                   Generator                     Output
──────────────                 ─────────────                 ──────
CISA KEV feed    ─┐
NVD CVE API      ─┤  →  ingest  →  content/feed-items/*.yml  →  build-feed  →  feed.html
Hand-written YAML ┘                                                             items/*.html
                                                                                rss.xml
```

**Ingest** fetches live vulnerability data, generates a brief for each new entry, and saves it as a YAML file in `content/feed-items/`. `content/processed-state.json` tracks which CVE IDs have already been processed so nothing gets duplicated.

**Build** reads all YAML files in `content/feed-items/`, renders them into HTML and RSS, and writes the output files. The output files are what GitHub Pages serves as the live site.

The whole thing runs automatically in GitHub Actions on a daily cron schedule. You can also run any step locally at any time.

---

## Local Setup

**Requirements:** Python 3.11+

```bash
# Clone and install dependencies
git clone https://github.com/ImZackAdams/PatchBrief.git
cd PatchBrief
pip install -r requirements.txt

# Verify it works
python -m patchbrief.cli --help
python -m pytest tests/ -v
```

**Optional environment variables:**

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # enables AI-written briefs
export NVD_API_KEY="..."                # higher NVD rate limits (free from nvd.nist.gov)
```

---

## Daily Operations

### Refresh the feed with real data (no API key needed)

This fetches from CISA KEV and NVD and writes briefs directly from their source text — no AI call required.

```bash
python -m patchbrief.cli ingest --no-ai --days 7
python -m patchbrief.cli build-feed
```

### Refresh with AI-enhanced briefs

With `ANTHROPIC_API_KEY` set, ingest calls Claude to write cleaner summaries, operator checks, and context explanations.

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python -m patchbrief.cli ingest --days 7
python -m patchbrief.cli build-feed
```

### Catch up after a gap

If the automated job has been offline for a while, run a wider look-back window:

```bash
python -m patchbrief.cli ingest --no-ai --days 30
python -m patchbrief.cli build-feed
```

### KEV-only run (faster, no rate-limit concerns)

```bash
python -m patchbrief.cli ingest --no-ai --kev-only --days 7
python -m patchbrief.cli build-feed
```

### Rebuild from existing YAML without fetching anything new

```bash
python -m patchbrief.cli build-feed
```

This is safe to run at any time. It only reads existing YAML files — it does not call any external APIs.

### Add a single hand-written item and rebuild

```bash
# Write your YAML file (see format below)
nano content/feed-items/2026-06-my-new-item.yml

# Rebuild
python -m patchbrief.cli build-feed
```

---

## CLI Reference

### `ingest`

Fetches new vulnerabilities from CISA KEV and NVD, generates a brief for each one, and writes a YAML file to `content/feed-items/`. Skips any CVE already in `content/processed-state.json`.

```
python -m patchbrief.cli ingest [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--days N` | 30 | Look back N days for new entries. Use 3–7 for daily runs, 30–90 for catch-up. |
| `--kev-only` | off | Only fetch from CISA KEV. Skips NVD entirely. Faster, no rate limits. |
| `--no-ai` | off | Build briefs from raw source fields instead of calling Claude. No API key needed. |
| `--max-nvd N` | 20 | Maximum NVD results to process per run. |
| `--api-key KEY` | env | Anthropic API key. Defaults to `ANTHROPIC_API_KEY` env var. |
| `--nvd-api-key KEY` | env | NVD API key. Defaults to `NVD_API_KEY` env var. Without one, NVD adds a 6-second delay per request. |
| `--content-dir PATH` | `content/feed-items` | Where to write generated YAML files. |
| `--state-file PATH` | `content/processed-state.json` | JSON file that tracks processed CVE IDs. |

**Behaviour when no API key is set:** if `ANTHROPIC_API_KEY` is not set and `--no-ai` is not passed, ingest automatically falls back to `--no-ai` mode with a warning. It will not crash.

---

### `build-feed`

Reads all YAML files in `content/feed-items/`, renders them into HTML and RSS, and writes the output files to the project root.

```
python -m patchbrief.cli build-feed [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--content-dir PATH` | `content/feed-items` | Directory of YAML source files. |
| `--base-url URL` | `https://www.patchbrief.org` | Base URL used in RSS `<link>` elements. |

**Output files written:**
- `feed.html` — the main feed page
- `items/{slug}.html` — one page per brief
- `rss.xml` — RSS feed

---

## GitHub Actions Automation

The workflow at `.github/workflows/build-feed.yml` runs automatically. You do not need to trigger it manually for normal operation.

### When it runs

| Trigger | What happens |
|---|---|
| **Daily at 09:00 UTC** | Runs `ingest --days 3` then `build-feed`. Commits any new files. |
| **Push to `main`** touching `content/`, `templates/`, or `patchbrief/` | Runs `build-feed` only (no ingest). Good for publishing hand-written items. |
| **Manual dispatch** (Actions tab → Run workflow) | Lets you set `days` and `kev_only` before triggering. |

### Manual trigger (GitHub UI)

1. Go to your repo on GitHub
2. Click **Actions** → **Build feed**
3. Click **Run workflow**
4. Set the `days` input (e.g. `30` to catch up a month)
5. Optionally check **Only ingest CISA KEV**
6. Click **Run workflow**

The run will ingest, build, and commit. Check the Actions log to see what was created.

---

## Secret Configuration

The daily automated ingest needs `ANTHROPIC_API_KEY` to write AI-enhanced briefs. Without it, the job falls back to raw-template mode (still accurate, less polished).

### Setting secrets in GitHub

1. Go to your repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add:

| Name | Value | Required? |
|---|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key (`sk-ant-...`) | Recommended |
| `NVD_API_KEY` | Your NVD API key (free from nvd.nist.gov) | Optional |

Without `ANTHROPIC_API_KEY`, ingest still runs in raw mode. Without `NVD_API_KEY`, NVD fetching works but adds a 6-second delay and is limited to 5 requests per 30 seconds.

### Getting an NVD API key

Register free at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key). Approval is instant.

---

## Writing Feed Items by Hand

Hand-written items are useful for:
- Notable events that the automated sources don't capture (ransomware campaigns, threat actor activity, Patch Tuesday summaries)
- Correcting or enriching an auto-generated brief
- Back-filling historical items

Create a YAML file in `content/feed-items/` following the naming convention `YYYY-MM-{vendor-slug}.yml`, then run `build-feed`.

### Minimal example

```yaml
id: 2026-06-fortinet-fortigate-cve-2026-12345
slug: 2026-06-fortinet-fortigate-cve-2026-12345
date: "2026-06-15"
type: KEV
signal: Known exploited
title: "CISA KEV: Fortinet FortiGate authentication bypass actively exploited"
summary: >
  CVE-2026-12345 is an authentication bypass in Fortinet FortiGate SSL-VPN.
  Unauthenticated attackers can gain administrative access to the management
  interface. CISA added it to the KEV catalog on June 15, 2026.
vendor: Fortinet
product: FortiGate SSL-VPN
cve: CVE-2026-12345
operator_check: >
  Confirm whether FortiGate management interfaces are internet-exposed.
  Apply Fortinet advisory FG-IR-26-XXX immediately. If patching is not possible
  within the CISA deadline, disable SSL-VPN or restrict management access by IP.
why_it_matters: >
  Active exploitation means real attackers are using this today. FortiGate
  devices are common enterprise perimeter assets with high-value network access.
sources:
  - title: CISA KEV catalog
    url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - title: Fortinet PSIRT advisory
    url: https://www.fortiguard.com/psirt/FG-IR-26-XXX
tags:
  - fortinet
  - fortigate
  - kev
  - ssl-vpn
is_sample: false
```

After saving, run:

```bash
python -m patchbrief.cli build-feed
```

The item appears on the feed immediately. Push to `main` to publish it to the live site.

### Marking the item in the processed-state

If your hand-written item has a `cve:` field, it is automatically added to `content/processed-state.json` the next time `ingest` bootstraps (which happens at the start of every ingest run). This prevents a duplicate auto-generated brief from being created later.

---

## Feed Item Field Reference

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Unique. Must match the filename without `.yml`. Use kebab-case. |
| `slug` | yes | Must equal `id`. Controls the URL: `items/{slug}.html`. |
| `date` | yes | ISO format: `"2026-06-15"`. Quote it — YAML will misparse bare dates. |
| `type` | yes | One of the type values below. |
| `signal` | yes | One of the signal values below. |
| `title` | yes | Under 100 characters. Shown as the headline on the feed card. |
| `summary` | yes | 2–3 sentences. Shown in the feed list. |
| `vendor` | yes | Vendor or project name (e.g. `Microsoft`, `Fortinet`, `Apache`). |
| `product` | yes | Specific product or component (e.g. `Windows Server`, `FortiGate`). |
| `cve` | no | CVE ID if applicable (`CVE-2026-12345`). Omit or set `null` if none. |
| `operator_check` | yes | What to verify or do. Practical, not alarming. |
| `why_it_matters` | yes | Why this signal is worth acting on. Context, not repetition of summary. |
| `sources` | yes | List with at least one entry. Each entry needs `title` and `url`. |
| `tags` | no | Lowercase kebab-case strings. Used by the search bar. |
| `is_sample` | yes | `false` for real items. `true` marks a preview/example. |

### Type values

| Value | When to use |
|---|---|
| `KEV` | CVE is in the CISA Known Exploited Vulnerabilities catalog |
| `Vendor advisory` | Vendor-published security advisory without a KEV listing |
| `Patch Tuesday` | Microsoft monthly patch release summary |
| `Ransomware` | Ransomware campaign or group activity |
| `Exploit activity` | Active exploitation confirmed, but no KEV listing yet |

### Signal values

| Value | When to use | Badge colour |
|---|---|---|
| `Known exploited` | Confirmed active exploitation (KEV or credible reports) | Green |
| `Critical vendor advisory` | Vendor-rated Critical or CVSS ≥ 9.0 | Red |
| `Patch review` | Significant patch warranting review (not yet exploited) | Amber |
| `Threat activity` | Threat actor or campaign activity, no specific CVE | Purple |

---

## Troubleshooting

### `ingest` creates nothing new

The processed state file already contains those CVE IDs. This is expected — it prevents duplicates. To check what's tracked:

```bash
python3 -c "import json; d=json.load(open('content/processed-state.json')); print(len(d['processed']), 'CVEs tracked')"
```

To force re-processing a specific CVE, remove its ID from `content/processed-state.json` and delete the corresponding YAML file, then re-run ingest.

### NVD fetch is very slow

NVD allows 5 requests per 30 seconds without an API key. The fetcher adds a 6-second delay automatically. Register for a free NVD API key (see [Secret Configuration](#secret-configuration)) to remove the delay.

### GitHub Actions commit step shows "No changes to commit"

The ingest ran but found no new items within the look-back window. This is normal if there are no new KEV additions or NVD critical CVEs since the last run.

### A generated brief has inaccurate vendor/product fields

NVD's CPE data is sometimes missing or generic. Edit the YAML file directly:

```bash
nano content/feed-items/YYYY-MM-vendor-cve-id.yml
# Fix vendor: and product: fields
python -m patchbrief.cli build-feed
```

### Build fails with "Missing required fields"

A YAML file is invalid. The error message names the file and the missing field. Fix the YAML, then re-run `build-feed`. Run the test suite to catch errors before building:

```bash
python -m pytest tests/ -v
```

### The live site is behind the local build

The live site at patchbrief.org is served from the `feed.html`, `items/`, and `rss.xml` files committed in the `main` branch. Push your local changes:

```bash
git add feed.html rss.xml items/ content/
git commit -m "update feed"
git push
```

GitHub Pages picks up changes within a few minutes.

---

## Monetization Setup

PatchBrief uses a three-tier model: Free (public feed), Pro ($9/month), Team ($49/month). The public feed is already live. This section explains what you need to do to start accepting payment and fulfilling subscriptions.

### Revenue model overview

| Tier | Price | Product | Fulfillment |
|---|---|---|---|
| Free | $0 | Public feed, RSS, `feed.json` | Nothing — it's already live |
| Pro | $9/mo or $79/yr | Daily digest email, vendor watchlist alerts | Stripe + email platform |
| Team | $49/mo or $399/yr | API access, 5 seats, CSV export, priority support | Stripe + email platform |

---

### Step 1 — Set up Stripe Payment Links

Stripe Payment Links let you accept cards with no code and no backend. Create them at [dashboard.stripe.com/payment-links](https://dashboard.stripe.com/payment-links).

Create four links (monthly + yearly for each paid tier) and set the product name, price, and billing cycle. Once created, each link is a URL like `https://buy.stripe.com/abc123`.

Then configure the static checkout page in `checkout-config.js`:

```js
window.PATCHBRIEF_CHECKOUT_LINKS = {
  pro: {
    monthly: "https://buy.stripe.com/YOUR_PRO_MONTHLY",
    yearly: "https://buy.stripe.com/YOUR_PRO_YEARLY"
  },
  team: {
    monthly: "https://buy.stripe.com/YOUR_TEAM_MONTHLY",
    yearly: "https://buy.stripe.com/YOUR_TEAM_YEARLY"
  }
};
```

The checkout page works even before these are set: it captures a paid checkout/invoice request through FormSubmit so high-intent buyers are not lost.

For generated surfaces (`feed.html`, `items/*.html`, and `digest-latest.html`), add the same links as GitHub Actions secrets:

| Secret | Purpose |
|---|---|
| `PATCHBRIEF_STRIPE_PRO_MONTHLY_URL` | Pro monthly checkout |
| `PATCHBRIEF_STRIPE_PRO_YEARLY_URL` | Pro yearly checkout |
| `PATCHBRIEF_STRIPE_TEAM_MONTHLY_URL` | Team monthly checkout |
| `PATCHBRIEF_STRIPE_TEAM_YEARLY_URL` | Team yearly checkout |

Set the Stripe Payment Link success URL to `https://www.patchbrief.org/onboarding.html` so paid subscribers can submit watchlist and delivery details immediately after purchase.

After configuring links, rebuild and push:

```bash
python -m patchbrief.cli build-feed
git add checkout-config.js feed.html items/ feed.json rss.xml digest-latest.html
git commit -m "add Stripe payment links"
git push
```

---

### Step 2 — Choose an email platform

The `digest` command generates a self-contained HTML email file (`digest-latest.html`). You paste or import that into your email platform to send it.

**Recommended platforms (all have free tiers):**

| Platform | Free tier | Why use it |
|---|---|---|
| [Beehiiv](https://beehiiv.com) | 2,500 subscribers | Built-in paid newsletter tiers, no transaction fee |
| [Mailchimp](https://mailchimp.com) | 500 subscribers | Familiar, good automation |
| [ConvertKit](https://convertkit.com) | 1,000 subscribers | Strong for segmentation (free vs. paid subscribers) |
| [Resend](https://resend.com) | 3,000/mo free | Developer-friendly API, great for automation |

**Beehiiv is the best fit** because it has a native paid subscription tier — subscribers can pay directly through Beehiiv, which eliminates the need for Stripe until you outgrow it.

---

### Step 3 — Send the weekly digest

The weekly digest is generated automatically every Monday at 10:00 UTC by GitHub Actions and saved as `digest-latest.html` in the repo root.

**To send it:**

1. Open `digest-latest.html` in a browser to preview it
2. Copy the HTML source
3. In your email platform, create a new campaign → paste HTML
4. Send to your free subscriber list

**To generate it manually:**

```bash
python -m patchbrief.cli digest --days 7 --issue 12 --output digest-latest.html
```

Increment `--issue` by 1 each week. GitHub Actions auto-calculates the issue number from weeks since launch.

---

### Step 4 — Fulfill Pro subscribers (vendor watchlists)

When someone upgrades to Pro via Stripe:

1. **Stripe sends you an email** when a payment succeeds. You can also set up a Stripe webhook to notify a Slack channel or email alias.
2. **Add them to a "Pro" segment** in your email platform.
3. **Switch their digest frequency to daily.** Run `digest --days 1 --label Daily` each morning in the GitHub Actions schedule (the daily run already does this via cron at 09:00 UTC).
4. **Set up watchlist filtering.** Ask the subscriber which vendors they want to track (the `watchlist.html` form collects this). Then in your email platform, create an automation that sends them a one-off email whenever a new item for that vendor is published.

For now, watchlist fulfillment is manual. As volume grows, the right automation depends on your email platform — Beehiiv and ConvertKit both support tag-based automations that can trigger on new subscriber tags.

---

### Step 5 — JSON API access for Team subscribers

The JSON API feed is at `https://www.patchbrief.org/feed.json`. It is publicly accessible now — no auth. The Team plan sells:
- **Priority access** (the public feed has no SLA; Team subscribers get a direct contact)
- **Structured integration help** (setting up SIEM/Slack/ticketing connectors)
- **Full history** (the public JSON is always the current build; Team subscribers get access to archived builds)

To add basic auth in future, the simplest approach is to move the feed to Cloudflare Pages with a Cloudflare Access rule, or to a private GitHub Pages repo. Document that as a follow-on when you have your first paying Team subscriber.

---

### Step 6 — Track revenue and growth

**Key numbers to watch weekly:**

- Stripe dashboard: MRR, new subscribers, churn
- Email platform: subscriber count, open rate, click rate on the upgrade CTA
- GitHub Actions logs: confirm daily ingest ran and committed new items
- `feed.json` → `total_items`: confirm the feed is growing

**Upgrade funnel:**

```
Visitor → reads feed.html → sees in-feed Pro card (item 11) → pricing.html → Stripe
Visitor → reads feed.html → subscribes to free digest → receives upgrade CTA in email → Stripe
Visitor → fills out watchlist.html → told watchlist requires Pro → Stripe
```

---

### Step 7 — Keep the checkout fallback healthy

Paid CTAs route to `checkout.html` unless a generated page receives Stripe URLs from environment secrets. Keep the FormSubmit route active because it handles:

- invoice or purchase-order requests
- buyers who prefer manual checkout
- payment-link outages or missing Stripe configuration
- Team prospects who need integration scoping before purchase

---

### Resetting the processed state (start fresh)

**Do this only if you want to regenerate everything from scratch.**

```bash
echo '{"processed": []}' > content/processed-state.json
# Remove all auto-generated items (keep any hand-written ones you want to keep)
rm content/feed-items/YYYY-MM-*.yml   # adjust the pattern as needed
python -m patchbrief.cli ingest --no-ai --days 90
python -m patchbrief.cli build-feed
```
