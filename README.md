# PatchBrief

## What is PatchBrief?

PatchBrief is a source-backed security intelligence feed for operators.

It tracks known exploited vulnerabilities, critical CVEs, GitHub-reviewed open-source
advisories, EPSS exploitation-likelihood signals, and selected public threat activity,
then turns them into short briefs built for patch triage.

## Product model

| Layer | Status |
|---|---|
| **Public feed** | Active production feed |
| **RSS** | Active |
| **JSON feed** | Active with source metadata |
| **Multi-source ingest** | CISA KEV, NVD, GitHub Security Advisories, FIRST EPSS |
| **Newsletter interest list** | Active via FormSubmit |
| **Monetization** | Active — checkout funnel, paid watchlist onboarding, Stripe link config |

## Boundaries

- Public sources only
- No scanning or agent installation
- No exposure verification
- No remediation advice
- Not a replacement for vendor guidance

PatchBrief is a signal layer. It points to public sources and suggests checks.
Operators and their teams make the calls.

## Current site

Static GitHub Pages site at `https://www.patchbrief.org`

| Page | Purpose |
|---|---|
| `index.html` | Homepage: public feed intro and newsletter signup |
| `feed.html` | Public security intel feed |
| `pricing.html` | Free / Pro / Team pricing and plan comparison |
| `checkout.html` | Static paid checkout handoff with Stripe-link and invoice-request fallback |
| `onboarding.html` | Paid subscriber onboarding for watchlists, delivery, and integrations |
| `items/` | Individual brief pages |

## Content model

Feed items are YAML files in `content/feed-items/`. The static generator reads them
and produces `feed.html`, `items/{slug}.html`, `rss.xml`, `feed.json`, and `sitemap.xml`.

See [docs/feed-item-format.md](docs/feed-item-format.md) for the full field reference.

## Local development

### Run the static feed generator

```bash
pip install -r requirements.txt
python -m patchbrief.cli build-feed
```

This reads `content/feed-items/*.yml` and generates:
- `feed.html`
- `items/{slug}.html` for each item
- `rss.xml`
- `feed.json`
- `sitemap.xml`

### Validate the feed

```bash
python -m patchbrief.cli validate
```

This checks feed content, duplicate IDs/slugs, and source-health metadata.

### Run the live ingestion pipeline

```bash
python -m patchbrief.cli ingest \
  --days 3 \
  --sources cisa_kev,nvd,github_advisory
```

By default, ingest fetches CISA KEV, NVD critical CVEs, GitHub Security Advisories,
and enriches CVE-backed items with FIRST EPSS scores. The command writes source-health
metadata to `content/source-status.json`, which is then included in `feed.json`.

Optional flags:

```bash
python -m patchbrief.cli build-feed \
  --content-dir content/feed-items \
  --base-url https://www.patchbrief.org \
  --public-window-days 365
```

`build-feed` keeps item pages for the full content corpus, but the public feed,
RSS, JSON, and sitemap default to a 365-day live window. Use
`--public-window-days 0` for a full archive build.

## Triggering the build workflow

The GitHub Actions workflow at `.github/workflows/build-feed.yml` runs automatically on
push to `main` when files under `content/feed-items/`, `templates/`, or `patchbrief/` change.

To trigger it manually:

1. Go to **Actions** in the GitHub repo
2. Select **Build feed**
3. Click **Run workflow**

Generated files (`feed.html`, `rss.xml`, `items/`) are uploaded as a build artifact.

## Roadmap

Short version:

- [x] Static site and public feed
- [x] Structured feed content format
- [x] Static feed generator
- [x] RSS generation
- [x] Multi-source live ingestion
- [x] Source-health metadata in `feed.json`
- [ ] Newsletter publishing workflow
- [x] Monetization funnel
- [ ] Fully automated paid subscriber fulfillment

## Docs

- [docs/next-steps-setup.md](docs/next-steps-setup.md) — **Setup checklist** — what to do before the site is live (start here)
- [docs/feed-item-format.md](docs/feed-item-format.md) — Feed item YAML schema and field reference
- [docs/source-ingestion-plan.md](docs/source-ingestion-plan.md) — Source priority and ingestion order
- [docs/pilot-metrics.md](docs/pilot-metrics.md) — Pilot goal table and weekly health check signals
