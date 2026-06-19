# PatchBrief

## What is PatchBrief?

PatchBrief is a public cyber intelligence feed and future watchlist filtering product for operators.

It tracks public vulnerability advisories, known exploited vulnerabilities, vendor security updates,
and high-signal threat activity, then turns them into short source-backed briefs.

## Product model

| Layer | Status |
|---|---|
| **Public feed** | Active — static, sample items during pilot |
| **RSS / newsletter** | Building — generator and delivery in progress |
| **Watchlist pilot** | Active — FormSubmit signup, manual matching |
| **Paid watchlist filtering** | Planned — shaped by pilot feedback |

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
| `index.html` | Homepage: public feed intro, newsletter signup, watchlist pilot form |
| `feed.html` | Public feed: sample security briefs |
| `items/` | Individual brief pages |
| `sample-brief.html` | Sample watchlist-filtered brief |
| `roadmap.html` | Product roadmap |

## Content model

Feed items are YAML files in `content/feed-items/`. The static generator reads them
and produces `feed.html`, `items/{slug}.html`, and `rss.xml`.

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

Optional flags:

```bash
python -m patchbrief.cli build-feed \
  --content-dir content/feed-items \
  --base-url https://www.patchbrief.org
```

### Run the watchlist brief generator

```bash
python -m patchbrief.cli generate-brief \
  --watchlist watchlists/sample-watchlist.yml \
  --out reports/sample-brief.html
```

### Ingest CISA KEV

```bash
python -m patchbrief.cli ingest-cisa-kev
```

Saves raw and normalized data to `data/`.

## Triggering the build workflow

The GitHub Actions workflow at `.github/workflows/build-feed.yml` runs automatically on
push to `main` when files under `content/feed-items/`, `templates/`, or `patchbrief/` change.

To trigger it manually:

1. Go to **Actions** in the GitHub repo
2. Select **Build feed**
3. Click **Run workflow**

Generated files (`feed.html`, `rss.xml`, `items/`) are uploaded as a build artifact.

## Roadmap

See [roadmap.html](roadmap.html) for the public-facing roadmap and [docs/source-ingestion-plan.md](docs/source-ingestion-plan.md)
for the planned ingestion implementation order.

Short version:

- [x] Static site and sample briefs
- [x] CISA KEV ingestion CLI
- [x] Watchlist matching CLI
- [x] Email brief delivery via Resend
- [x] Structured feed content format
- [x] Static feed generator
- [x] RSS generation
- [ ] Automated ingestion pipeline
- [ ] Saved watchlist delivery to pilot users
- [ ] Paid watchlist filtering tiers

## Docs

- [docs/feed-item-format.md](docs/feed-item-format.md) — Feed item YAML schema and field reference
- [docs/pilot-metrics.md](docs/pilot-metrics.md) — How to judge whether the pilot is working
- [docs/source-ingestion-plan.md](docs/source-ingestion-plan.md) — Planned ingestion sources and order
- [docs/watchlist-format.md](docs/watchlist-format.md) — Watchlist YAML schema
