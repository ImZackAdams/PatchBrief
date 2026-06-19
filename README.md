# PatchBrief

## What is PatchBrief?

PatchBrief is a public security intelligence feed for operators.

It tracks public vulnerability advisories, known exploited vulnerabilities, vendor security updates,
and high-signal threat activity, then turns them into short source-backed briefs.

## Product model

| Layer | Status |
|---|---|
| **Public feed** | Active MVP |
| **RSS** | Active |
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

Optional flags:

```bash
python -m patchbrief.cli build-feed \
  --content-dir content/feed-items \
  --base-url https://www.patchbrief.org
```

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
- [ ] Newsletter publishing workflow
- [x] Monetization funnel
- [ ] Fully automated paid subscriber fulfillment

## Docs

- [docs/feed-item-format.md](docs/feed-item-format.md) — Feed item YAML schema and field reference
