# PatchBrief

## Product

PatchBrief is a lightweight vulnerability watchlist monitoring service for small IT teams, consultants, and MSPs.

Users create a watchlist of vendors, products, or technologies they care about. PatchBrief watches public advisory sources and sends short source-backed briefs when something deserves review.

## Current state

- Static GitHub Pages landing page
- Pilot signup form using FormSubmit
- No backend yet
- No payment yet
- No scanner
- No exposure verification

## Product thesis

Users do not need another dashboard. They need to know when public vulnerability advisories matter to the vendors, products, or technologies they care about.

## Pilot workflow

1. User creates a watchlist
2. PatchBrief receives the watchlist
3. PatchBrief generates sample briefs manually or semi-automatically
4. User gives feedback on relevance, format, and cadence

## Planned monetization

- Free pilot
- Planned individual watchlist tier around $9/mo
- Planned team/MSP tier around $29–$99/mo
- One-off reports are not the primary business model

## Boundaries

- Public sources only
- No scanning
- No exposure verification
- No remediation
- Not a replacement for vendor guidance

## Development roadmap

- [x] Static repositioning
- [x] Sample brief
- [x] Local brief generator (CLI)
- [x] CISA KEV ingestion
- [x] Watchlist matching
- [ ] Email brief generation
- [ ] Saved watchlists
- [ ] Payment/subscription

## Local development

```bash
pip install -r requirements.txt
python -m patchbrief.cli generate-brief --watchlist watchlists/sample-watchlist.yml --out reports/sample-brief.html
```

See [examples/README.md](examples/README.md) for more commands.
