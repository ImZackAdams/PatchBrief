# Examples

## Generate a placeholder brief

```bash
python -m patchbrief.cli generate-brief \
  --watchlist watchlists/sample-watchlist.yml \
  --out reports/sample-brief.html
```

Opens `reports/sample-brief.html` in your browser.

## Ingest CISA KEV

```bash
python -m patchbrief.cli ingest-cisa-kev
```

Fetches the current CISA Known Exploited Vulnerabilities catalog and saves to:
- `data/raw/cisa-kev.json`
- `data/normalized/cisa-kev.json`

Requires an internet connection.

## Generate a brief from CISA KEV data

```bash
python -m patchbrief.cli generate-brief \
  --watchlist watchlists/sample-watchlist.yml \
  --source data/normalized/cisa-kev.json \
  --out reports/cisa-brief.html
```

## Use a custom watchlist

Copy `watchlists/sample-watchlist.yml` and edit it:

```yaml
name: My Stack
owner_email: you@company.com
cadence: important_only
terms:
  - Microsoft
  - Cisco
  - VMware
```

Then run:

```bash
python -m patchbrief.cli generate-brief \
  --watchlist watchlists/my-watchlist.yml \
  --source data/normalized/cisa-kev.json \
  --out reports/my-brief.html
```
