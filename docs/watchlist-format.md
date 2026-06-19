# Watchlist Format

Watchlists are YAML files that define what PatchBrief monitors.

## Schema

```yaml
name: My Watchlist
owner_email: you@example.com
cadence: weekly
terms:
  - Microsoft
  - Chrome
  - Fortinet
```

## Fields

- `name` — Human-readable watchlist name.
- `owner_email` — Email address for brief delivery. Required.
- `cadence` — How often to receive briefs. One of: `important_only`, `weekly`, `monthly`.
  - `important_only`: Briefs sent only when P1 (known exploited) or P2 (critical) matches occur.
  - `weekly`: All matches included in a weekly brief.
  - `monthly`: All matches included in a monthly brief.
- `terms` — List of vendors, products, or technologies to monitor. 1–10 items. Each term must be 60 characters or fewer.

## Guidelines

- Keep terms short and specific (e.g. "Microsoft", "Chrome", "Fortinet FortiOS").
- Do not use internal hostnames or IP addresses.
- Do not include sensitive internal asset names.
- Do not commit real customer watchlists to this repo.

## Customer data

Real customer watchlists belong in `watchlists/customer/` (gitignored). Use `watchlists/sample-watchlist.yml` as a reference format.
