# Pilot Metrics

Use this table for the first 30 days after launch.

## Weekly health check

| Metric | Target | Where to check |
|---|---:|---|
| Feed items published | 5+ per week | `feed.json.total_items` delta |
| Source freshness | All active sources `ok` | `feed.json.pipeline.sources` |
| Free subscribers | +10 per week | FormSubmit / email platform |
| Pricing visits | Baseline, then improve | Analytics |
| Checkout intent submissions | 1+ per week | FormSubmit |
| Pro conversions | First paid user | Stripe / checkout requests |
| Team conversations | 1 qualified lead | Checkout or email |

## Source reliability signals

Review after every scheduled workflow failure:

- Did `ingest` run?
- Did any source return `failed` in `content/source-status.json`?
- Did `validate` pass?
- Did `build-feed` commit generated files?
- Did GitHub Pages deploy the latest commit?

## Revenue funnel

Primary paths:

1. Search or direct visitor lands on a CVE brief.
2. Reader opens the feed or subscribes free.
3. In-feed and email CTAs push to Pro checkout.
4. Watchlist page captures vendor intent.
5. Team buyers request integration support or invoice flow.

## Product decisions

Use weekly metrics to decide what to build next:

| Signal | Build next |
|---|---|
| Many free subscribers, low paid intent | Improve digest value and upgrade CTA copy |
| Many watchlist forms | Automate vendor-matched alerts |
| Team checkout requests | Add private feed/auth and integration docs |
| Source failures | Harden connector or add fallback source |
| Search traffic to item pages | Improve item-page CTAs and related-item navigation |
