# Feed Item Format

Feed items are YAML files stored in `content/feed-items/`. Each file represents one public brief.

The static generator reads these files to produce `feed.html`, individual item pages under `items/`, and `rss.xml`.

## Schema

```yaml
id: unique-slug-matching-filename
slug: unique-slug-matching-filename
date: "YYYY-MM-DD"
type: KEV                         # see Type values below
signal: Known exploited           # see Signal values below
title: "Brief title"
summary: >
  One to three sentence summary of what happened and why it matters at a glance.
vendor: Vendor name
product: Product name or line
cve: CVE-YYYY-NNNNN               # null if no CVE
operator_check: >
  What an operator should do or check. One to three sentences.
why_it_matters: >
  Explains the signal — why this is worth reviewing. Focus on what makes it
  actionable: exploitation status, affected product class, severity, CISA signals.
sources:
  - title: Source display name
    url: https://example.com/advisory
tags:
  - tag-one
  - tag-two
is_sample: true   # set to false for real published items
```

## Field reference

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique identifier, matches filename without extension. Use kebab-case. |
| `slug` | yes | URL slug for the generated item page. Must match `id`. |
| `date` | yes | ISO date string (`"YYYY-MM-DD"`). Quote it to prevent YAML date parsing. |
| `type` | yes | Content category. See Type values. |
| `signal` | yes | Threat signal label shown on the feed and item pages. See Signal values. |
| `title` | yes | Brief title. Keep under 100 characters. |
| `summary` | yes | One to three sentences. Shown in the feed list. |
| `vendor` | yes | Vendor or organization name. |
| `product` | yes | Affected product, service, or feature. |
| `cve` | no | CVE ID if applicable. Set to `null` if no CVE. |
| `operator_check` | yes | What an operator should do or verify. Practical, not alarming. |
| `why_it_matters` | yes | Explanation of the signal. Why this brief was written. |
| `sources` | yes | List of source objects with `title` and `url`. At least one required. |
| `tags` | no | List of lowercase kebab-case tag strings. Used for filtering. |
| `is_sample` | yes | `true` for preview/example items. `false` for real published items. |

## Type values

| Value | Use for |
|---|---|
| `KEV` | CISA Known Exploited Vulnerabilities catalog additions |
| `Vendor advisory` | Vendor-published security advisories |
| `Patch Tuesday` | Microsoft Patch Tuesday releases |
| `Ransomware` | Ransomware group activity reports |
| `Exploit activity` | Active exploitation reports without a KEV addition |

## Signal values

| Value | Meaning |
|---|---|
| `Known exploited` | CISA KEV addition or confirmed active exploitation |
| `Critical vendor advisory` | Vendor-rated critical or CVSS ≥ 9.0 |
| `Patch review` | Important patch or update that warrants review |
| `Threat activity` | Threat actor or campaign activity without a specific CVE |

## Naming convention

File names should follow: `YYYY-MM-{vendor-product-brief-slug}.yml`

Examples:
- `2024-04-paloalto-globalprotect-kev.yml`
- `2024-06-microsoft-patch-tuesday-msmq.yml`
- `2024-08-chrome-zero-day-kev.yml`

## Boundaries

PatchBrief uses public sources. Feed items:
- Must link to a public source for every claim
- Must not claim to verify exposure or scan environments
- Must not replace vendor guidance
- Should use measured language: "operators may want to check" rather than "you must act now"
