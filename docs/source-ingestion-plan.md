# Source Ingestion Plan

PatchBrief prioritizes public sources that are useful to operators and stable enough to run unattended in GitHub Actions.

## Active sources

| Source | Connector | Role | Default |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | `cisa_kev` | Confirmed exploitation and remediation deadlines | On |
| Microsoft Security Update Guide | `msrc` | Patch Tuesday and Microsoft high-signal CVEs | On |
| NVD CVE API | `nvd` | Newly published critical CVEs | On |
| GitHub Security Advisories | `github_advisory` | Reviewed open-source package advisories | On |
| CERT/CC Vulnerability Notes | `cert_vu` | Coordinated disclosures and multi-vendor notes | On |
| Exploit-DB | `exploitdb` | Verified public exploit entries | On |
| FIRST EPSS | `epss` | CVE exploitation-likelihood enrichment | On |

## Source priority

When two sources describe the same CVE, PatchBrief keeps one item using this priority:

1. `cisa_kev` because known exploitation is the strongest operator signal.
2. `msrc` because Microsoft Patch Tuesday signals drive urgent enterprise patch cycles.
3. `github_advisory` because package-level advisory data can be more actionable for application teams.
4. `nvd` because it provides broad CVE coverage and severity metadata.
5. `cert_vu` because coordinated disclosures often add context but may overlap with CVE sources.
6. `exploitdb` because public exploit availability is valuable but should not override authoritative vulnerability records.

EPSS does not create feed items. It enriches CVE-backed records with probability and percentile.

## Run commands

```bash
python -m patchbrief.cli ingest --days 3
python -m patchbrief.cli validate
python -m patchbrief.cli build-feed
```

To temporarily limit sources:

```bash
python -m patchbrief.cli ingest --sources cisa_kev,nvd --days 3
python -m patchbrief.cli ingest --kev-only --days 7
python -m patchbrief.cli ingest --no-epss --days 3
```

## Source health

Each ingest writes `content/source-status.json` with source IDs, item counts, status, and timestamps. `build-feed` embeds those records into `feed.json` under `pipeline.sources`.

Operators should check this file if the feed stops growing or a scheduled workflow succeeds without new items.

## Add-source criteria

Add a new source only when it meets all of these:

- Public, source-backed, and lawful to fetch.
- Stable API, RSS, JSON, or machine-readable format.
- Clear timestamp field for incremental ingest.
- Clear upstream URL for every generated item.
- Adds signal not already covered by the active source mix.

## Candidate future sources

| Source | Why it might matter | Notes |
|---|---|---|
| Vendor PSIRT feeds | Faster vendor-specific context | Start with vendors that buyers watch most. |
| CISA advisories/RSS | Campaign and product-specific advisories | Add after confirming stable machine-readable feed URLs. |
| AttackerKB or exploit-intel APIs | Exploitability context | Only if licensing and source attribution are clean. |
| Ransomware campaign feeds | Ransomware-specific coverage | Add only after confirming reliable JSON/RSS access and clean attribution. |
