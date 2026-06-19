# Source Ingestion Plan

How PatchBrief plans to ingest public vulnerability and threat intelligence sources.

This document defines the sources, their value, expected data format, planned use, and risks.
The goal is to avoid ingesting everything at once and preserve the public feed MVP.

---

## Implementation order

1. **Manual feed items** (current) — hand-curated YAML, no ingestion required
2. **CISA KEV ingestion** (next) — structured JSON, high signal, already scaffolded
3. **NVD enrichment** — adds CVSS scores and descriptions to existing items
4. **MSRC enrichment** — adds Microsoft Patch Tuesday detail
5. **GitHub Security Advisories** — adds ecosystem package advisory coverage
6. **Vendor-specific sources** — Fortinet, Palo Alto, Cisco, Ivanti, VMware advisory feeds
7. **Threat activity sources** — CISA advisories, FBI/CISA joint advisories, ransomware tracking

---

## Sources

### CISA KEV (Known Exploited Vulnerabilities)

**What it provides:** Structured list of CVEs confirmed to have been exploited in the wild.
CISA publishes this catalog as a JSON feed updated when new exploits are confirmed.

**Why it matters:** KEV additions are the strongest public signal available. When CISA adds a CVE,
it means real exploitation has been observed. Federal agencies are required to remediate by a due date.
Private organizations use KEV as a prioritization signal.

**Data format:** JSON at `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Fields include: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `shortDescription`,
`dateAdded`, `dueDate`, `requiredAction`, `references`

**Expected use:** Primary signal source. Every KEV addition with sufficient context becomes a feed item.

**Risk/limitation:** KEV covers confirmed exploitation, not all critical CVEs. Some important
vulnerabilities may not be in KEV. Coverage is US-government-focused but broadly applicable.

---

### NVD (National Vulnerability Database)

**What it provides:** CVSS scores, descriptions, CWE classifications, and CPE product matching
for most published CVEs.

**Why it matters:** NVD enriches feed items with severity scores and standard descriptions
when vendor advisories are sparse or inconsistent.

**Data format:** REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`). Requires API key
for higher rate limits.

**Expected use:** Enrichment source only. Not used as a primary discovery source — too much volume.
Pull NVD data for CVEs already identified from KEV or vendor advisories.

**Risk/limitation:** NVD has experienced significant processing delays. Data may lag vendor disclosures
by days or weeks. Not a real-time source.

---

### Microsoft MSRC (Security Response Center)

**What it provides:** Microsoft's official security advisory feed, including Patch Tuesday releases.
Structured JSON/XML via MSRC API or CVRF feed.

**Why it matters:** Microsoft products (Windows, Office, Exchange, Azure) appear in many operator
environments. Patch Tuesday is a predictable monthly event worth summarizing.

**Data format:** CVRF/CSAF feed and REST API at `https://api.msrc.microsoft.com/`

**Expected use:** Monthly Patch Tuesday summary generation. Supplement KEV items affecting
Microsoft products.

**Risk/limitation:** Volume is high (100+ CVEs per Patch Tuesday). Need filtering to surface
only critical and actively exploited items for the public feed.

---

### GitHub Security Advisories (GHSA)

**What it provides:** Vulnerability advisories for open source packages across npm, PyPI, Go,
Maven, NuGet, and other ecosystems.

**Why it matters:** Teams running modern software stacks are exposed to supply chain vulnerabilities
in dependencies. GHSA covers these with structured data.

**Data format:** GraphQL API and REST API at `https://api.github.com/advisories`. Also available
as OSV-format exports.

**Expected use:** Supplement feed for ecosystem-specific advisories when a package has a significant
user base, high severity, or credible active exploitation.

**Risk/limitation:** Very high volume. Needs aggressive filtering. Most advisories are low-signal.
Best used selectively when a package is widely deployed or exploitation is confirmed.

---

### Vendor-specific advisory feeds

**What it provides:** Vendor security bulletins and advisories from Fortinet, Palo Alto Networks,
Cisco, Ivanti, VMware/Broadcom, and similar vendors common in operator environments.

**Why it matters:** Vendor advisories often precede KEV additions. Critical advisories from
network device vendors (firewalls, VPN appliances) warrant direct monitoring.

**Data format:** Varies by vendor. Some provide RSS/Atom feeds. Some require scraping or
using unofficial feeds.

**Expected use:** Supplement KEV for high-risk vendor products. Prioritize network security
appliances and identity/access management products.

**Risk/limitation:** No standardized format. Requires per-vendor integration. Vendor feeds
may change without notice.

---

### Threat activity sources

**What it provides:** CISA cybersecurity advisories, FBI/CISA joint advisories, and ransomware
campaign reports that describe active threat actor behavior without a specific CVE.

**Why it matters:** Some of the most actionable intelligence is threat-actor-activity-based,
not just CVE-based. "Ransomware group X is targeting unpatched Y" is a useful signal even
without a new CVE.

**Data format:** CISA advisories are structured JSON/STIX. FBI/CISA joint advisories are
typically PDF or HTML.

**Expected use:** Selective feed items when a credible advisory describes active campaigns
affecting products common in operator environments.

**Risk/limitation:** Threat activity sources require editorial judgment. Not everything
warrants a feed item. Quality over volume.

---

## Boundaries

These sources are not planned:

- **Shodan/Censys/internet scanning data** — PatchBrief does not verify exposure
- **Commercial threat intel feeds** — cost and licensing complexity
- **Dark web or closed-source intel** — outside public-sources-only constraint
- **Social media threat intel** — too noisy, requires human verification
- **Unverified researcher disclosures** — require vendor confirmation first
