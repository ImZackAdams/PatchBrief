from __future__ import annotations

from datetime import date, timedelta

from .base import RawVuln
from .http import fetch_json

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def fetch_recent_kev(days: int = 30) -> list[RawVuln]:
    """Return KEV entries added within the last *days* days."""
    data = fetch_json(CISA_KEV_URL, timeout=30)

    cutoff = date.today() - timedelta(days=days)
    results: list[RawVuln] = []

    for vuln in data.get("vulnerabilities", []):
        added_str = vuln.get("dateAdded", "")
        try:
            added = date.fromisoformat(added_str)
        except (ValueError, TypeError):
            continue

        if days > 0 and added < cutoff:
            continue

        cve_id = vuln.get("cveID", "").strip()
        if not cve_id:
            continue

        results.append(
            RawVuln(
                source="cisa_kev",
                cve_id=cve_id,
                vendor=vuln.get("vendorProject", "Unknown").strip(),
                product=vuln.get("product", "Unknown").strip(),
                description=vuln.get("shortDescription", "").strip(),
                date_added=added_str,
                vulnerability_name=vuln.get("vulnerabilityName", "").strip() or None,
                kev_action=vuln.get("requiredAction", "").strip() or None,
                kev_due_date=vuln.get("dueDate", "").strip() or None,
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                source_title="CISA KEV catalog",
            )
        )

    return results
