from __future__ import annotations

import json
import urllib.request
from datetime import date, timedelta

from .base import RawVuln

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def fetch_recent_kev(days: int = 30) -> list[RawVuln]:
    """Return KEV entries added within the last *days* days."""
    req = urllib.request.Request(
        CISA_KEV_URL,
        headers={"User-Agent": "PatchBrief-Ingest/1.0 (https://www.patchbrief.org)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))

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
            )
        )

    return results
