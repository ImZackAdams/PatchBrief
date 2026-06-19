from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional

from .base import RawVuln

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_critical(
    days: int = 7,
    api_key: Optional[str] = None,
    max_results: int = 30,
) -> list[RawVuln]:
    """Return CRITICAL CVEs published within the last *days* days from NVD."""
    now = datetime.now(tz=timezone.utc)
    start = now - timedelta(days=days)

    params: dict[str, str] = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": str(max_results),
    }

    url = NVD_API_URL + "?" + urllib.parse.urlencode(params)
    headers: dict[str, str] = {
        "User-Agent": "PatchBrief-Ingest/1.0 (https://www.patchbrief.org)"
    }
    if api_key:
        headers["apiKey"] = api_key
    else:
        # Without a key, NVD allows ~5 req/30s — add delay to be safe.
        time.sleep(6)

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"  [nvd] fetch failed: {exc}")
        return []

    results: list[RawVuln] = []
    for vuln_item in data.get("vulnerabilities", []):
        cve = vuln_item.get("cve", {})
        cve_id = cve.get("id", "").strip()
        if not cve_id:
            continue

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        ).strip()

        vendor, product = _extract_vendor_product(cve)

        cvss_score = _extract_cvss_score(cve)

        refs = [
            r["url"]
            for r in cve.get("references", [])[:4]
            if r.get("url")
        ]

        pub_date = cve.get("published", "")[:10]

        results.append(
            RawVuln(
                source="nvd",
                cve_id=cve_id,
                vendor=vendor,
                product=product,
                description=description[:600],
                date_added=pub_date,
                cvss_score=cvss_score,
                references=refs,
            )
        )

    return results


def _extract_vendor_product(cve: dict) -> tuple[str, str]:
    configs = cve.get("configurations", [])
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    if vendor and product and vendor != "*":
                        return vendor, product
    return "Unknown", "Unknown"


def _extract_cvss_score(cve: dict) -> Optional[float]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None
