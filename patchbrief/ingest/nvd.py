from __future__ import annotations

import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Optional

from .base import RawVuln
from .http import fetch_json

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
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key
    else:
        # Without a key, NVD allows ~5 req/30s — add delay to be safe.
        time.sleep(6)

    try:
        data = fetch_json(url, headers=headers, timeout=45)
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

        refs = [
            r["url"]
            for r in cve.get("references", [])[:4]
            if r.get("url")
        ]

        vendor, product = _extract_vendor_product(cve, description, refs)
        if not _is_resolved_value(vendor) or not _is_resolved_value(product):
            print(f"  [nvd] skipped {cve_id}: unresolved vendor/product")
            continue

        cvss_score = _extract_cvss_score(cve)

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
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                source_title=f"NVD — {cve_id}",
            )
        )

    return results


def _extract_vendor_product(cve: dict, description: str = "", references: list[str] | None = None) -> tuple[str, str]:
    configs = cve.get("configurations", [])
    for cfg in configs:
        parsed = _extract_from_node(cfg)
        if parsed:
            return parsed

    parsed = _infer_from_description(description)
    if parsed:
        return parsed

    return "Unresolved", "Unresolved"


def _extract_from_node(node: dict) -> tuple[str, str] | None:
    for match in node.get("cpeMatch", []):
        cpe = match.get("criteria", "")
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor = _display_cpe_part(parts[3])
            product = _display_cpe_part(parts[4])
            if _is_resolved_value(vendor) and _is_resolved_value(product):
                return vendor, product

    for child in node.get("nodes", []) or []:
        parsed = _extract_from_node(child)
        if parsed:
            return parsed

    return None


def _display_cpe_part(value: str) -> str:
    value = urllib.parse.unquote(value or "")
    value = value.replace("\\ ", " ").replace("_", " ").replace("-", " ")
    return " ".join(part for part in value.title().split() if part)


def _infer_from_description(description: str) -> tuple[str, str] | None:
    if not description:
        return None

    import re

    patterns = [
        r"^(?P<vendor>[A-Z][A-Za-z0-9&.\-]{1,40}) (?P<product>[A-Z][A-Za-z0-9&()./\- ]{1,70}) contains ",
        r"^(?P<vendor>[A-Z][A-Za-z0-9&.\-]{1,40}) (?P<product>[A-Z][A-Za-z0-9&()./\- ]{1,70}) versions? ",
        r"^A vulnerability in (?P<product>[A-Z][A-Za-z0-9&()./\- ]{1,70}) of (?P<vendor>[A-Z][A-Za-z0-9&.\- ]{1,40}) ",
    ]
    for pattern in patterns:
        match = re.search(pattern, description)
        if not match:
            continue
        vendor = _clean_inferred_name(match.group("vendor"))
        product = _clean_inferred_name(match.group("product"))
        if _is_resolved_value(vendor) and _is_resolved_value(product):
            return vendor, product

    return None


def _clean_inferred_name(value: str) -> str:
    value = value.strip(" .,:;")
    stop_words = (" contains", " versions", " prior", " before", " through")
    lower = value.lower()
    for stop in stop_words:
        idx = lower.find(stop)
        if idx != -1:
            value = value[:idx]
            break
    return " ".join(value.split())


def _is_resolved_value(value: str) -> bool:
    return bool(value and value.strip().lower() not in {"unknown", "unresolved", "n/a", "none", "*", "-", "product pending analysis"})


def _extract_cvss_score(cve: dict) -> Optional[float]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None
