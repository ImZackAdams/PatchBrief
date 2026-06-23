from __future__ import annotations

import urllib.parse
from datetime import date, timedelta
from typing import Iterable

from .base import RawVuln
from .http import fetch_json

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
ECOSYSTEM_LABELS = {
    "actions": "GitHub Actions",
    "composer": "Composer",
    "go": "Go",
    "maven": "Maven",
    "npm": "npm",
    "nuget": "NuGet",
    "pip": "PyPI",
    "pub": "Pub",
    "rubygems": "RubyGems",
    "rust": "Rust",
    "swift": "Swift",
}


def fetch_recent_github_advisories(
    *,
    days: int = 7,
    token: str | None = None,
    severities: Iterable[str] = ("critical", "high"),
    max_results: int = 30,
) -> list[RawVuln]:
    """Return recent reviewed GitHub Security Advisories."""
    cutoff = date.today() - timedelta(days=days)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results: list[RawVuln] = []
    seen: set[str] = set()
    per_severity = max(10, min(100, max_results))

    for severity in severities:
        params = {
            "type": "reviewed",
            "severity": severity,
            "published": f">={cutoff.isoformat()}",
            "sort": "published",
            "direction": "desc",
            "per_page": str(per_severity),
        }
        url = GITHUB_ADVISORIES_URL + "?" + urllib.parse.urlencode(params)

        try:
            data = fetch_json(url, headers=headers, timeout=45)
        except Exception as exc:
            print(f"  [github_advisories] fetch failed for severity={severity}: {exc}")
            continue

        for advisory in data:
            vuln = _to_raw_vuln(advisory)
            if not vuln:
                continue
            key = vuln.cve_id.upper()
            if key in seen:
                continue
            seen.add(key)
            results.append(vuln)
            if len(results) >= max_results:
                return results

    return results


def _to_raw_vuln(advisory: dict) -> RawVuln | None:
    ghsa_id = str(advisory.get("ghsa_id") or "").strip()
    primary_id = _first_identifier(advisory, "CVE") or ghsa_id
    if not primary_id:
        return None

    package = _primary_package(advisory)
    ecosystem = _display_ecosystem(package.get("ecosystem") or "Open source")
    package_name = package.get("name") or "Package"
    published_at = str(advisory.get("published_at") or "")[:10]

    summary = str(advisory.get("summary") or "").strip()
    description = str(advisory.get("description") or "").strip()
    text = summary or description or f"{primary_id} in {package_name}."

    html_url = str(advisory.get("html_url") or "").strip()
    references = [r for r in advisory.get("references", []) if isinstance(r, str) and r.startswith("http")]
    if html_url:
        references.insert(0, html_url)

    return RawVuln(
        source="github_advisory",
        cve_id=primary_id,
        vendor=ecosystem,
        product=package_name,
        description=text[:900],
        date_added=published_at,
        vulnerability_name=summary or None,
        cvss_score=_extract_cvss_score(advisory),
        references=references[:5],
        source_url=html_url or None,
        source_title=f"GitHub Advisory {ghsa_id}" if ghsa_id else "GitHub Advisory Database",
    )


def _first_identifier(advisory: dict, identifier_type: str) -> str | None:
    for identifier in advisory.get("identifiers", []):
        if identifier.get("type") == identifier_type and identifier.get("value"):
            return str(identifier["value"]).strip()
    return None


def _primary_package(advisory: dict) -> dict:
    vulnerabilities = advisory.get("vulnerabilities") or []
    for vuln in vulnerabilities:
        package = vuln.get("package") or {}
        if package.get("name"):
            return {
                "ecosystem": str(package.get("ecosystem") or "Open source").strip(),
                "name": str(package.get("name") or "Package").strip(),
            }
    return {"ecosystem": "Open source", "name": "Package"}


def _display_ecosystem(ecosystem: str) -> str:
    normalized = ecosystem.strip().lower()
    return ECOSYSTEM_LABELS.get(normalized, ecosystem.strip() or "Open source")


def _extract_cvss_score(advisory: dict) -> float | None:
    severities = advisory.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        score = (severities.get(key) or {}).get("score")
        if score is not None:
            return float(score)
    cvss = advisory.get("cvss") or {}
    score = cvss.get("score")
    return float(score) if score is not None else None
