from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta

from .base import RawVuln
from .http import fetch_json, fetch_text

MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_GUIDE_URL = "https://msrc.microsoft.com/update-guide/en-US/vulnerability"

_NS = {
    "cvrf": "http://www.icasi.org/CVRF/schema/cvrf/1.1",
    "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
}


def fetch_recent_msrc(
    *,
    days: int = 35,
    max_results: int = 25,
    min_cvss: float = 8.8,
) -> list[RawVuln]:
    """Return recent high-signal Microsoft Security Update Guide CVEs."""
    cutoff = date.today() - timedelta(days=days)
    try:
        updates = fetch_json(MSRC_UPDATES_URL, timeout=45)
    except Exception as exc:
        print(f"  [msrc] updates fetch failed: {exc}")
        return []

    results: list[RawVuln] = []
    for update in _recent_security_updates(updates, cutoff=cutoff):
        cvrf_url = str(update.get("CvrfUrl") or "").strip()
        if not cvrf_url:
            continue
        try:
            cvrf_xml = fetch_text(cvrf_url, headers={"Accept": "application/xml"}, timeout=60)
        except Exception as exc:
            print(f"  [msrc] CVRF fetch failed for {update.get('ID')}: {exc}")
            continue
        results.extend(
            _parse_cvrf(
                cvrf_xml,
                release_id=str(update.get("ID") or ""),
                release_title=str(update.get("DocumentTitle") or "Microsoft Security Updates"),
                release_date=str(update.get("InitialReleaseDate") or "")[:10],
                min_cvss=min_cvss,
                remaining=max_results - len(results),
            )
        )
        if len(results) >= max_results:
            break

    return results


def _recent_security_updates(updates: dict, *, cutoff: date) -> list[dict]:
    candidates = []
    for update in updates.get("value", []):
        title = str(update.get("DocumentTitle") or "")
        released = _parse_date(str(update.get("InitialReleaseDate") or ""))
        if not released or released < cutoff or "Security Updates" not in title:
            continue
        candidates.append(update)
    return sorted(candidates, key=lambda item: str(item.get("InitialReleaseDate") or ""), reverse=True)


def _parse_cvrf(
    xml_text: str,
    *,
    release_id: str,
    release_title: str,
    release_date: str,
    min_cvss: float,
    remaining: int,
) -> list[RawVuln]:
    if remaining <= 0:
        return []

    root = ET.fromstring(xml_text)
    results: list[RawVuln] = []

    for vuln_el in root.findall("vuln:Vulnerability", _NS):
        cve_id = _text(vuln_el.find("vuln:CVE", _NS))
        if not cve_id:
            continue

        score = _cvss_score(vuln_el)
        severity = _threat_description(vuln_el, "Severity")
        exploit_status = _threat_description(vuln_el, "Exploit Status")
        if not _is_high_signal(score, severity, exploit_status, min_cvss):
            continue

        title = _text(vuln_el.find("vuln:Title", _NS)) or cve_id
        product = _tag_note(vuln_el) or _product_from_title(title)
        if not product:
            continue

        description = _note(vuln_el, "Description") or title
        references = _remediation_urls(vuln_el)
        guide_url = f"{MSRC_GUIDE_URL}/{cve_id}"
        references.insert(0, guide_url)

        status_note = f" MSRC exploitability: {exploit_status}." if exploit_status else ""
        results.append(
            RawVuln(
                source="msrc",
                cve_id=cve_id,
                vendor="Microsoft",
                product=product,
                description=f"{description} Published in {release_title}.{status_note}"[:900],
                date_added=release_date,
                vulnerability_name=title,
                cvss_score=score,
                references=references[:5],
                source_url=guide_url,
                source_title=f"MSRC {release_id} Security Update Guide",
            )
        )
        if len(results) >= remaining:
            break

    return results


def _is_high_signal(score: float | None, severity: str, exploit_status: str, min_cvss: float) -> bool:
    if severity.lower() == "critical":
        return True
    if score is not None and score >= min_cvss:
        return True
    return "exploitation more likely" in exploit_status.lower()


def _parse_date(value: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _text(element: ET.Element | None) -> str:
    return "".join(element.itertext()).strip() if element is not None else ""


def _note(vuln_el: ET.Element, note_type: str) -> str:
    for note in vuln_el.findall("vuln:Notes/vuln:Note", _NS):
        if note.attrib.get("Type") == note_type:
            return _clean_html(_text(note))
    return ""


def _tag_note(vuln_el: ET.Element) -> str:
    for note in vuln_el.findall("vuln:Notes/vuln:Note", _NS):
        if note.attrib.get("Type") == "Tag":
            value = _clean_html(_text(note))
            if value:
                return value
    return ""


def _threat_description(vuln_el: ET.Element, threat_type: str) -> str:
    for threat in vuln_el.findall("vuln:Threats/vuln:Threat", _NS):
        if threat.attrib.get("Type") == threat_type:
            return _text(threat.find("vuln:Description", _NS))
    return ""


def _cvss_score(vuln_el: ET.Element) -> float | None:
    scores = []
    for score_el in vuln_el.findall("vuln:CVSSScoreSets/vuln:ScoreSet/vuln:BaseScore", _NS):
        try:
            scores.append(float(_text(score_el)))
        except ValueError:
            continue
    return max(scores) if scores else None


def _remediation_urls(vuln_el: ET.Element) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for url_el in vuln_el.findall("vuln:Remediations/vuln:Remediation/vuln:URL", _NS):
        url = _text(url_el)
        if url.startswith("http") and url not in seen:
            urls.append(url)
            seen.add(url)
    return urls


def _product_from_title(title: str) -> str:
    title = re.sub(r"\b(?:Remote Code Execution|Elevation of Privilege|Information Disclosure|Spoofing|Denial of Service|Security Feature Bypass|Tampering) Vulnerability\b", "", title, flags=re.IGNORECASE)
    title = title.replace("Microsoft Microsoft", "Microsoft")
    return " ".join(title.strip(" -").split())


def _clean_html(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value)
    return " ".join(value.split())
