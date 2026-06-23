from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta

from .base import RawVuln
from .http import fetch_text

CERT_VU_ATOM_URL = "https://www.kb.cert.org/vuls/atomfeed/"

_ATOM_NS = {"atom": "http://www.w3.org/2005/Atom"}


def fetch_recent_cert_vu(
    *,
    days: int = 7,
    max_results: int = 20,
) -> list[RawVuln]:
    """Return recent CERT/CC Vulnerability Notes from the public Atom feed."""
    cutoff = date.today() - timedelta(days=days)

    try:
        xml_text = fetch_text(CERT_VU_ATOM_URL, timeout=45)
    except Exception as exc:
        print(f"  [cert_vu] fetch failed: {exc}")
        return []

    return _parse_cert_atom(xml_text, cutoff=cutoff, max_results=max_results)


def _parse_cert_atom(xml_text: str, *, cutoff: date, max_results: int) -> list[RawVuln]:
    root = ET.fromstring(xml_text)
    results: list[RawVuln] = []

    for entry in root.findall("atom:entry", _ATOM_NS):
        title = _text(entry.find("atom:title", _ATOM_NS))
        link = _entry_link(entry)
        published = _text(entry.find("atom:published", _ATOM_NS)) or _text(entry.find("atom:updated", _ATOM_NS))
        published_date = _parse_date(published)
        if not published_date or published_date < cutoff:
            continue

        vu_id = _extract_vu_id(title, link)
        if not vu_id:
            continue

        summary = _html_to_text(_text(entry.find("atom:summary", _ATOM_NS)))
        vendor, product = _infer_vendor_product(title, summary)
        if not vendor or not product:
            continue

        cves = _extract_cves(summary)
        cve_note = f" Related CVEs: {', '.join(cves[:4])}." if cves else ""

        results.append(
            RawVuln(
                source="cert_vu",
                cve_id=f"VU-{vu_id}",
                vendor=vendor,
                product=product,
                description=(_truncate(summary, 850) + cve_note).strip(),
                date_added=published_date.isoformat(),
                vulnerability_name=title,
                references=[link] if link else [],
                source_url=link,
                source_title=f"CERT/CC Vulnerability Note VU#{vu_id}",
            )
        )
        if len(results) >= max_results:
            break

    return results


def _entry_link(entry: ET.Element) -> str:
    for link in entry.findall("atom:link", _ATOM_NS):
        if link.attrib.get("rel") in {None, "", "alternate"} and link.attrib.get("href"):
            return link.attrib["href"].strip()
    return ""


def _text(element: ET.Element | None) -> str:
    return "".join(element.itertext()).strip() if element is not None else ""


def _parse_date(value: str) -> date | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).date()
    except ValueError:
        return None


def _extract_vu_id(title: str, link: str) -> str:
    match = re.search(r"VU#(\d+)", title) or re.search(r"/id/(\d+)", link)
    return match.group(1) if match else ""


def _extract_cves(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))


def _html_to_text(value: str) -> str:
    value = html.unescape(value or "")
    value = re.sub(r"<(h[1-6]|p|li|br)\b[^>]*>", " ", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    return " ".join(value.split())


def _infer_vendor_product(title: str, summary: str) -> tuple[str, str]:
    clean_title = re.sub(r"^VU#\d+:\s*", "", title).strip()

    patterns = [
        r"\bin (?P<name>[A-Z][A-Za-z0-9 ._+\-/()]{3,90})",
        r"^(?P<name>[A-Z][A-Za-z0-9 ._+\-/()]{3,90}) (?:allows|contains|does|is|has|exposes|uses|found) ",
    ]
    for pattern in patterns:
        match = re.search(pattern, clean_title)
        if match:
            name = _clean_name(match.group("name"))
            if name:
                return _split_vendor_product(name)

    cve_context = re.search(r"\b(?P<name>[A-Z][A-Za-z0-9 ._+\-/()]{3,80}) (?:versions?|before|through|contains)", summary)
    if cve_context:
        return _split_vendor_product(_clean_name(cve_context.group("name")))

    fallback = _clean_name(clean_title)
    if fallback:
        return "Multiple vendors", fallback[:80]
    return "", ""


def _split_vendor_product(name: str) -> tuple[str, str]:
    parts = name.split()
    if len(parts) == 1:
        return parts[0], parts[0]
    vendor = parts[0]
    product = " ".join(parts[1:]) or name
    if vendor.lower() in {"multiple", "vendor-signed"}:
        return "Multiple vendors", name
    return vendor, product


def _clean_name(value: str) -> str:
    value = re.split(r"\b(?:before|through|versions?|may|allows|contains|found|vulnerable)\b", value, maxsplit=1)[0]
    value = value.strip(" .,:;-")
    return " ".join(value.split())


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    trimmed = value[:limit].rsplit(" ", 1)[0].strip(" .,:;")
    return f"{trimmed}..."
