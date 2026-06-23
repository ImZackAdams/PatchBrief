from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import anthropic as _anthropic
    from patchbrief.ingest.base import RawVuln

MODEL = "claude-haiku-4-5-20251001"

_SYSTEM = (
    "You are a security intelligence analyst writing operator-ready briefs for the "
    "PatchBrief public feed. Briefs are concise, factual, and actionable. "
    "Write for security operators who need to know whether and how a vulnerability "
    "affects their environment. Never speculate. Stick to what public sources confirm."
)

_VALID_SIGNALS = {
    "Known exploited",
    "Critical vendor advisory",
    "High-risk advisory",
    "Patch review",
    "Threat activity",
}

_VALID_TYPES = {
    "KEV",
    "Vendor advisory",
    "Patch Tuesday",
    "Ransomware",
    "Exploit activity",
}


def generate_brief(vuln: "RawVuln", client: "_anthropic.Anthropic") -> dict:
    """Call Claude to generate structured brief fields for *vuln*.

    Returns a dict with keys: title, summary, operator_check, why_it_matters,
    signal, type.
    """
    source_block = _build_source_block(vuln)

    prompt = f"""Based on this public vulnerability data, write a PatchBrief security intelligence brief.

{source_block}

Return a JSON object with EXACTLY these keys (no extras, no markdown fences):
{{
  "title": "<concise factual headline under 100 chars>",
  "summary": "<2-3 sentences: what the vulnerability is, how it works, who is affected>",
  "operator_check": "<2-4 sentences: specific actions for security operators to verify or patch>",
  "why_it_matters": "<1-2 sentences: impact and exploitability context>",
  "signal": "<one of: Known exploited | Critical vendor advisory | Patch review | Threat activity>",
  "type": "<one of: KEV | Vendor advisory | Patch Tuesday | Ransomware | Exploit activity>"
}}"""

    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    result = json.loads(raw)
    return _validate_and_fix(result, vuln)


def _build_source_block(vuln: "RawVuln") -> str:
    lines = [
        f"CVE ID: {vuln.cve_id}",
        f"Vendor: {vuln.vendor}",
        f"Product: {vuln.product}",
        f"Description: {vuln.description}",
        f"Source: {vuln.source}",
        f"Date: {vuln.date_added}",
    ]
    if vuln.kev_action:
        lines.append(f"CISA Required Action: {vuln.kev_action}")
    if vuln.cvss_score is not None:
        lines.append(f"CVSS Score: {vuln.cvss_score}")
    if vuln.epss_score is not None:
        lines.append(f"EPSS Probability: {vuln.epss_score:.3f}")
    if vuln.epss_percentile is not None:
        lines.append(f"EPSS Percentile: {vuln.epss_percentile:.3f}")
    if vuln.references:
        lines.append("References: " + ", ".join(vuln.references[:3]))
    return "\n".join(lines)


def generate_raw_brief(vuln: "RawVuln") -> dict:
    """Build a brief from raw source fields only — no AI call needed.

    Uses CISA KEV's own vulnerability name, description, and required action
    directly. Results are accurate but less polished than AI-generated briefs.
    """
    if vuln.source == "cisa_kev":
        title = vuln.vulnerability_name or f"{vuln.vendor} {vuln.product} — {vuln.cve_id}"
        summary = vuln.description or f"{vuln.cve_id} affects {vuln.vendor} {vuln.product}."
        operator_check = vuln.kev_action or (
            f"Apply available patches for {vuln.product}. "
            f"Check vendor guidance for {vuln.cve_id}."
        )
        due_note = (
            f" CISA remediation deadline: {vuln.kev_due_date}." if vuln.kev_due_date else ""
        )
        why_it_matters = (
            f"{vuln.cve_id} is listed in CISA's Known Exploited Vulnerabilities catalog, "
            f"confirming active exploitation in the wild.{due_note} "
            f"Treat remediation as urgent."
        )
        signal = "Known exploited"
        type_ = "KEV"
    elif vuln.source == "github_advisory":
        title = vuln.vulnerability_name or f"{vuln.product} — {vuln.cve_id}"
        summary = (
            vuln.description
            or f"GitHub reviewed advisory {vuln.cve_id} affects {vuln.product} in the {vuln.vendor} ecosystem."
        )
        score_note = f" CVSS score: {vuln.cvss_score}." if vuln.cvss_score else ""
        epss_note = _epss_sentence(vuln)
        operator_check = (
            f"Check whether {vuln.product} is present in application dependency manifests, lockfiles, or build images. "
            f"Review the GitHub advisory and upgrade to a patched version where available.{score_note}{epss_note}"
        )
        why_it_matters = (
            f"GitHub has published a reviewed security advisory for {vuln.product}. "
            f"Prioritize it with other application dependency updates"
            + (f", especially because EPSS places it in the {vuln.epss_percentile:.0%} percentile." if vuln.epss_percentile else ".")
        )
        signal = "Critical vendor advisory" if (vuln.cvss_score or 0) >= 9 else "High-risk advisory"
        type_ = "Vendor advisory"
    else:
        title = f"{vuln.vendor} {vuln.product} — {vuln.cve_id} (Critical)"
        summary = vuln.description or f"Critical vulnerability in {vuln.vendor} {vuln.product}."
        score_note = f" CVSS score: {vuln.cvss_score}." if vuln.cvss_score else ""
        epss_note = _epss_sentence(vuln)
        operator_check = (
            f"Review {vuln.cve_id} in your asset inventory. "
            f"Apply patches per vendor guidance and verify {vuln.product} is not exposed.{score_note}{epss_note}"
        )
        why_it_matters = (
            f"This CVE carries a CRITICAL severity rating"
            + (f" (CVSS {vuln.cvss_score})" if vuln.cvss_score else "")
            + f" in {vuln.vendor} {vuln.product}. Patch or mitigate promptly."
            + (
                f" EPSS percentile: {vuln.epss_percentile:.0%}."
                if vuln.epss_percentile is not None
                else ""
            )
        )
        signal = "Critical vendor advisory"
        type_ = "Vendor advisory"

    return {
        "title": title[:117] + "..." if len(title) > 120 else title,
        "summary": _clean_public_text(summary),
        "operator_check": _clean_public_text(operator_check),
        "why_it_matters": _clean_public_text(why_it_matters),
        "signal": signal,
        "type": type_,
    }


def _epss_sentence(vuln: "RawVuln") -> str:
    if vuln.epss_score is None or vuln.epss_percentile is None:
        return ""
    return f" EPSS probability: {vuln.epss_score:.1%}; percentile: {vuln.epss_percentile:.0%}."


def _validate_and_fix(result: dict, vuln: "RawVuln") -> dict:
    if result.get("signal") not in _VALID_SIGNALS:
        result["signal"] = (
            "Known exploited" if vuln.source == "cisa_kev" else "Critical vendor advisory"
        )
    if result.get("type") not in _VALID_TYPES:
        result["type"] = "KEV" if vuln.source == "cisa_kev" else "Vendor advisory"

    for key in ("title", "summary", "operator_check", "why_it_matters"):
        if not result.get(key):
            result[key] = f"See {vuln.cve_id} advisory for details."

    if len(result.get("title", "")) > 120:
        result["title"] = result["title"][:117] + "..."

    for key in ("summary", "operator_check", "why_it_matters"):
        result[key] = _clean_public_text(str(result.get(key, "")))

    return result


def _clean_public_text(text: str) -> str:
    text = re.sub(
        r"\b(?:This affects|This impacts|Affected is) an unknown function of the file (?P<file>\S+)(?: of the component (?P<component>[^.]+))?\.",
        _replace_unknown_function,
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\ban unknown function\b", "an affected code path", text, flags=re.IGNORECASE)
    return " ".join(text.split())


def _replace_unknown_function(match: re.Match[str]) -> str:
    file_name = match.group("file")
    component = (match.group("component") or "").strip()
    if component:
        return f"The issue affects {file_name} in the {component} component."
    return f"The issue affects {file_name}."
