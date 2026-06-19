from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Union

from patchbrief.models import Advisory, AdvisoryMatch, Watchlist

REQUIRED_FIELDS = {"id", "source", "source_url", "title", "description", "vendor", "product", "severity"}

CRITICAL_SEVERITIES = {"critical"}
HIGH_SEVERITIES = {"high"}


def load_advisories(path: Union[str, Path]) -> list[Advisory]:
    """Load a normalized JSON advisory file and return a list of Advisory dataclasses."""
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        records = json.load(f)

    advisories: list[Advisory] = []
    for i, record in enumerate(records):
        missing = REQUIRED_FIELDS - set(record.keys())
        if missing:
            print(
                f"Warning: skipping advisory at index {i} — missing fields: {', '.join(sorted(missing))}",
                file=sys.stderr,
            )
            continue

        advisories.append(
            Advisory(
                id=str(record["id"]),
                source=str(record["source"]),
                source_url=str(record["source_url"]),
                title=str(record["title"]),
                description=str(record["description"]),
                vendor=str(record["vendor"]),
                product=str(record["product"]),
                severity=str(record["severity"]),
                known_exploited=bool(record.get("known_exploited", False)),
                published_date=record.get("published_date"),
                updated_date=record.get("updated_date"),
                cve=record.get("cve"),
                due_date=record.get("due_date"),
                raw=record.get("raw", {}),
            )
        )
    return advisories


def _compute_priority(advisory: Advisory) -> int:
    """Return priority 1–4 based on known_exploited and severity."""
    if advisory.known_exploited:
        return 1
    sev = (advisory.severity or "").lower()
    if sev in CRITICAL_SEVERITIES:
        return 2
    if sev in HIGH_SEVERITIES:
        return 3
    return 4


def _build_suggested_checks(priority: int, matched_terms: list[str], match_reasons: list[str]) -> list[str]:
    """Generate deterministic suggested checks."""
    terms_str = ", ".join(matched_terms)
    checks = [
        f"Confirm whether {terms_str} is present in your environment.",
        "Review the source advisory linked below.",
    ]
    if priority == 1:
        checks.append("Treat as priority — this vulnerability has known exploitation.")
    elif priority == 2:
        checks.append("Review immediately — critical severity.")
    checks.append("Check current version or configuration against vendor guidance.")
    return checks


def match_advisories(watchlist: Watchlist, advisories: list[Advisory]) -> list[AdvisoryMatch]:
    """Match advisories against watchlist terms, returning sorted AdvisoryMatch list."""
    results: list[AdvisoryMatch] = []
    lower_terms = [t.lower() for t in watchlist.terms]

    for advisory in advisories:
        # Build searchable fields (field_name -> lowercased value or None)
        searchable = {
            "vendor": (advisory.vendor or "").lower(),
            "product": (advisory.product or "").lower(),
            "title": (advisory.title or "").lower(),
            "description": (advisory.description or "").lower(),
        }
        if advisory.cve:
            searchable["cve"] = advisory.cve.lower()

        matched_terms: list[str] = []
        match_reasons: list[str] = []

        for term, lower_term in zip(watchlist.terms, lower_terms):
            hit_fields: list[str] = []
            for field_name, field_value in searchable.items():
                if lower_term in field_value:
                    hit_fields.append(field_name)
            if hit_fields:
                if term not in matched_terms:
                    matched_terms.append(term)
                for f in hit_fields:
                    reason = f"{term} matched in {f}"
                    if reason not in match_reasons:
                        match_reasons.append(reason)

        if not matched_terms:
            continue

        priority = _compute_priority(advisory)
        suggested_checks = _build_suggested_checks(priority, matched_terms, match_reasons)

        results.append(
            AdvisoryMatch(
                advisory=advisory,
                matched_terms=matched_terms,
                match_reasons=match_reasons,
                priority=priority,
                suggested_checks=suggested_checks,
            )
        )

    # Sort: lowest priority number first, then by advisory.id
    results.sort(key=lambda m: (m.priority, m.advisory.id))
    return results


def filter_by_cadence(
    matches: list[AdvisoryMatch], cadence: str
) -> tuple[list[AdvisoryMatch], list[AdvisoryMatch]]:
    """
    Filter matches based on cadence setting.

    Returns (included, omitted).
    - important_only: include P1 and P2; omit P3 and P4
    - weekly/monthly: include all; omit nothing
    """
    if cadence == "important_only":
        included = [m for m in matches if m.priority <= 2]
        omitted = [m for m in matches if m.priority > 2]
        return included, omitted
    else:
        # weekly or monthly: include everything
        return list(matches), []
