from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from .http import fetch_json

EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass(frozen=True)
class EpssScore:
    cve: str
    epss: float
    percentile: float


def fetch_epss_scores(cve_ids: list[str], *, batch_size: int = 100) -> dict[str, EpssScore]:
    """Return latest EPSS scores keyed by upper-case CVE ID."""
    normalized = sorted({cve.upper() for cve in cve_ids if cve.upper().startswith("CVE-")})
    scores: dict[str, EpssScore] = {}

    for start in range(0, len(normalized), batch_size):
        batch = normalized[start:start + batch_size]
        if not batch:
            continue

        url = EPSS_API_URL + "?" + urllib.parse.urlencode({"cve": ",".join(batch)})
        try:
            data = fetch_json(url, timeout=45)
        except Exception as exc:
            print(f"  [epss] fetch failed for {len(batch)} CVEs: {exc}")
            continue

        for row in data.get("data", []):
            cve = str(row.get("cve") or "").upper()
            if not cve:
                continue
            try:
                scores[cve] = EpssScore(
                    cve=cve,
                    epss=float(row.get("epss")),
                    percentile=float(row.get("percentile")),
                )
            except (TypeError, ValueError):
                continue

    return scores
