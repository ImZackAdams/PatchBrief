from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RawVuln:
    """Raw vulnerability data from an ingestion source before brief generation."""
    source: str
    cve_id: str           # CVE ID when available; otherwise a stable source ID.
    vendor: str
    product: str
    description: str
    date_added: str       # ISO date YYYY-MM-DD
    vulnerability_name: Optional[str] = None   # CISA KEV official name
    kev_action: Optional[str] = None
    kev_due_date: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    references: list[str] = field(default_factory=list)
    source_url: Optional[str] = None
    source_title: Optional[str] = None

    @property
    def is_cve(self) -> bool:
        return self.cve_id.upper().startswith("CVE-")
