from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RawVuln:
    """Raw vulnerability data from an ingestion source before brief generation."""
    source: str           # "cisa_kev" | "nvd"
    cve_id: str           # e.g. "CVE-2024-1234"
    vendor: str
    product: str
    description: str
    date_added: str       # ISO date YYYY-MM-DD
    vulnerability_name: Optional[str] = None   # CISA KEV official name
    kev_action: Optional[str] = None
    kev_due_date: Optional[str] = None
    cvss_score: Optional[float] = None
    references: list[str] = field(default_factory=list)
