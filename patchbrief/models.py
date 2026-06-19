from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Advisory:
    id: str
    source: str
    source_url: str
    title: str
    description: str
    vendor: str
    product: str
    severity: str
    known_exploited: bool
    published_date: Optional[str] = None
    updated_date: Optional[str] = None
    cve: Optional[str] = None
    due_date: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Convert any datetime objects to isoformat strings
        for key, value in d.items():
            if isinstance(value, datetime):
                d[key] = value.isoformat()
        return d


@dataclass
class Watchlist:
    name: str
    owner_email: str
    cadence: str
    terms: list[str]


@dataclass
class AdvisoryMatch:
    advisory: Advisory
    matched_terms: list[str]
    match_reasons: list[str]
    priority: int
    suggested_checks: list[str]


@dataclass
class Brief:
    generated_at: datetime
    watchlist: Watchlist
    advisories_reviewed: int
    matches: list[AdvisoryMatch]
    source_names: list[str]
