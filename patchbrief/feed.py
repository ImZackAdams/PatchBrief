from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class FeedSource:
    title: str
    url: str


@dataclass
class FeedItem:
    id: str
    slug: str
    date: str
    type: str
    signal: str
    title: str
    summary: str
    vendor: str
    product: str
    operator_check: str
    why_it_matters: str
    sources: list[FeedSource]
    cve: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    is_sample: bool = True

    @property
    def signal_class(self) -> str:
        mapping = {
            "Known exploited": "exploited",
            "Critical vendor advisory": "critical",
            "Patch review": "patch",
            "Threat activity": "threat",
        }
        return mapping.get(self.signal, "patch")

    @property
    def display_date(self) -> str:
        try:
            from datetime import date
            parts = self.date.split("-")
            d = date(int(parts[0]), int(parts[1]), int(parts[2]))
            return d.strftime("%b %-d, %Y")
        except Exception:
            return self.date

    @property
    def rfc822_date(self) -> str:
        try:
            from datetime import datetime, timezone
            parts = self.date.split("-")
            d = datetime(int(parts[0]), int(parts[1]), int(parts[2]), tzinfo=timezone.utc)
            return d.strftime("%a, %d %b %Y %H:%M:%S +0000")
        except Exception:
            return self.date


_REQUIRED_FIELDS = [
    "id", "slug", "date", "type", "signal", "title", "summary",
    "vendor", "product", "operator_check", "why_it_matters", "sources",
]


def load_feed_item(path: Path) -> FeedItem:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    missing = [k for k in _REQUIRED_FIELDS if not data.get(k)]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    sources_raw = data.get("sources", [])
    if not isinstance(sources_raw, list) or not sources_raw:
        raise ValueError("sources must be a non-empty list")

    sources = []
    for i, s in enumerate(sources_raw):
        if not isinstance(s, dict) or not s.get("title") or not s.get("url"):
            raise ValueError(f"sources[{i}] must have title and url")
        sources.append(FeedSource(title=s["title"], url=s["url"]))

    cve = data.get("cve")
    if cve is not None:
        cve = str(cve) if cve else None

    return FeedItem(
        id=str(data["id"]),
        slug=str(data["slug"]),
        date=str(data["date"]),
        type=str(data["type"]),
        signal=str(data["signal"]),
        title=str(data["title"]),
        summary=str(data["summary"]).strip(),
        vendor=str(data["vendor"]),
        product=str(data["product"]),
        cve=cve,
        operator_check=str(data["operator_check"]).strip(),
        why_it_matters=str(data["why_it_matters"]).strip(),
        sources=sources,
        tags=[str(t) for t in data.get("tags", [])],
        is_sample=bool(data.get("is_sample", True)),
    )


def load_feed_items(content_dir: Path) -> list[FeedItem]:
    yml_files = sorted(content_dir.glob("*.yml"))
    if not yml_files:
        raise ValueError(f"No YAML files found in {content_dir}")

    items: list[FeedItem] = []
    errors: list[str] = []

    for path in yml_files:
        try:
            items.append(load_feed_item(path))
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(f"  {path.name}: {exc}")

    if errors:
        raise ValueError("Feed item validation errors:\n" + "\n".join(errors))

    items.sort(key=lambda x: x.date, reverse=True)
    return items
