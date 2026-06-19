"""Tests for feed content loading and rendering."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchbrief.feed import FeedItem, load_feed_item
from patchbrief.render.feed import render_feed_item_card, render_rss


def _write_item(
    path: Path,
    *,
    title: str = "Sample item",
    summary: str = "Short summary.",
) -> None:
    path.write_text(
        f"""
id: sample
slug: sample
date: "2024-08-01"
type: KEV
signal: Known exploited
title: {json.dumps(title)}
summary: {json.dumps(summary)}
vendor: Example
product: Example Product
operator_check: Check whether Example Product is present.
why_it_matters: It is a useful public signal.
sources:
  - title: Vendor advisory
    url: https://example.com/advisory
""".strip(),
        encoding="utf-8",
    )


def _load_test_item(tmp_path: Path, **kwargs: str) -> FeedItem:
    path = tmp_path / "item.yml"
    _write_item(path, **kwargs)
    return load_feed_item(path)


def test_load_feed_item_validates_required_fields(tmp_path: Path):
    path = tmp_path / "item.yml"
    _write_item(path)

    item = load_feed_item(path)

    assert item.slug == "sample"
    assert item.display_date == "Aug 1, 2024"
    assert item.signal_class == "exploited"


def test_load_feed_item_rejects_missing_sources(tmp_path: Path):
    path = tmp_path / "item.yml"
    path.write_text(
        """
id: sample
slug: sample
date: "2024-08-01"
type: KEV
signal: Known exploited
title: Sample item
summary: Short summary.
vendor: Example
product: Example Product
operator_check: Check whether Example Product is present.
why_it_matters: It is a useful public signal.
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sources"):
        load_feed_item(path)


def test_feed_card_escapes_html(tmp_path: Path):
    item = _load_test_item(tmp_path, title="<script>alert(1)</script>")

    html = render_feed_item_card(item)

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_rss_escapes_titles_and_links(tmp_path: Path):
    item = _load_test_item(
        tmp_path,
        title="Example & item",
        summary="Summary with <angle brackets>.",
    )

    rss = render_rss([item], "https://patchbrief.test/")

    assert "<title>Example &amp; item</title>" in rss
    assert "<description>Summary with &lt;angle brackets&gt;.</description>" in rss
    assert "https://patchbrief.test/items/sample.html" in rss
