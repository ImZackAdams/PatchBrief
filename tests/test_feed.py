"""Tests for feed content loading and rendering."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchbrief.feed import FeedItem, load_feed_item
from patchbrief.monetization import checkout_url, paid_cta_url
from patchbrief.render.feed import (
    render_feed_item_card,
    render_item_page,
    render_rss,
    render_sitemap,
)


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


def test_load_feed_item_rejects_unknown_vendor_or_product(tmp_path: Path):
    path = tmp_path / "item.yml"
    _write_item(path)
    text = path.read_text(encoding="utf-8").replace("vendor: Example", "vendor: Unknown")
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="vendor must be specific"):
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


def test_checkout_url_encodes_plan_billing_and_source():
    url = checkout_url("team", "monthly", "pricing card")

    assert url == "/checkout.html?plan=team&billing=monthly&source=pricing+card"


def test_paid_cta_url_uses_configured_payment_link(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PATCHBRIEF_STRIPE_PRO_YEARLY_URL", "https://buy.stripe.test/pro-yearly")

    assert paid_cta_url("pro", "yearly", "test") == "https://buy.stripe.test/pro-yearly"


def test_paid_cta_url_falls_back_to_checkout(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PATCHBRIEF_STRIPE_TEAM_MONTHLY_URL", raising=False)

    assert (
        paid_cta_url("team", "monthly", "test")
        == "/checkout.html?plan=team&billing=monthly&source=test"
    )


def test_item_page_has_paid_alert_cta(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PATCHBRIEF_STRIPE_PRO_YEARLY_URL", raising=False)
    item = _load_test_item(tmp_path)

    html = render_item_page(item)

    assert "Get Pro alerts" in html
    assert "/checkout.html?plan=pro&amp;billing=yearly&amp;source=brief" in html


def test_sitemap_includes_revenue_and_item_pages(tmp_path: Path):
    item = _load_test_item(tmp_path)

    sitemap = render_sitemap([item], "https://patchbrief.test/")

    assert "<loc>https://patchbrief.test/pricing.html</loc>" in sitemap
    assert "<loc>https://patchbrief.test/checkout.html</loc>" in sitemap
    assert "<loc>https://patchbrief.test/items/sample.html</loc>" in sitemap
