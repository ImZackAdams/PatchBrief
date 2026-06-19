"""Tests for patchbrief.render.html.render_brief."""
from __future__ import annotations

from datetime import datetime

import pytest

from patchbrief.models import Advisory, AdvisoryMatch, Brief, Watchlist
from patchbrief.render.html import render_brief


def _make_brief(matches=None, source_names=None) -> Brief:
    watchlist = Watchlist(
        name="Test Watchlist",
        owner_email="test@example.com",
        cadence="weekly",
        terms=["Palo Alto", "Chrome"],
    )
    return Brief(
        generated_at=datetime(2024, 6, 15, 9, 0, 0),
        watchlist=watchlist,
        advisories_reviewed=5,
        matches=matches or [],
        source_names=source_names or ["CISA KEV"],
    )


def _make_match(title="Test Advisory", known_exploited=False, severity="medium") -> AdvisoryMatch:
    adv = Advisory(
        id="CVE-2024-0001",
        source="Test Source",
        source_url="https://example.com/advisory",
        title=title,
        description="A test description.",
        vendor="Test Vendor",
        product="Test Product",
        severity=severity,
        known_exploited=known_exploited,
        published_date="2024-01-01",
        cve="CVE-2024-0001",
        raw={},
    )
    return AdvisoryMatch(
        advisory=adv,
        matched_terms=["Test Vendor"],
        match_reasons=["Test Vendor matched in vendor"],
        priority=4,
        suggested_checks=["Confirm whether Test Vendor is present in your environment."],
    )


# 1. Rendered HTML contains watchlist terms
def test_html_contains_watchlist_terms():
    brief = _make_brief()
    html = render_brief(brief)
    assert "Palo Alto" in html
    assert "Chrome" in html


# 2. Rendered HTML contains disclaimer text
def test_html_contains_disclaimer():
    brief = _make_brief()
    html = render_brief(brief)
    assert "does not scan your environment" in html
    assert "vendor guidance" in html


# 3. HTML-unsafe content in advisory title is escaped
def test_xss_title_is_escaped():
    malicious_title = "<script>alert(1)</script>"
    match = _make_match(title=malicious_title)
    brief = _make_brief(matches=[match])
    html = render_brief(brief)
    # Raw script tag must NOT appear
    assert "<script>alert(1)</script>" not in html
    # Escaped version must appear
    assert "&lt;script&gt;" in html
    assert "alert(1)" in html  # The text content is present but safely escaped
