"""Tests for patchbrief.advisories.match_advisories."""
from __future__ import annotations

import pytest

from patchbrief.advisories import match_advisories
from patchbrief.models import Advisory, Watchlist


def _advisory(**kwargs) -> Advisory:
    defaults = dict(
        id="CVE-2024-0001",
        source="Test Source",
        source_url="https://example.com/advisory",
        title="Test Advisory",
        description="A test advisory description.",
        vendor="Acme Corp",
        product="Acme Widget",
        severity="medium",
        known_exploited=False,
        published_date="2024-01-01",
        updated_date=None,
        cve=None,
        due_date=None,
        raw={},
    )
    defaults.update(kwargs)
    return Advisory(**defaults)


def _watchlist(*terms, cadence="weekly") -> Watchlist:
    return Watchlist(
        name="Test",
        owner_email="test@example.com",
        cadence=cadence,
        terms=list(terms),
    )


# 1. Vendor field match
def test_vendor_match():
    adv = _advisory(id="CVE-2024-0001", vendor="Palo Alto Networks", product="PAN-OS")
    wl = _watchlist("Palo Alto")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert "vendor" in " ".join(matches[0].match_reasons)


# 2. Product field match
def test_product_match():
    adv = _advisory(id="CVE-2024-0002", vendor="Microsoft", product="Windows Server 2022")
    wl = _watchlist("Windows Server")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert "product" in " ".join(matches[0].match_reasons)


# 3. Title field match
def test_title_match():
    adv = _advisory(
        id="CVE-2024-0003",
        title="Remote Code Execution in Apache Struts",
        vendor="Apache",
        product="Struts",
    )
    wl = _watchlist("Remote Code Execution")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert "title" in " ".join(matches[0].match_reasons)


# 4. Description field match
def test_description_match():
    adv = _advisory(
        id="CVE-2024-0004",
        description="An unauthenticated attacker can exploit the Cisco IOS XE management interface.",
        vendor="Cisco",
        product="IOS",
    )
    wl = _watchlist("Cisco IOS")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert "description" in " ".join(matches[0].match_reasons)


# 5. CVE field match
def test_cve_match():
    adv = _advisory(
        id="CVE-2024-0005",
        cve="CVE-2024-0005",
        vendor="Generic Vendor",
        product="Generic Product",
    )
    wl = _watchlist("CVE-2024-0005")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert "cve" in " ".join(matches[0].match_reasons)


# 6. Unmatched advisory excluded
def test_unmatched_excluded():
    adv = _advisory(
        id="CVE-2024-0006",
        vendor="Unknown Vendor",
        product="Unknown Product",
        title="Unrelated advisory",
        description="Nothing to see here.",
    )
    wl = _watchlist("Palo Alto", "Microsoft")
    matches = match_advisories(wl, [adv])
    assert matches == []


# 7. known_exploited=True → P1
def test_known_exploited_is_p1():
    adv = _advisory(
        id="CVE-2024-0007",
        vendor="Palo Alto Networks",
        known_exploited=True,
        severity="critical",
    )
    wl = _watchlist("Palo Alto")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert matches[0].priority == 1


# 8. severity=critical, not known_exploited → P2
def test_critical_not_exploited_is_p2():
    adv = _advisory(
        id="CVE-2024-0008",
        vendor="Microsoft",
        known_exploited=False,
        severity="critical",
    )
    wl = _watchlist("Microsoft")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert matches[0].priority == 2


# 9. severity=high → P3
def test_high_severity_is_p3():
    adv = _advisory(
        id="CVE-2024-0009",
        vendor="Fortinet",
        known_exploited=False,
        severity="high",
    )
    wl = _watchlist("Fortinet")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert matches[0].priority == 3


# 10. severity=medium → P4
def test_medium_severity_is_p4():
    adv = _advisory(
        id="CVE-2024-0010",
        vendor="Veeam",
        known_exploited=False,
        severity="medium",
    )
    wl = _watchlist("Veeam")
    matches = match_advisories(wl, [adv])
    assert len(matches) == 1
    assert matches[0].priority == 4


# 11. P1 appears before P4 in sorted output
def test_sort_p1_before_p4():
    adv_p4 = _advisory(
        id="CVE-2024-0020",
        vendor="Veeam",
        known_exploited=False,
        severity="medium",
    )
    adv_p1 = _advisory(
        id="CVE-2024-0021",
        vendor="Veeam",
        known_exploited=True,
        severity="critical",
    )
    wl = _watchlist("Veeam")
    # Pass P4 first to ensure sorting is tested
    matches = match_advisories(wl, [adv_p4, adv_p1])
    assert len(matches) == 2
    assert matches[0].priority == 1
    assert matches[1].priority == 4
