from __future__ import annotations

from pathlib import Path

from patchbrief.cli import (
    _build_sources,
    _filter_public_items,
    _load_source_status,
    _resolve_sources,
    _write_source_status,
)
from patchbrief.generate.brief import generate_raw_brief
from patchbrief.ingest import epss, github_advisories, nvd
from patchbrief.ingest.base import RawVuln


class _Item:
    def __init__(self, date: str) -> None:
        self.date = date


def test_github_advisory_source_maps_reviewed_advisory(monkeypatch):
    def fake_fetch_json(url: str, **kwargs):
        return [
            {
                "ghsa_id": "GHSA-abcd-1234-efgh",
                "html_url": "https://github.com/advisories/GHSA-abcd-1234-efgh",
                "summary": "Example package allows remote code execution",
                "description": "Longer advisory body.",
                "published_at": "2026-06-20T10:00:00Z",
                "identifiers": [
                    {"type": "GHSA", "value": "GHSA-abcd-1234-efgh"},
                    {"type": "CVE", "value": "CVE-2026-9999"},
                ],
                "references": ["https://example.com/advisory"],
                "vulnerabilities": [
                    {"package": {"ecosystem": "npm", "name": "example-package"}}
                ],
                "cvss_severities": {
                    "cvss_v3": {"score": 9.8},
                },
            }
        ]

    monkeypatch.setattr(github_advisories, "fetch_json", fake_fetch_json)

    items = github_advisories.fetch_recent_github_advisories(days=3, max_results=5)

    assert len(items) == 1
    assert items[0].source == "github_advisory"
    assert items[0].cve_id == "CVE-2026-9999"
    assert items[0].vendor == "npm"
    assert items[0].product == "example-package"
    assert items[0].cvss_score == 9.8
    assert items[0].source_url == "https://github.com/advisories/GHSA-abcd-1234-efgh"


def test_epss_fetch_scores_batches_cves(monkeypatch):
    def fake_fetch_json(url: str, **kwargs):
        return {
            "data": [
                {"cve": "CVE-2026-9999", "epss": "0.42", "percentile": "0.96"},
            ]
        }

    monkeypatch.setattr(epss, "fetch_json", fake_fetch_json)

    scores = epss.fetch_epss_scores(["CVE-2026-9999", "not-a-cve"])

    assert scores["CVE-2026-9999"].epss == 0.42
    assert scores["CVE-2026-9999"].percentile == 0.96


def test_raw_brief_for_github_advisory_uses_open_source_copy():
    vuln = RawVuln(
        source="github_advisory",
        cve_id="CVE-2026-9999",
        vendor="npm",
        product="example-package",
        description="Example package allows remote code execution.",
        date_added="2026-06-20",
        cvss_score=9.8,
        epss_score=0.42,
        epss_percentile=0.96,
    )

    brief = generate_raw_brief(vuln)

    assert brief["signal"] == "Critical vendor advisory"
    assert brief["type"] == "Vendor advisory"
    assert "dependency" in brief["operator_check"]
    assert "EPSS probability" in brief["operator_check"]


def test_raw_brief_cleans_noisy_nvd_unknown_function_copy():
    vuln = RawVuln(
        source="nvd",
        cve_id="CVE-2026-0001",
        vendor="Example",
        product="Example Product",
        description=(
            "A vulnerability was identified in Example Product. This affects an unknown "
            "function of the file /view.php of the component Parameter Handler. Remote "
            "exploitation is possible."
        ),
        date_added="2026-06-20",
        cvss_score=9.8,
    )

    brief = generate_raw_brief(vuln)

    assert "unknown function" not in brief["summary"].lower()
    assert "The issue affects /view.php in the Parameter Handler component." in brief["summary"]


def test_source_helpers_round_trip_status(tmp_path: Path):
    path = tmp_path / "source-status.json"
    run = {
        "id": "github_advisory",
        "label": "GitHub Security Advisories",
        "role": "source",
        "status": "ok",
        "items_seen": 2,
        "started_at": "2026-06-20T00:00:00Z",
        "finished_at": "2026-06-20T00:00:02Z",
    }

    _write_source_status(path, [run])

    assert _load_source_status(path)[0]["id"] == "github_advisory"
    assert _resolve_sources("cisa-kev,nvd,github-advisory") == [
        "cisa_kev",
        "nvd",
        "github_advisory",
    ]


def test_public_feed_window_hides_archive_items():
    items = [_Item("2026-06-01"), _Item("2024-01-01")]

    assert [item.date for item in _filter_public_items(items, 365)] == ["2026-06-01"]
    assert len(_filter_public_items(items, 0)) == 2


def test_public_feed_window_rejects_negative_values():
    try:
        _filter_public_items([_Item("2026-06-01")], -1)
    except ValueError as exc:
        assert "0 or greater" in str(exc)
    else:
        raise AssertionError("expected negative public window to fail")


def test_build_sources_avoids_fake_nvd_link_for_ghsa_only():
    vuln = RawVuln(
        source="github_advisory",
        cve_id="GHSA-abcd-1234-efgh",
        vendor="npm",
        product="example-package",
        description="Example advisory.",
        date_added="2026-06-20",
        source_url="https://github.com/advisories/GHSA-abcd-1234-efgh",
        source_title="GitHub Advisory GHSA-abcd-1234-efgh",
    )

    sources = _build_sources(vuln)

    assert sources == [
        {
            "title": "GitHub Advisory GHSA-abcd-1234-efgh",
            "url": "https://github.com/advisories/GHSA-abcd-1234-efgh",
        }
    ]


def test_nvd_extracts_vendor_product_from_nested_cpe():
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:example_vendor:example_product:*:*:*:*:*:*:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert nvd._extract_vendor_product(cve) == ("Example Vendor", "Example Product")


def test_nvd_infers_vendor_product_without_cpe():
    cve = {"configurations": []}
    description = "ExampleCorp Example Product contains an improper access control vulnerability."

    assert nvd._extract_vendor_product(cve, description, []) == (
        "ExampleCorp",
        "Example Product",
    )


def test_nvd_marks_unresolved_when_vendor_product_are_incomplete():
    cve = {"configurations": []}

    assert nvd._extract_vendor_product(
        cve,
        "",
        ["https://security.example.com/advisory/cve-2026-0001"],
    ) == ("Unresolved", "Unresolved")


def test_nvd_skips_unresolved_vendor_product(monkeypatch):
    def fake_fetch_json(url: str, **kwargs):
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-0001",
                        "published": "2026-06-20T00:00:00.000",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "A generic critical vulnerability without product metadata.",
                            }
                        ],
                        "references": [{"url": "https://security.example.com/cve-2026-0001"}],
                        "configurations": [],
                        "metrics": {},
                    }
                }
            ]
        }

    monkeypatch.setattr(nvd, "fetch_json", fake_fetch_json)

    assert nvd.fetch_recent_critical(days=1, api_key="test-key", max_results=1) == []
