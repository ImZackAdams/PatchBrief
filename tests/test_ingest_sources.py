from __future__ import annotations

from datetime import date
from pathlib import Path

from patchbrief.cli import (
    _build_sources,
    _filter_public_items,
    _load_source_status,
    _resolve_sources,
    _write_source_status,
)
from patchbrief.generate.brief import _validate_and_fix, generate_raw_brief
from patchbrief.ingest import cert_vu, epss, exploitdb, github_advisories, msrc, nvd
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
    assert _resolve_sources("") == [
        "cisa_kev",
        "msrc",
        "github_advisory",
        "nvd",
        "cert_vu",
        "exploitdb",
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


def test_cert_vu_atom_maps_coordinated_disclosure():
    xml = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>VU#936962: Multiple file parsing vulnerabilities in FastStone Image Viewer 8.3.0.0</title>
    <link href="https://kb.cert.org/vuls/id/936962" rel="alternate"/>
    <published>2026-06-22T18:41:47+00:00</published>
    <summary type="html">&lt;p&gt;&lt;strong&gt;CVE-2026-30040&lt;/strong&gt; A critical heap-based buffer overflow vulnerability exists in FastStone Image Viewer.&lt;/p&gt;</summary>
  </entry>
</feed>"""

    items = cert_vu._parse_cert_atom(xml, cutoff=date(2026, 6, 1), max_results=5)

    assert len(items) == 1
    assert items[0].source == "cert_vu"
    assert items[0].cve_id == "VU-936962"
    assert items[0].vendor == "FastStone"
    assert items[0].product == "Image Viewer 8.3.0.0"
    assert "CVE-2026-30040" in items[0].description


def test_cert_vu_infers_multi_vendor_uefi_title():
    vendor, product = cert_vu._infer_vendor_product(
        "VU#457458: Vendor-signed UEFI applications found vulnerable to Secure Boot bypass",
        "",
    )

    assert vendor == "Multiple vendors"
    assert product == "Vendor-signed UEFI applications"


def test_raw_brief_for_cert_vu_uses_coordinated_disclosure_type():
    vuln = RawVuln(
        source="cert_vu",
        cve_id="VU-936962",
        vendor="FastStone",
        product="Image Viewer",
        description="CERT/CC published a coordinated disclosure note.",
        date_added="2026-06-22",
        vulnerability_name="VU#936962: FastStone Image Viewer parsing vulnerabilities",
    )

    brief = generate_raw_brief(vuln)

    assert brief["type"] == "Coordinated disclosure"
    assert brief["signal"] == "Patch review"
    assert "CERT/CC" in brief["operator_check"]


def test_ai_label_validation_falls_back_to_source_aware_type():
    vuln = RawVuln(
        source="cert_vu",
        cve_id="VU-936962",
        vendor="FastStone",
        product="Image Viewer",
        description="CERT/CC published a coordinated disclosure note.",
        date_added="2026-06-22",
    )

    brief = _validate_and_fix(
        {
            "title": "CERT/CC note",
            "summary": "Public note.",
            "operator_check": "Review vendor guidance.",
            "why_it_matters": "Coordinated disclosure.",
            "signal": "bad signal",
            "type": "bad type",
        },
        vuln,
    )

    assert brief["type"] == "Coordinated disclosure"
    assert brief["signal"] == "Patch review"


def test_msrc_filters_recent_security_updates_and_parses_high_signal_cves():
    updates = {
        "value": [
            {
                "ID": "2026-Jun",
                "DocumentTitle": "June 2026 Security Updates",
                "InitialReleaseDate": "2026-06-09T07:00:00Z",
                "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun",
            },
            {
                "ID": "2026-Jan",
                "DocumentTitle": "January 2026 Security Updates",
                "InitialReleaseDate": "2026-01-13T08:00:00Z",
                "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jan",
            },
        ]
    }
    recent = msrc._recent_security_updates(updates, cutoff=date(2026, 6, 1))

    assert [item["ID"] for item in recent] == ["2026-Jun"]

    xml = """<?xml version="1.0"?>
<cvrf:cvrfdoc xmlns:vuln="http://www.icasi.org/CVRF/schema/vuln/1.1" xmlns:cvrf="http://www.icasi.org/CVRF/schema/cvrf/1.1">
  <vuln:Vulnerability>
    <vuln:Title>Windows TCP/IP Remote Code Execution Vulnerability</vuln:Title>
    <vuln:Notes>
      <vuln:Note Title="Description" Type="Description" Ordinal="0">&lt;p&gt;Improper input validation in Windows TCP/IP allows remote code execution.&lt;/p&gt;</vuln:Note>
      <vuln:Note Title="Windows TCP/IP" Type="Tag" Ordinal="20">Windows TCP/IP</vuln:Note>
    </vuln:Notes>
    <vuln:CVE>CVE-2026-42904</vuln:CVE>
    <vuln:Threats>
      <vuln:Threat Type="Severity"><vuln:Description>Critical</vuln:Description></vuln:Threat>
      <vuln:Threat Type="Exploit Status"><vuln:Description>Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Unlikely</vuln:Description></vuln:Threat>
    </vuln:Threats>
    <vuln:CVSSScoreSets>
      <vuln:ScoreSet><vuln:BaseScore>9.6</vuln:BaseScore></vuln:ScoreSet>
    </vuln:CVSSScoreSets>
    <vuln:Remediations>
      <vuln:Remediation Type="Vendor Fix"><vuln:URL>https://catalog.update.microsoft.com/example</vuln:URL></vuln:Remediation>
    </vuln:Remediations>
  </vuln:Vulnerability>
</cvrf:cvrfdoc>"""

    items = msrc._parse_cvrf(
        xml,
        release_id="2026-Jun",
        release_title="June 2026 Security Updates",
        release_date="2026-06-09",
        min_cvss=8.8,
        remaining=5,
    )

    assert len(items) == 1
    assert items[0].source == "msrc"
    assert items[0].cve_id == "CVE-2026-42904"
    assert items[0].vendor == "Microsoft"
    assert items[0].product == "Windows TCP/IP"
    assert items[0].cvss_score == 9.6


def test_raw_brief_for_msrc_uses_patch_tuesday_type():
    vuln = RawVuln(
        source="msrc",
        cve_id="CVE-2026-42904",
        vendor="Microsoft",
        product="Windows TCP/IP",
        description="Improper input validation allows remote code execution.",
        date_added="2026-06-09",
        vulnerability_name="Windows TCP/IP Remote Code Execution Vulnerability",
        cvss_score=9.6,
    )

    brief = generate_raw_brief(vuln)

    assert brief["type"] == "Patch Tuesday"
    assert brief["signal"] == "Critical vendor advisory"
    assert "Microsoft Security Update Guide" in brief["operator_check"]


def test_exploitdb_csv_maps_verified_recent_exploits():
    csv_text = """id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url
53000,exploits/windows/remote/53000.py,"ExampleApp Server 2.0 - Remote Code Execution",2026-06-22,Researcher,remote,windows,,2026-06-22,2026-06-22,1,CVE-2026-55555,,,,,https://example.com/advisory
52999,exploits/windows/dos/52999.py,"OldApp 1.0 - Crash",2026-01-01,Researcher,dos,windows,,2026-01-01,2026-01-01,1,CVE-2026-11111,,,,,
"""

    items = exploitdb._parse_exploitdb_csv(
        csv_text,
        cutoff=date(2026, 6, 1),
        max_results=5,
    )

    assert len(items) == 1
    assert items[0].source == "exploitdb"
    assert items[0].cve_id == "CVE-2026-55555"
    assert items[0].vendor == "ExampleApp"
    assert items[0].product == "Server"
    assert items[0].source_url == "https://www.exploit-db.com/exploits/53000"


def test_raw_brief_for_exploitdb_uses_exploit_activity_type():
    vuln = RawVuln(
        source="exploitdb",
        cve_id="CVE-2026-55555",
        vendor="ExampleApp",
        product="Server",
        description="Exploit-DB published a verified remote entry.",
        date_added="2026-06-22",
        vulnerability_name="ExampleApp Server 2.0 - Remote Code Execution",
    )

    brief = generate_raw_brief(vuln)

    assert brief["type"] == "Exploit activity"
    assert brief["signal"] == "Threat activity"
    assert "public exploit availability" in brief["operator_check"]


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
