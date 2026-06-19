from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def cmd_generate_brief(args: argparse.Namespace) -> None:
    from patchbrief.advisories import filter_by_cadence, load_advisories, match_advisories
    from patchbrief.models import Brief
    from patchbrief.render.html import render_brief
    from patchbrief.watchlist import load_watchlist

    # Load watchlist
    try:
        watchlist = load_watchlist(args.watchlist)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"Error loading watchlist: {exc}", file=sys.stderr)
        sys.exit(1)

    matches: list = []
    omitted: list = []
    advisories_reviewed = 0
    source_names: list[str] = []

    if args.source:
        try:
            advisories = load_advisories(args.source)
        except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
            print(f"Error loading advisories: {exc}", file=sys.stderr)
            sys.exit(1)

        advisories_reviewed = len(advisories)
        source_names = list({a.source for a in advisories})
        all_matches = match_advisories(watchlist, advisories)
        matches, omitted = filter_by_cadence(all_matches, watchlist.cadence)

    brief = Brief(
        generated_at=datetime.now(),
        watchlist=watchlist,
        advisories_reviewed=advisories_reviewed,
        matches=matches,
        source_names=source_names,
    )

    html = render_brief(brief, omitted=omitted)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")

    print(f"Brief written to: {out_path}")
    print(f"  Advisories reviewed: {advisories_reviewed}")
    print(f"  Matches included:    {len(matches)}")
    if omitted:
        print(f"  Matches omitted:     {len(omitted)} (cadence: {watchlist.cadence})")


def cmd_ingest_cisa_kev(args: argparse.Namespace) -> None:
    import requests

    raw_dir = Path("data/raw")
    normalized_dir = Path("data/normalized")

    try:
        raw_dir.mkdir(parents=True, exist_ok=True)
        normalized_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Error creating data directories: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching CISA KEV from {CISA_KEV_URL} ...")

    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        raw_data = response.json()
    except requests.exceptions.Timeout:
        print("Error: request timed out after 30 seconds.", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.ConnectionError as exc:
        print(f"Error: connection failed — {exc}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Error: could not parse JSON response — {exc}", file=sys.stderr)
        sys.exit(1)

    # Save raw
    raw_path = raw_dir / "cisa-kev.json"
    try:
        raw_path.write_text(json.dumps(raw_data, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"Error writing raw data: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Raw data saved to: {raw_path}")

    # Normalize
    vulnerabilities = raw_data.get("vulnerabilities", [])
    normalized: list[dict] = []

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID", "")
        references = vuln.get("references", [])
        if references and isinstance(references, list):
            source_url = references[0] if isinstance(references[0], str) else CISA_KEV_URL
        else:
            source_url = CISA_KEV_URL

        record = {
            "id": cve_id or vuln.get("vulnerabilityName", "unknown"),
            "source": "CISA KEV",
            "source_url": source_url,
            "cve": cve_id or None,
            "vendor": vuln.get("vendorProject", ""),
            "product": vuln.get("product", ""),
            "title": vuln.get("vulnerabilityName", ""),
            "description": vuln.get("shortDescription", ""),
            "known_exploited": True,
            "published_date": vuln.get("dateAdded"),
            "updated_date": None,
            "due_date": vuln.get("dueDate"),
            "severity": "critical",
            "raw": vuln,
        }
        normalized.append(record)

    normalized_path = normalized_dir / "cisa-kev.json"
    try:
        normalized_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"Error writing normalized data: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Normalized data saved to: {normalized_path}")
    print(f"  Total records: {len(normalized)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patchbrief",
        description="PatchBrief — vulnerability watchlist monitoring tool",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-brief
    p_gen = subparsers.add_parser(
        "generate-brief",
        help="Generate an HTML brief from a watchlist and optional advisory source.",
    )
    p_gen.add_argument(
        "--watchlist",
        required=True,
        metavar="PATH",
        help="Path to the YAML watchlist file.",
    )
    p_gen.add_argument(
        "--source",
        metavar="PATH",
        default=None,
        help="Path to a normalized advisories JSON file (optional).",
    )
    p_gen.add_argument(
        "--out",
        required=True,
        metavar="PATH",
        help="Output path for the generated HTML brief.",
    )
    p_gen.set_defaults(func=cmd_generate_brief)

    # ingest-cisa-kev
    p_ingest = subparsers.add_parser(
        "ingest-cisa-kev",
        help="Fetch and normalize the CISA Known Exploited Vulnerabilities catalog.",
    )
    p_ingest.set_defaults(func=cmd_ingest_cisa_kev)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
