from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SITE_BASE_URL = "https://www.patchbrief.org"


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


def cmd_build_feed(args: argparse.Namespace) -> None:
    from patchbrief.feed import load_feed_items
    from patchbrief.render.feed import render_feed, render_item_page, render_rss

    content_dir = Path(args.content_dir)
    if not content_dir.is_dir():
        print(f"Error: content directory not found: {content_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading feed items from {content_dir} ...")
    try:
        items = load_feed_items(content_dir)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"  Loaded {len(items)} items")

    # Generate feed.html
    feed_html = render_feed(items)
    feed_path = Path("feed.html")
    feed_path.write_text(feed_html, encoding="utf-8")
    print(f"Generated: {feed_path}")

    # Generate items/{slug}.html
    items_dir = Path("items")
    items_dir.mkdir(exist_ok=True)
    for item in items:
        item_html = render_item_page(item)
        item_path = items_dir / f"{item.slug}.html"
        item_path.write_text(item_html, encoding="utf-8")
        print(f"Generated: {item_path}")

    # Generate rss.xml
    base_url = args.base_url.rstrip("/")
    rss_xml = render_rss(items, base_url)
    rss_path = Path("rss.xml")
    rss_path.write_text(rss_xml, encoding="utf-8")
    print(f"Generated: {rss_path}")

    print(f"\nBuild complete: {len(items)} items, feed.html, rss.xml")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patchbrief",
        description="PatchBrief security intel feed tooling",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ingest-cisa-kev
    p_ingest = subparsers.add_parser(
        "ingest-cisa-kev",
        help="Fetch and normalize the CISA Known Exploited Vulnerabilities catalog.",
    )
    p_ingest.set_defaults(func=cmd_ingest_cisa_kev)

    # build-feed
    p_feed = subparsers.add_parser(
        "build-feed",
        help="Generate feed.html, item pages, and rss.xml from YAML content files.",
    )
    p_feed.add_argument(
        "--content-dir",
        default="content/feed-items",
        metavar="PATH",
        help="Directory containing YAML feed item files (default: content/feed-items).",
    )
    p_feed.add_argument(
        "--base-url",
        default=SITE_BASE_URL,
        metavar="URL",
        help=f"Site base URL for RSS links (default: {SITE_BASE_URL}).",
    )
    p_feed.set_defaults(func=cmd_build_feed)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
