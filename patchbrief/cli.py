from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SITE_BASE_URL = "https://www.patchbrief.org"


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


def cmd_send_brief(args: argparse.Namespace) -> None:
    import os

    from patchbrief.advisories import filter_by_cadence, load_advisories, match_advisories
    from patchbrief.email import send_brief
    from patchbrief.models import Brief
    from patchbrief.render.html import render_brief
    from patchbrief.watchlist import load_watchlist

    api_key = args.resend_key or os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        print("Error: --resend-key or RESEND_API_KEY env var required.", file=sys.stderr)
        sys.exit(1)

    try:
        watchlist = load_watchlist(args.watchlist)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"Error loading watchlist: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        advisories = load_advisories(args.source)
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        print(f"Error loading advisories: {exc}", file=sys.stderr)
        sys.exit(1)

    all_matches = match_advisories(watchlist, advisories)
    included, omitted = filter_by_cadence(all_matches, watchlist.cadence)

    if not included:
        print(f"No matches for {watchlist.owner_email} (cadence: {watchlist.cadence}) — skipping.")
        return

    brief = Brief(
        generated_at=datetime.now(),
        watchlist=watchlist,
        advisories_reviewed=len(advisories),
        matches=included,
        source_names=list({m.advisory.source for m in included}),
    )
    html = render_brief(brief, omitted=omitted)

    count = len(included)
    subject = f"PatchBrief — {count} advisor{'y' if count == 1 else 'ies'} matched your watchlist"

    try:
        result = send_brief(
            html=html,
            to=watchlist.owner_email,
            subject=subject,
            from_address=args.from_email,
            api_key=api_key,
        )
    except RuntimeError as exc:
        print(f"Error sending email: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Sent to {watchlist.owner_email}: {result.get('id', 'ok')}")


def cmd_create_watchlist(args: argparse.Namespace) -> None:
    import yaml

    terms = [t.strip() for t in args.terms.split(",") if t.strip()]
    if not terms:
        print("Error: --terms must include at least one term.", file=sys.stderr)
        sys.exit(1)

    data = {
        "name": args.name,
        "owner_email": args.email,
        "cadence": args.cadence,
        "terms": terms,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"Watchlist written to {out_path}")
    print(f"  Owner: {args.email}")
    print(f"  Terms: {', '.join(terms)}")
    print(f"  Cadence: {args.cadence}")


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
        description="PatchBrief public feed and watchlist tooling",
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

    # send-brief
    p_send = subparsers.add_parser(
        "send-brief",
        help="Generate a brief and email it to the watchlist owner via Resend.",
    )
    p_send.add_argument("--watchlist", required=True, metavar="PATH")
    p_send.add_argument("--source", required=True, metavar="PATH")
    p_send.add_argument("--resend-key", default=None, metavar="KEY",
                        help="Resend API key (or set RESEND_API_KEY env var).")
    p_send.add_argument("--from-email", default="briefs@patchbrief.org", metavar="EMAIL")
    p_send.set_defaults(func=cmd_send_brief)

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

    # create-watchlist
    p_create = subparsers.add_parser(
        "create-watchlist",
        help="Write a subscriber watchlist YAML from CLI arguments.",
    )
    p_create.add_argument("--name", required=True, metavar="SLUG",
                          help="Watchlist slug, e.g. acme-corp")
    p_create.add_argument("--email", required=True, metavar="EMAIL")
    p_create.add_argument("--terms", required=True, metavar="TERMS",
                          help="Comma-separated watchlist terms.")
    p_create.add_argument("--cadence", required=True,
                          choices=["important_only", "weekly", "monthly"])
    p_create.add_argument("--out", required=True, metavar="PATH",
                          help="Output path for the YAML file.")
    p_create.set_defaults(func=cmd_create_watchlist)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
