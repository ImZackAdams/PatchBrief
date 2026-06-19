from __future__ import annotations

import argparse
import sys
from pathlib import Path

SITE_BASE_URL = "https://www.patchbrief.org"


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
