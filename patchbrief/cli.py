from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import yaml

SITE_BASE_URL = "https://www.patchbrief.org"
STATE_FILE = "content/processed-state.json"


# ---------------------------------------------------------------------------
# build-feed command
# ---------------------------------------------------------------------------

def cmd_build_feed(args: argparse.Namespace) -> None:
    import json as _json
    from datetime import datetime, timezone
    from patchbrief.feed import load_feed_items
    from patchbrief.render.feed import (
        render_feed,
        render_item_page,
        render_rss,
        render_sitemap,
    )

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

    base_url = args.base_url.rstrip("/")

    feed_html = render_feed(items)
    Path("feed.html").write_text(feed_html, encoding="utf-8")
    print("Generated: feed.html")

    items_dir = Path("items")
    items_dir.mkdir(exist_ok=True)
    for item in items:
        item_html = render_item_page(item)
        (items_dir / f"{item.slug}.html").write_text(item_html, encoding="utf-8")
        print(f"Generated: items/{item.slug}.html")

    rss_xml = render_rss(items, base_url)
    Path("rss.xml").write_text(rss_xml, encoding="utf-8")
    print("Generated: rss.xml")

    sitemap_xml = render_sitemap(items, base_url)
    Path("sitemap.xml").write_text(sitemap_xml, encoding="utf-8")
    print("Generated: sitemap.xml")

    # JSON API feed — the Team-tier product, free tier public preview
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    feed_data = {
        "version": "1.0",
        "title": "PatchBrief Security Intelligence Feed",
        "home_page_url": f"{base_url}/feed.html",
        "feed_url": f"{base_url}/feed.json",
        "description": "Short operator-ready briefs on exploited vulnerabilities, critical advisories, and threat activity.",
        "generated": now,
        "total_items": len(items),
        "items": [
            {
                "id": item.id,
                "slug": item.slug,
                "url": f"{base_url}/items/{item.slug}.html",
                "date": item.date,
                "type": item.type,
                "signal": item.signal,
                "title": item.title,
                "summary": item.summary,
                "vendor": item.vendor,
                "product": item.product,
                "cve": item.cve,
                "operator_check": item.operator_check,
                "why_it_matters": item.why_it_matters,
                "tags": item.tags,
                "sources": [{"title": s.title, "url": s.url} for s in item.sources],
            }
            for item in items
        ],
    }
    Path("feed.json").write_text(
        _json.dumps(feed_data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("Generated: feed.json")

    print(f"\nBuild complete: {len(items)} items → feed.html, rss.xml, feed.json, sitemap.xml")


# ---------------------------------------------------------------------------
# ingest command
# ---------------------------------------------------------------------------

def cmd_ingest(args: argparse.Namespace) -> None:
    from patchbrief.ingest.cisa_kev import fetch_recent_kev
    from patchbrief.ingest.nvd import fetch_recent_critical
    from patchbrief.ingest.state import ProcessedState
    from patchbrief.generate.brief import generate_brief, generate_raw_brief

    use_ai = not getattr(args, "no_ai", False)
    client = None
    if use_ai:
        api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print("Warning: ANTHROPIC_API_KEY not set — using raw brief mode.", file=sys.stderr)
            use_ai = False
        else:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

    mode_label = "AI-enhanced" if use_ai else "raw (no AI)"
    print(f"Ingest mode: {mode_label}")

    content_dir = Path(args.content_dir)
    content_dir.mkdir(parents=True, exist_ok=True)

    state_path = Path(args.state_file)
    state = ProcessedState(state_path)
    print(f"Loaded processed state: {len(state)} known CVEs")

    # Bootstrap: scan existing YAML files and mark their CVEs processed.
    _bootstrap_state(content_dir, state)

    # --- Fetch from CISA KEV ---
    print(f"\nFetching CISA KEV (last {args.days} days)...")
    try:
        kev_items = fetch_recent_kev(days=args.days)
        print(f"  {len(kev_items)} KEV entries found")
    except Exception as exc:
        print(f"  KEV fetch failed: {exc}", file=sys.stderr)
        kev_items = []

    # --- Fetch from NVD ---
    nvd_items = []
    if not args.kev_only:
        nvd_api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY", "") or None
        print(f"\nFetching NVD CRITICAL CVEs (last {args.days} days)...")
        try:
            nvd_items = fetch_recent_critical(
                days=args.days,
                api_key=nvd_api_key,
                max_results=args.max_nvd,
            )
            print(f"  {len(nvd_items)} critical NVD CVEs found")
        except Exception as exc:
            print(f"  NVD fetch failed: {exc}", file=sys.stderr)

    # Dedupe by CVE ID; KEV takes priority over NVD.
    seen: set[str] = set()
    combined = []
    for vuln in kev_items + nvd_items:
        key = vuln.cve_id.upper()
        if key not in seen:
            seen.add(key)
            combined.append(vuln)

    new_items = [v for v in combined if not state.is_processed(v.cve_id)]
    print(f"\n{len(new_items)} new items to process")

    if not new_items:
        print("Nothing new — exiting.")
        return

    generated = 0
    for vuln in new_items:
        print(f"  [{vuln.source}] {vuln.cve_id}...")
        try:
            if use_ai and client is not None:
                brief = generate_brief(vuln, client)
            else:
                brief = generate_raw_brief(vuln)
            slug = _make_slug(vuln)
            yaml_path = content_dir / f"{slug}.yml"

            sources = _build_sources(vuln)
            item_data = {
                "id": slug,
                "slug": slug,
                "date": vuln.date_added or _today(),
                "type": brief["type"],
                "signal": brief["signal"],
                "title": brief["title"],
                "summary": brief["summary"],
                "vendor": vuln.vendor,
                "product": vuln.product,
                "cve": vuln.cve_id,
                "operator_check": brief["operator_check"],
                "why_it_matters": brief["why_it_matters"],
                "sources": sources,
                "tags": _make_tags(vuln, brief),
                "is_sample": False,
            }

            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump(item_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

            state.mark_processed(vuln.cve_id)
            generated += 1
            print(f"    Created: {yaml_path}")

        except Exception as exc:
            print(f"    Error processing {vuln.cve_id}: {exc}", file=sys.stderr)

    state.save()
    print(f"\nIngest complete: {generated} new briefs created")


# ---------------------------------------------------------------------------
# digest command
# ---------------------------------------------------------------------------

def cmd_digest(args: argparse.Namespace) -> None:
    from datetime import date, timedelta
    from patchbrief.feed import load_feed_items
    from patchbrief.generate.digest import render_digest

    content_dir = Path(args.content_dir)
    if not content_dir.is_dir():
        print(f"Error: content directory not found: {content_dir}", file=sys.stderr)
        sys.exit(1)

    try:
        all_items = load_feed_items(content_dir)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    cutoff = (date.today() - timedelta(days=args.days)).isoformat()
    items = [it for it in all_items if it.date >= cutoff]

    if not items:
        print(f"No items found in the last {args.days} days. Try --days 30.")
        sys.exit(0)

    html = render_digest(
        items,
        issue=args.issue,
        base_url=args.base_url.rstrip("/"),
        max_items=args.max_items,
        label=args.label,
    )

    out = Path(args.output)
    out.write_text(html, encoding="utf-8")
    print(f"Digest generated: {out}  ({len(items)} items in window, {min(len(items), args.max_items)} included)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bootstrap_state(content_dir: Path, state: "ProcessedState") -> None:
    """Scan existing YAML files and mark any CVE IDs as already processed."""
    added = 0
    for yml in content_dir.glob("*.yml"):
        try:
            with open(yml, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            cve = data.get("cve") if isinstance(data, dict) else None
            if cve and not state.is_processed(str(cve)):
                state.mark_processed(str(cve))
                added += 1
        except Exception:
            pass
    if added:
        print(f"  Bootstrapped {added} CVEs from existing YAML files")


def _make_slug(vuln: "RawVuln") -> str:
    date_prefix = (vuln.date_added or _today())[:7]  # YYYY-MM
    vendor_slug = re.sub(r"[^a-z0-9]+", "-", vuln.vendor.lower()).strip("-")[:20]
    cve_slug = vuln.cve_id.lower()
    return f"{date_prefix}-{vendor_slug}-{cve_slug}"


def _today() -> str:
    from datetime import date
    return date.today().isoformat()


def _build_sources(vuln: "RawVuln") -> list[dict]:
    sources = []
    if vuln.source == "cisa_kev":
        sources.append({
            "title": "CISA KEV catalog",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        })
    sources.append({
        "title": f"NVD — {vuln.cve_id}",
        "url": f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}",
    })
    for ref in (vuln.references or [])[:2]:
        if ref.startswith("http"):
            sources.append({"title": "Vendor reference", "url": ref})
    return sources


def _make_tags(vuln: "RawVuln", brief: dict) -> list[str]:
    tags = [vuln.cve_id.lower()]
    type_tag = brief.get("type", "").lower().replace(" ", "-")
    if type_tag:
        tags.append(type_tag)
    vendor_tag = re.sub(r"[^a-z0-9]+", "-", vuln.vendor.lower()).strip("-")
    if vendor_tag:
        tags.append(vendor_tag)
    return tags


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

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

    # ingest
    p_ingest = subparsers.add_parser(
        "ingest",
        help="Fetch new vulnerabilities and generate AI briefs.",
    )
    p_ingest.add_argument(
        "--content-dir",
        default="content/feed-items",
        metavar="PATH",
        help="Directory to write generated YAML feed items (default: content/feed-items).",
    )
    p_ingest.add_argument(
        "--state-file",
        default=STATE_FILE,
        metavar="PATH",
        help=f"JSON file tracking processed CVE IDs (default: {STATE_FILE}).",
    )
    p_ingest.add_argument(
        "--days",
        type=int,
        default=30,
        metavar="N",
        help="Look back N days for new vulnerabilities (default: 30).",
    )
    p_ingest.add_argument(
        "--api-key",
        default="",
        metavar="KEY",
        help="Anthropic API key (default: ANTHROPIC_API_KEY env var).",
    )
    p_ingest.add_argument(
        "--nvd-api-key",
        default="",
        metavar="KEY",
        help="NVD API key for higher rate limits (default: NVD_API_KEY env var).",
    )
    p_ingest.add_argument(
        "--kev-only",
        action="store_true",
        help="Only fetch from CISA KEV, skip NVD.",
    )
    p_ingest.add_argument(
        "--no-ai",
        action="store_true",
        dest="no_ai",
        help="Build briefs from raw source fields only (no Claude API call).",
    )
    p_ingest.add_argument(
        "--max-nvd",
        type=int,
        default=20,
        metavar="N",
        help="Maximum NVD results per run (default: 20).",
    )
    p_ingest.set_defaults(func=cmd_ingest)

    # digest
    p_digest = subparsers.add_parser(
        "digest",
        help="Generate an HTML email digest from recent feed items.",
    )
    p_digest.add_argument(
        "--content-dir",
        default="content/feed-items",
        metavar="PATH",
        help="Directory containing YAML feed item files (default: content/feed-items).",
    )
    p_digest.add_argument(
        "--days",
        type=int,
        default=7,
        metavar="N",
        help="Include items published in the last N days (default: 7).",
    )
    p_digest.add_argument(
        "--max-items",
        type=int,
        default=8,
        metavar="N",
        help="Maximum number of items to include (default: 8).",
    )
    p_digest.add_argument(
        "--issue",
        type=int,
        default=1,
        metavar="N",
        help="Issue number shown in the digest header (default: 1).",
    )
    p_digest.add_argument(
        "--label",
        default="Weekly",
        metavar="LABEL",
        help="Digest label, e.g. Weekly or Daily (default: Weekly).",
    )
    p_digest.add_argument(
        "--output",
        default="digest.html",
        metavar="PATH",
        help="Output file path (default: digest.html).",
    )
    p_digest.add_argument(
        "--base-url",
        default=SITE_BASE_URL,
        metavar="URL",
        help=f"Site base URL for links (default: {SITE_BASE_URL}).",
    )
    p_digest.set_defaults(func=cmd_digest)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
