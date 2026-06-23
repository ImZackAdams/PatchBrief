from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

SITE_BASE_URL = "https://www.patchbrief.org"
STATE_FILE = "content/processed-state.json"
SOURCE_STATUS_FILE = "content/source-status.json"
PUBLIC_WINDOW_DAYS = 365

SOURCE_LABELS = {
    "cisa_kev": "CISA Known Exploited Vulnerabilities",
    "nvd": "NVD critical CVEs",
    "github_advisory": "GitHub Security Advisories",
    "epss": "FIRST EPSS enrichment",
}


# ---------------------------------------------------------------------------
# build-feed command
# ---------------------------------------------------------------------------

def cmd_build_feed(args: argparse.Namespace) -> None:
    import json as _json
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
    source_status = _load_source_status(Path(args.source_status_file))

    if args.public_window_days < 0:
        print("Error: --public-window-days must be 0 or greater.", file=sys.stderr)
        sys.exit(1)

    public_items = _filter_public_items(items, args.public_window_days)
    if len(public_items) != len(items):
        print(
            f"  Public feed window: {len(public_items)} current items "
            f"({len(items) - len(public_items)} archived)"
        )

    feed_html = render_feed(public_items)
    Path("feed.html").write_text(feed_html, encoding="utf-8")
    print("Generated: feed.html")

    items_dir = Path("items")
    items_dir.mkdir(exist_ok=True)
    for item in items:
        item_html = render_item_page(item)
        (items_dir / f"{item.slug}.html").write_text(item_html, encoding="utf-8")
        print(f"Generated: items/{item.slug}.html")

    rss_xml = render_rss(public_items, base_url)
    Path("rss.xml").write_text(rss_xml, encoding="utf-8")
    print("Generated: rss.xml")

    sitemap_xml = render_sitemap(public_items, base_url)
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
        "total_items": len(public_items),
        "archived_items": len(items) - len(public_items),
        "public_window_days": args.public_window_days,
        "pipeline": {
            "generated": now,
            "source_count": len(source_status),
            "sources": source_status,
        },
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
            for item in public_items
        ],
    }
    Path("feed.json").write_text(
        _json.dumps(feed_data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("Generated: feed.json")

    print(
        f"\nBuild complete: {len(public_items)} current items "
        f"({len(items)} total) → feed.html, rss.xml, feed.json, sitemap.xml"
    )


# ---------------------------------------------------------------------------
# ingest command
# ---------------------------------------------------------------------------

def cmd_ingest(args: argparse.Namespace) -> None:
    from patchbrief.ingest.cisa_kev import fetch_recent_kev
    from patchbrief.ingest.epss import fetch_epss_scores
    from patchbrief.ingest.github_advisories import fetch_recent_github_advisories
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

    source_names = _resolve_sources(args.sources, kev_only=args.kev_only)
    source_runs = []
    source_items = []

    if "cisa_kev" in source_names:
        print(f"\nFetching CISA KEV (last {args.days} days)...")
        started = _utc_now()
        try:
            kev_items = fetch_recent_kev(days=args.days)
            print(f"  {len(kev_items)} KEV entries found")
            source_items.extend(kev_items)
            source_runs.append(_source_run("cisa_kev", "ok", len(kev_items), started))
        except Exception as exc:
            print(f"  KEV fetch failed: {exc}", file=sys.stderr)
            source_runs.append(_source_run("cisa_kev", "failed", 0, started, str(exc)))

    if "nvd" in source_names:
        nvd_api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY", "") or None
        print(f"\nFetching NVD CRITICAL CVEs (last {args.days} days)...")
        started = _utc_now()
        try:
            nvd_items = fetch_recent_critical(
                days=args.days,
                api_key=nvd_api_key,
                max_results=args.max_nvd,
            )
            print(f"  {len(nvd_items)} critical NVD CVEs found")
            source_items.extend(nvd_items)
            source_runs.append(_source_run("nvd", "ok", len(nvd_items), started))
        except Exception as exc:
            print(f"  NVD fetch failed: {exc}", file=sys.stderr)
            source_runs.append(_source_run("nvd", "failed", 0, started, str(exc)))

    if "github_advisory" in source_names:
        github_token = args.github_token or os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GH_TOKEN", "") or None
        print(f"\nFetching GitHub Security Advisories (last {args.days} days)...")
        started = _utc_now()
        try:
            github_items = fetch_recent_github_advisories(
                days=args.days,
                token=github_token,
                max_results=args.max_github,
            )
            print(f"  {len(github_items)} GitHub advisories found")
            source_items.extend(github_items)
            source_runs.append(_source_run("github_advisory", "ok", len(github_items), started))
        except Exception as exc:
            print(f"  GitHub advisory fetch failed: {exc}", file=sys.stderr)
            source_runs.append(_source_run("github_advisory", "failed", 0, started, str(exc)))

    # Dedupe by primary ID; source order gives KEV priority over appsec and NVD records.
    seen: set[str] = set()
    combined = []
    for vuln in sorted(source_items, key=_source_priority):
        key = vuln.cve_id.upper()
        if key not in seen:
            seen.add(key)
            combined.append(vuln)

    if args.enrich_epss and combined:
        cve_ids = [v.cve_id for v in combined if v.is_cve]
        print(f"\nFetching FIRST EPSS scores for {len(cve_ids)} CVEs...")
        started = _utc_now()
        try:
            epss_scores = fetch_epss_scores(cve_ids)
            for vuln in combined:
                score = epss_scores.get(vuln.cve_id.upper())
                if score:
                    vuln.epss_score = score.epss
                    vuln.epss_percentile = score.percentile
            print(f"  {len(epss_scores)} EPSS scores applied")
            source_runs.append(_source_run("epss", "ok", len(epss_scores), started, role="enrichment"))
        except Exception as exc:
            print(f"  EPSS enrichment failed: {exc}", file=sys.stderr)
            source_runs.append(_source_run("epss", "failed", 0, started, str(exc), role="enrichment"))

    new_items = [v for v in combined if not state.is_processed(v.cve_id)]
    print(f"\n{len(new_items)} new items to process")

    if not new_items:
        _write_source_status(Path(args.source_status_file), source_runs)
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
                "external_id": vuln.cve_id,
                "source": vuln.source,
                "date": vuln.date_added or _today(),
                "type": brief["type"],
                "signal": brief["signal"],
                "title": brief["title"],
                "summary": brief["summary"],
                "vendor": vuln.vendor,
                "product": vuln.product,
                "cve": vuln.cve_id if vuln.is_cve else None,
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
    _write_source_status(Path(args.source_status_file), source_runs)
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
# validate command
# ---------------------------------------------------------------------------

def cmd_validate(args: argparse.Namespace) -> None:
    from patchbrief.feed import load_feed_items

    content_dir = Path(args.content_dir)
    if not content_dir.is_dir():
        print(f"Error: content directory not found: {content_dir}", file=sys.stderr)
        sys.exit(1)

    try:
        items = load_feed_items(content_dir)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    duplicate_slugs = _duplicates([item.slug for item in items])
    duplicate_ids = _duplicates([item.id for item in items])
    if duplicate_slugs or duplicate_ids:
        if duplicate_slugs:
            print(f"Duplicate slugs: {', '.join(duplicate_slugs)}", file=sys.stderr)
        if duplicate_ids:
            print(f"Duplicate ids: {', '.join(duplicate_ids)}", file=sys.stderr)
        sys.exit(1)

    source_status = _load_source_status(Path(args.source_status_file))
    if not source_status:
        print(f"Warning: no source status found at {args.source_status_file}", file=sys.stderr)

    print(f"Validation passed: {len(items)} feed items, {len(source_status)} source records")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bootstrap_state(content_dir: Path, state: "ProcessedState") -> None:
    """Scan existing YAML files and mark source IDs as already processed."""
    added = 0
    for yml in content_dir.glob("*.yml"):
        try:
            with open(yml, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            source_id = None
            if isinstance(data, dict):
                source_id = data.get("cve") or data.get("external_id")
            if source_id and not state.is_processed(str(source_id)):
                state.mark_processed(str(source_id))
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
    seen_urls: set[str] = set()

    def add_source(title: str, url: str) -> None:
        if url and url.startswith("http") and url not in seen_urls:
            sources.append({"title": title, "url": url})
            seen_urls.add(url)

    if vuln.source_url:
        add_source(vuln.source_title or SOURCE_LABELS.get(vuln.source, vuln.source), vuln.source_url)
    if vuln.source == "cisa_kev":
        add_source("CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    if vuln.is_cve:
        add_source(f"NVD — {vuln.cve_id}", f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}")
    for ref in (vuln.references or [])[:2]:
        add_source("Source reference", ref)
    return sources


def _make_tags(vuln: "RawVuln", brief: dict) -> list[str]:
    tags = [vuln.cve_id.lower()]
    type_tag = brief.get("type", "").lower().replace(" ", "-")
    if type_tag:
        tags.append(type_tag)
    vendor_tag = re.sub(r"[^a-z0-9]+", "-", vuln.vendor.lower()).strip("-")
    if vendor_tag:
        tags.append(vendor_tag)
    source_tag = vuln.source.lower().replace("_", "-")
    if source_tag:
        tags.append(source_tag)
    if vuln.epss_percentile is not None and vuln.epss_percentile >= 0.95:
        tags.append("high-epss")
    return tags


def _resolve_sources(raw_sources: str, *, kev_only: bool = False) -> list[str]:
    if kev_only:
        return ["cisa_kev"]
    allowed = {"cisa_kev", "nvd", "github_advisory"}
    requested = [
        source.strip().lower().replace("-", "_")
        for source in raw_sources.split(",")
        if source.strip()
    ]
    invalid = [source for source in requested if source not in allowed]
    if invalid:
        raise SystemExit(f"Invalid source(s): {', '.join(invalid)}. Valid sources: {', '.join(sorted(allowed))}")
    return requested or ["cisa_kev", "nvd", "github_advisory"]


def _source_priority(vuln: "RawVuln") -> tuple[int, str]:
    priority = {
        "cisa_kev": 0,
        "github_advisory": 1,
        "nvd": 2,
    }
    return (priority.get(vuln.source, 9), vuln.cve_id)


def _source_run(
    source_id: str,
    status: str,
    item_count: int,
    started_at: str,
    error: str | None = None,
    *,
    role: str = "source",
) -> dict:
    run = {
        "id": source_id,
        "label": SOURCE_LABELS.get(source_id, source_id),
        "role": role,
        "status": status,
        "items_seen": item_count,
        "started_at": started_at,
        "finished_at": _utc_now(),
    }
    if error:
        run["error"] = error[:240]
    return run


def _write_source_status(path: Path, source_runs: list[dict]) -> None:
    if not source_runs:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": _utc_now(),
        "sources": source_runs,
    }
    import json
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _load_source_status(path: Path) -> list[dict]:
    if not path.exists():
        return []
    import json
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    sources = data.get("sources", [])
    return sources if isinstance(sources, list) else []


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    repeated: set[str] = set()
    for value in values:
        if value in seen:
            repeated.add(value)
        seen.add(value)
    return sorted(repeated)


def _filter_public_items(items: list, window_days: int) -> list:
    if window_days < 0:
        raise ValueError("window_days must be 0 or greater")
    if window_days == 0:
        return items
    from datetime import date, timedelta

    cutoff = (date.today() - timedelta(days=window_days)).isoformat()
    return [item for item in items if item.date >= cutoff]


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    p_feed.add_argument(
        "--source-status-file",
        default=SOURCE_STATUS_FILE,
        metavar="PATH",
        help=f"Source health metadata JSON (default: {SOURCE_STATUS_FILE}).",
    )
    p_feed.add_argument(
        "--public-window-days",
        type=int,
        default=PUBLIC_WINDOW_DAYS,
        metavar="N",
        help=(
            "Only publish feed/RSS/JSON/sitemap items from the last N days. "
            f"Use 0 to include all items (default: {PUBLIC_WINDOW_DAYS})."
        ),
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
        "--github-token",
        default="",
        metavar="TOKEN",
        help="GitHub token for advisory API rate limits (default: GITHUB_TOKEN or GH_TOKEN env var).",
    )
    p_ingest.add_argument(
        "--sources",
        default="cisa_kev,nvd,github_advisory",
        metavar="LIST",
        help="Comma-separated ingestion sources: cisa_kev,nvd,github_advisory.",
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
    p_ingest.add_argument(
        "--max-github",
        type=int,
        default=30,
        metavar="N",
        help="Maximum GitHub advisories per run (default: 30).",
    )
    p_ingest.add_argument(
        "--no-epss",
        action="store_false",
        dest="enrich_epss",
        help="Skip FIRST EPSS enrichment.",
    )
    p_ingest.add_argument(
        "--source-status-file",
        default=SOURCE_STATUS_FILE,
        metavar="PATH",
        help=f"Source health metadata JSON (default: {SOURCE_STATUS_FILE}).",
    )
    p_ingest.set_defaults(enrich_epss=True)
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

    # validate
    p_validate = subparsers.add_parser(
        "validate",
        help="Validate feed content and pipeline metadata without writing generated files.",
    )
    p_validate.add_argument(
        "--content-dir",
        default="content/feed-items",
        metavar="PATH",
        help="Directory containing YAML feed item files (default: content/feed-items).",
    )
    p_validate.add_argument(
        "--source-status-file",
        default=SOURCE_STATUS_FILE,
        metavar="PATH",
        help=f"Source health metadata JSON (default: {SOURCE_STATUS_FILE}).",
    )
    p_validate.set_defaults(func=cmd_validate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
