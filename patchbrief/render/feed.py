from __future__ import annotations

import html
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from xml.sax.saxutils import escape as xml_escape

from patchbrief.feed import FeedItem
from patchbrief.monetization import paid_cta_url

_TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"


def _load_template(name: str) -> string.Template:
    path = _TEMPLATES_DIR / name
    return string.Template(path.read_text(encoding="utf-8"))


def _esc(value: Optional[str]) -> str:
    return html.escape(str(value or ""))


def _render_signal_badge(item: FeedItem) -> str:
    return (
        f'<span class="signal-badge {_esc(item.signal_class)}">'
        f"{_esc(item.signal)}</span>"
    )


def _render_type_badge(item: FeedItem) -> str:
    return f'<span class="type-badge">{_esc(item.type)}</span>'


def _render_cve_tag(item: FeedItem) -> str:
    if not item.cve:
        return ""
    return f'<span class="cve-tag">{_esc(item.cve)}</span>'


def _render_sources_html(item: FeedItem) -> str:
    links = "".join(
        f'<a href="{_esc(s.url)}">{_esc(s.title)}</a>' for s in item.sources
    )
    return f'<div class="feed-sources">{links}</div>'


def _render_item_sources_html(item: FeedItem) -> str:
    links = "".join(
        f'<a href="{_esc(s.url)}">{_esc(s.title)}</a>' for s in item.sources
    )
    return f'<div class="source-links">{links}</div>'


def render_feed_item_card(item: FeedItem) -> str:
    cve_tag = _render_cve_tag(item)
    sources_html = _render_sources_html(item)
    item_url = f"items/{_esc(item.slug)}.html"
    cve_attr = f' data-cve="{_esc(item.cve)}"' if item.cve else ""
    title_attr = _esc(item.title)
    vendor_attr = _esc(item.vendor)

    return f"""
            <article class="feed-item" data-type="{_esc(item.type)}" data-signal="{_esc(item.signal_class)}" data-title="{title_attr}" data-vendor="{vendor_attr}"{cve_attr}>
              <div class="feed-item-top">
                <div class="feed-item-meta">
                  <span class="feed-date">{_esc(item.display_date)}</span>
                  {_render_type_badge(item)}
                  {_render_signal_badge(item)}
                  {cve_tag}
                </div>
              </div>
              <h2 class="feed-item-title">
                <a href="{item_url}">{_esc(item.title)}</a>
              </h2>
              <p class="feed-vendor">{_esc(item.vendor)} · {_esc(item.product)}</p>
              <p class="feed-summary">{_esc(item.summary)}</p>
              <div class="feed-check">
                <p class="feed-check-label">Operator check</p>
                <p>{_esc(item.operator_check)}</p>
                {sources_html}
              </div>
              <a class="feed-read-link" href="{item_url}">Read brief →</a>
            </article>"""


_TYPE_FILTER_ORDER = {
    "KEV": 0,
    "Vendor advisory": 1,
    "Patch Tuesday": 2,
    "Ransomware": 3,
    "Exploit activity": 4,
}


def _render_filter_chips(items: list[FeedItem]) -> str:
    item_types = sorted(
        {item.type for item in items},
        key=lambda item_type: (_TYPE_FILTER_ORDER.get(item_type, 99), item_type),
    )
    chips = [
        '<button class="chip active" data-filter="all" role="listitem" aria-pressed="true">All</button>'
    ]
    chips.extend(
        f'<button class="chip" data-filter="{_esc(item_type)}" role="listitem" aria-pressed="false">{_esc(item_type)}</button>'
        for item_type in item_types
    )
    return "\n              ".join(chips)


def render_feed(items: list[FeedItem]) -> str:
    template = _load_template("feed.html.template")
    items_html = "\n".join(render_feed_item_card(item) for item in items)
    is_sample = any(item.is_sample for item in items)
    sample_notice = (
        '<p class="sample-notice" role="note">'
        "Preview feed. Items are examples of format and source style, not live intelligence."
        "</p>"
        if is_sample
        else ""
    )
    return template.safe_substitute(
        ITEMS_HTML=items_html,
        SAMPLE_NOTICE=sample_notice,
        FILTER_CHIPS=_render_filter_chips(items),
        ITEM_COUNT=str(len(items)),
        PRO_YEARLY_URL=_esc(paid_cta_url("pro", "yearly", "feed")),
        PRO_MONTHLY_URL=_esc(paid_cta_url("pro", "monthly", "feed")),
        TEAM_YEARLY_URL=_esc(paid_cta_url("team", "yearly", "feed")),
    )


def render_item_page(item: FeedItem) -> str:
    template = _load_template("item.html.template")
    cve_badge = (
        f'<span class="badge badge-cve">{_esc(item.cve)}</span>' if item.cve else ""
    )
    meta_cve_row = (
        f"""              <div class="meta-item">
                <span class="meta-label">CVE</span>
                <span class="meta-value">{_esc(item.cve)}</span>
              </div>"""
        if item.cve
        else ""
    )
    sources_html = _render_item_sources_html(item)
    sample_notice = (
        '<span class="sample-notice" role="note">'
        "Preview brief — example format, not live intelligence"
        "</span>"
        if item.is_sample
        else ""
    )

    return template.safe_substitute(
        TITLE=_esc(item.title),
        PAGE_TITLE=_esc(item.title) + " | PatchBrief",
        DATE=_esc(item.display_date),
        TYPE=_esc(item.type),
        SIGNAL=_esc(item.signal),
        SIGNAL_CLASS=_esc(item.signal_class),
        VENDOR=_esc(item.vendor),
        PRODUCT=_esc(item.product),
        CVE_BADGE=cve_badge,
        META_CVE_ROW=meta_cve_row,
        SUMMARY=_esc(item.summary),
        WHY_IT_MATTERS=_esc(item.why_it_matters),
        OPERATOR_CHECK=_esc(item.operator_check),
        SOURCES_HTML=sources_html,
        SAMPLE_NOTICE=sample_notice,
        PRO_YEARLY_URL=_esc(paid_cta_url("pro", "yearly", "brief")),
    )


def render_rss(items: list[FeedItem], base_url: str) -> str:
    build_time = datetime.now(tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    normalized_base_url = base_url.rstrip("/")
    channel_link = f"{normalized_base_url}/feed.html"

    item_blocks = []
    for item in items:
        item_url = f"{normalized_base_url}/items/{item.slug}.html"
        item_blocks.append(
            f"    <item>\n"
            f"      <title>{xml_escape(item.title)}</title>\n"
            f"      <link>{xml_escape(item_url)}</link>\n"
            f"      <guid isPermaLink=\"true\">{xml_escape(item_url)}</guid>\n"
            f"      <pubDate>{xml_escape(item.rfc822_date)}</pubDate>\n"
            f"      <description>{xml_escape(item.summary)}</description>\n"
            f"    </item>"
        )

    items_xml = "\n".join(item_blocks)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n'
        "  <channel>\n"
        "    <title>PatchBrief</title>\n"
        f"    <link>{xml_escape(channel_link)}</link>\n"
        "    <description>Short operator-ready briefs on public vulnerability advisories, "
        "known exploited vulnerabilities, vendor updates, and threat activity.</description>\n"
        f"    <lastBuildDate>{build_time}</lastBuildDate>\n"
        "    <language>en</language>\n"
        f"{items_xml}\n"
        "  </channel>\n"
        "</rss>\n"
    )


def render_sitemap(items: list[FeedItem], base_url: str) -> str:
    normalized_base_url = base_url.rstrip("/")
    static_paths = [
        ("", "1.0"),
        ("feed.html", "0.9"),
        ("api.html", "0.9"),
        ("pricing.html", "0.9"),
        ("checkout.html", "0.8"),
        ("watchlist.html", "0.8"),
        ("onboarding.html", "0.5"),
    ]
    url_blocks = [
        _render_sitemap_url(f"{normalized_base_url}/{path}", priority)
        for path, priority in static_paths
    ]
    url_blocks.extend(
        _render_sitemap_url(f"{normalized_base_url}/items/{item.slug}.html", "0.7", item.date)
        for item in items
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(url_blocks)
        + "\n</urlset>\n"
    )


def _render_sitemap_url(url: str, priority: str, lastmod: str | None = None) -> str:
    lastmod_xml = f"\n    <lastmod>{xml_escape(lastmod)}</lastmod>" if lastmod else ""
    return (
        "  <url>\n"
        f"    <loc>{xml_escape(url)}</loc>{lastmod_xml}\n"
        f"    <priority>{priority}</priority>\n"
        "  </url>"
    )
