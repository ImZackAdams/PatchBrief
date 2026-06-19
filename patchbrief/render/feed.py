from __future__ import annotations

import html
import string
from pathlib import Path
from typing import Optional

from patchbrief.feed import FeedItem

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

    return f"""
            <article class="feed-item">
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


def render_feed(items: list[FeedItem]) -> str:
    template = _load_template("feed.html.template")
    items_html = "\n".join(render_feed_item_card(item) for item in items)
    is_sample = any(item.is_sample for item in items)
    sample_notice = (
        '<p class="sample-notice" role="note">'
        "Sample feed while PatchBrief is in pilot. "
        "Items are examples of format and source style, not live intelligence."
        "</p>"
        if is_sample
        else ""
    )
    return template.safe_substitute(
        ITEMS_HTML=items_html,
        SAMPLE_NOTICE=sample_notice,
        ITEM_COUNT=str(len(items)),
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
        "Sample brief — example format, not live intelligence"
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
    )
