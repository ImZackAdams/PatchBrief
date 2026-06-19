from __future__ import annotations

import html
from typing import Optional

from patchbrief.models import Advisory, AdvisoryMatch, Brief


def _severity_badge(severity: str) -> str:
    sev_lower = severity.lower() if severity else ""
    if sev_lower == "critical":
        bg = "var(--red)"
        fg = "#fff"
    elif sev_lower == "high":
        bg = "#b45309"
        fg = "#fff"
    else:
        bg = "#6b7f7a"
        fg = "#fff"
    label = html.escape(severity.upper() if severity else "UNKNOWN")
    return (
        f'<span class="badge" style="background:{bg};color:{fg};">{label}</span>'
    )


def _render_match(match: AdvisoryMatch) -> str:
    adv: Advisory = match.advisory
    title = html.escape(adv.title or "Untitled")
    vendor = html.escape(adv.vendor or "")
    product = html.escape(adv.product or "")
    source = html.escape(adv.source or "")
    source_url = html.escape(adv.source_url or "#")
    description = html.escape(adv.description or "")
    matched_terms_str = html.escape(", ".join(match.matched_terms))
    match_reasons_str = html.escape(", ".join(match.match_reasons))

    cve_badge = ""
    if adv.cve:
        cve_badge = f' <span class="badge badge-cve">{html.escape(adv.cve)}</span>'

    exploited_badge = ""
    if adv.known_exploited:
        exploited_badge = ' <span class="badge badge-exploited">Known Exploited</span>'

    sev_badge = _severity_badge(adv.severity or "")

    checks_html = "\n".join(
        f"<li>{html.escape(check)}</li>" for check in match.suggested_checks
    )

    published = ""
    if adv.published_date:
        published = f'<span class="meta-item">Published: {html.escape(str(adv.published_date))}</span>'

    due = ""
    if adv.due_date:
        due = f'<span class="meta-item due">Due: {html.escape(str(adv.due_date))}</span>'

    return f"""
<div class="advisory-card">
  <div class="advisory-header">
    <h3 class="advisory-title">{title}{cve_badge}{exploited_badge}</h3>
    <div class="advisory-meta">
      <span class="meta-item">{vendor} / {product}</span>
      {sev_badge}
      {published}
      {due}
    </div>
  </div>
  <p class="advisory-description">{description}</p>
  <div class="advisory-detail">
    <div class="detail-row"><span class="detail-label">Matched terms:</span> <span class="detail-value">{matched_terms_str}</span></div>
    <div class="detail-row"><span class="detail-label">Match reasons:</span> <span class="detail-value">{match_reasons_str}</span></div>
  </div>
  <div class="advisory-checks">
    <p class="checks-heading">Suggested checks</p>
    <ul>{checks_html}</ul>
  </div>
  <div class="advisory-source">
    <a href="{source_url}" class="source-link" target="_blank" rel="noopener noreferrer">{source} &rarr;</a>
  </div>
</div>
"""


def render_brief(brief: Brief, omitted: Optional[list[AdvisoryMatch]] = None) -> str:
    """Render a Brief as a complete, self-contained HTML string."""
    if omitted is None:
        omitted = []

    watchlist_name = html.escape(brief.watchlist.name)
    terms_str = html.escape(", ".join(brief.watchlist.terms))
    cadence_display = html.escape(brief.watchlist.cadence.replace("_", " ").title())
    generated_str = brief.generated_at.strftime("%B %-d, %Y, %-I:%M %p")

    # Summary stats
    total_reviewed = brief.advisories_reviewed
    total_matches = len(brief.matches)
    exploited_count = sum(1 for m in brief.matches if m.advisory.known_exploited)
    priority_count = sum(1 for m in brief.matches if m.priority <= 2)

    # Split matches into priority (P1+P2) and other (P3+P4)
    priority_matches = [m for m in brief.matches if m.priority <= 2]
    other_matches = [m for m in brief.matches if m.priority > 2]

    # Priority section
    priority_section = ""
    if priority_matches:
        cards = "".join(_render_match(m) for m in priority_matches)
        priority_section = f"""
<section class="match-section">
  <h2 class="section-heading priority-heading">Priority review</h2>
  {cards}
</section>
"""

    # Other matches section (only for weekly/monthly)
    other_section = ""
    if other_matches and brief.watchlist.cadence in ("weekly", "monthly"):
        cards = "".join(_render_match(m) for m in other_matches)
        other_section = f"""
<section class="match-section">
  <h2 class="section-heading">Other matches</h2>
  {cards}
</section>
"""

    # No-matches message
    no_matches_section = ""
    if total_matches == 0:
        no_matches_section = """
<div class="no-matches">
  <p class="no-matches-title">No matching advisories found</p>
  <p class="no-matches-body">
    No advisories in the configured sources matched your watchlist terms.
    This means no matches were found in the sources reviewed — it does not mean
    your environment is safe or unaffected. Review vendor channels and other sources directly.
  </p>
</div>
"""

    # Omitted note
    omitted_note = ""
    if omitted:
        n = len(omitted)
        omitted_note = f"""
<p class="omitted-note">
  {n} lower-priority {"match was" if n == 1 else "matches were"} omitted based on cadence setting.
</p>
"""

    sources_str = html.escape(", ".join(brief.source_names)) if brief.source_names else "None"

    exploited_class = "summary-card highlight" if exploited_count > 0 else "summary-card"
    priority_class = "summary-card highlight" if priority_count > 0 else "summary-card"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PatchBrief — {watchlist_name}</title>
  <style>
    :root {{
      --page: #fbfbf8;
      --paper: #fff;
      --ink: #111816;
      --muted: #66706d;
      --line: #e2e5df;
      --accent: #0f766e;
      --red: #913f32;
      --radius: 6px;
      --max: 860px;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background: var(--page);
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 15px;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }}

    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    .page-wrap {{
      max-width: var(--max);
      margin: 0 auto;
      padding: 32px 20px 64px;
    }}

    /* Header */
    .site-header {{
      border-bottom: 1px solid var(--line);
      padding-bottom: 16px;
      margin-bottom: 32px;
    }}

    .brand {{
      font-size: 18px;
      font-weight: 700;
      color: var(--accent);
      letter-spacing: -0.01em;
    }}

    /* Brief title block */
    .brief-meta {{
      margin-bottom: 28px;
    }}

    .brief-title {{
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin-bottom: 8px;
    }}

    .brief-details {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.8;
    }}

    .brief-details strong {{
      color: var(--ink);
      font-weight: 600;
    }}

    /* Summary grid */
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 36px;
    }}

    .summary-card {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 16px 18px;
    }}

    .summary-card .card-value {{
      font-size: 28px;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 4px;
    }}

    .summary-card .card-label {{
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}

    .summary-card.highlight .card-value {{
      color: var(--red);
    }}

    /* Section headings */
    .section-heading {{
      font-size: 16px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      border-bottom: 1px solid var(--line);
      padding-bottom: 8px;
      margin-bottom: 20px;
    }}

    .priority-heading {{
      color: var(--red);
      border-bottom-color: var(--red);
    }}

    /* Advisory cards */
    .match-section {{
      margin-bottom: 40px;
    }}

    .advisory-card {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 20px 22px;
      margin-bottom: 16px;
    }}

    .advisory-header {{
      margin-bottom: 12px;
    }}

    .advisory-title {{
      font-size: 16px;
      font-weight: 700;
      line-height: 1.4;
      margin-bottom: 6px;
    }}

    .advisory-meta {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--muted);
    }}

    .meta-item {{
      display: inline;
    }}

    .meta-item.due {{
      font-weight: 600;
      color: var(--red);
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}

    .badge-cve {{
      background: #e8eff4;
      color: #2f6388;
    }}

    .badge-exploited {{
      background: var(--accent);
      color: #fff;
    }}

    /* Advisory body */
    .advisory-description {{
      font-size: 14px;
      color: var(--muted);
      margin-bottom: 14px;
    }}

    .advisory-detail {{
      font-size: 13px;
      margin-bottom: 14px;
      border-left: 2px solid var(--line);
      padding-left: 12px;
    }}

    .detail-row {{
      margin-bottom: 4px;
    }}

    .detail-label {{
      font-weight: 600;
      color: var(--ink);
    }}

    .detail-value {{
      color: var(--muted);
    }}

    /* Suggested checks */
    .advisory-checks {{
      background: #f5f8f5;
      border-radius: var(--radius);
      padding: 14px 16px;
      margin-bottom: 14px;
    }}

    .checks-heading {{
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      margin-bottom: 8px;
    }}

    .advisory-checks ul {{
      padding-left: 18px;
      font-size: 14px;
    }}

    .advisory-checks li {{
      margin-bottom: 4px;
    }}

    /* Source link */
    .advisory-source {{
      font-size: 13px;
    }}

    .source-link {{
      color: var(--accent);
      font-weight: 600;
    }}

    /* No matches */
    .no-matches {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 32px;
      text-align: center;
      margin-bottom: 32px;
    }}

    .no-matches-title {{
      font-size: 17px;
      font-weight: 700;
      margin-bottom: 10px;
    }}

    .no-matches-body {{
      color: var(--muted);
      font-size: 14px;
      max-width: 520px;
      margin: 0 auto;
    }}

    /* Omitted note */
    .omitted-note {{
      font-size: 13px;
      color: var(--muted);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 10px 14px;
      margin-bottom: 32px;
    }}

    /* Disclaimer */
    .disclaimer {{
      border-top: 1px solid var(--line);
      padding-top: 20px;
      margin-top: 40px;
      font-size: 12px;
      color: var(--muted);
    }}

    /* Print */
    @media print {{
      body {{ background: #fff; }}
      .page-wrap {{ padding: 0; }}
      .advisory-card {{
        background: #fff;
        border: 1px solid #ccc;
        break-inside: avoid;
      }}
      .advisory-checks {{ background: #f5f5f5; }}
      .summary-card {{ background: #fff; border: 1px solid #ccc; }}
      a {{ color: #0f766e; }}
    }}

    @media (max-width: 560px) {{
      .brief-title {{ font-size: 18px; }}
      .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
    }}
  </style>
</head>
<body>
  <div class="page-wrap">
    <header class="site-header">
      <span class="brand">PatchBrief</span>
    </header>

    <div class="brief-meta">
      <h1 class="brief-title">PatchBrief Watchlist Brief &mdash; {watchlist_name}</h1>
      <div class="brief-details">
        <div>Generated: <strong>{generated_str}</strong></div>
        <div>Watchlist terms: <strong>{terms_str}</strong></div>
        <div>Cadence: <strong>{cadence_display}</strong></div>
        <div>Sources: <strong>{sources_str}</strong></div>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card">
        <div class="card-value">{total_reviewed}</div>
        <div class="card-label">Advisories reviewed</div>
      </div>
      <div class="summary-card">
        <div class="card-value">{total_matches}</div>
        <div class="card-label">Watchlist matches</div>
      </div>
      <div class="{exploited_class}">
        <div class="card-value">{exploited_count}</div>
        <div class="card-label">Known exploited</div>
      </div>
      <div class="{priority_class}">
        <div class="card-value">{priority_count}</div>
        <div class="card-label">Priority review items</div>
      </div>
    </div>

    {no_matches_section}
    {priority_section}
    {other_section}
    {omitted_note}

    <footer class="disclaimer">
      <p>PatchBrief uses public advisory sources and does not scan your environment, verify exposure, or replace vendor guidance.</p>
    </footer>
  </div>
</body>
</html>"""
