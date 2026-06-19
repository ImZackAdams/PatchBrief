"""HTML email digest generator.

Produces a self-contained, email-client-compatible HTML digest from a list
of FeedItems. Uses table-based layout with fully inline styles so it renders
correctly in Gmail, Outlook, Apple Mail, and similar clients.

Usage:
    from patchbrief.generate.digest import render_digest
    html = render_digest(items, issue=42, base_url="https://www.patchbrief.org")
    Path("digest-42.html").write_text(html)
"""
from __future__ import annotations

import html as html_mod
from datetime import date
from typing import TYPE_CHECKING

from patchbrief.monetization import paid_cta_url

if TYPE_CHECKING:
    from patchbrief.feed import FeedItem

BASE_URL = "https://www.patchbrief.org"

_SIGNAL_ORDER = {
    "Known exploited": 0,
    "Critical vendor advisory": 1,
    "Patch review": 2,
    "Threat activity": 3,
}

_SIGNAL_COLOR = {
    "exploited": ("#edf7f4", "#0f766e"),
    "critical":  ("#fdf0ee", "#913f32"),
    "patch":     ("#fdf5e6", "#8a5c0f"),
    "threat":    ("#f0eefb", "#5a3f9e"),
}


def render_digest(
    items: list[FeedItem],
    issue: int = 1,
    base_url: str = BASE_URL,
    max_items: int = 8,
    label: str = "Weekly",
) -> str:
    """Return a standalone HTML email string for the given feed items.

    Items are sorted by signal priority and truncated to *max_items*.
    """
    base_url = base_url.rstrip("/")
    today = date.today().strftime("%B %-d, %Y")

    ranked = sorted(
        items,
        key=lambda it: (_SIGNAL_ORDER.get(it.signal, 9), it.date),
    )
    top = ranked[:max_items]

    items_html = "".join(_render_item(it, base_url) for it in top)
    item_count = len(top)
    total = len(items)

    return _wrap(items_html, issue=issue, today=today, item_count=item_count,
                 total=total, base_url=base_url, label=label)


def _e(value: str) -> str:
    return html_mod.escape(str(value or ""))


def _signal_colors(item: FeedItem) -> tuple[str, str]:
    return _SIGNAL_COLOR.get(item.signal_class, ("#f3f4f0", "#66706d"))


def _render_item(item: FeedItem, base_url: str) -> str:
    bg, fg = _signal_colors(item)
    item_url = f"{base_url}/items/{_e(item.slug)}.html"
    cve_part = f" &middot; {_e(item.cve)}" if item.cve else ""
    sources_html = "".join(
        f'<a href="{_e(s.url)}" style="color:#0f766e;text-decoration:none;font-size:12px;margin-right:8px;">{_e(s.title)}</a>'
        for s in item.sources[:3]
    )

    return f"""
    <!-- Item -->
    <tr>
      <td style="padding:0 0 1px;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border:1px solid #e2e5df;border-radius:6px;overflow:hidden;">
          <tr>
            <td style="padding:4px 16px;background:{bg};">
              <span style="font-size:11px;font-weight:700;color:{fg};letter-spacing:0.04em;text-transform:uppercase;">{_e(item.signal)}</span>
              <span style="font-size:11px;color:{fg};opacity:0.7;margin-left:8px;">{_e(item.display_date)}{cve_part}</span>
            </td>
          </tr>
          <tr>
            <td style="padding:14px 16px 4px;">
              <a href="{item_url}" style="font-size:15px;font-weight:700;color:#111816;text-decoration:none;line-height:1.3;display:block;">{_e(item.title)}</a>
            </td>
          </tr>
          <tr>
            <td style="padding:4px 16px 6px;">
              <span style="font-size:12px;color:#66706d;">{_e(item.vendor)} &middot; {_e(item.product)}</span>
            </td>
          </tr>
          <tr>
            <td style="padding:0 16px 10px;">
              <p style="margin:0;font-size:13px;color:#2e3936;line-height:1.55;">{_e(item.summary)}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:10px 16px;border-top:1px solid #e2e5df;background:#fbfbf8;">
              <p style="margin:0 0 4px;font-size:10px;font-weight:700;color:#66706d;letter-spacing:0.05em;text-transform:uppercase;">Operator check</p>
              <p style="margin:0 0 10px;font-size:12px;color:#2e3936;line-height:1.55;">{_e(item.operator_check)}</p>
              {sources_html}
              <a href="{item_url}" style="display:inline-block;margin-top:6px;font-size:12px;color:#0f766e;font-weight:700;text-decoration:none;">Read full brief &rarr;</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr><td style="height:12px;"></td></tr>"""


def _wrap(
    items_html: str,
    *,
    issue: int,
    today: str,
    item_count: int,
    total: int,
    base_url: str,
    label: str,
) -> str:
    pro_checkout_url = paid_cta_url(
        "pro",
        "yearly",
        "email-digest",
        root_relative=False,
        base_url=base_url,
    )
    pro_checkout_href = _e(pro_checkout_url)

    return f"""<!doctype html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <title>PatchBrief #{issue} — {label} Digest</title>
  <!--[if mso]><noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript><![endif]-->
  <style>
    body {{ margin:0;padding:0;background:#fbfbf8; }}
    a {{ color:#0f766e; }}
    @media only screen and (max-width:600px) {{
      .email-body {{ width:100% !important; }}
      .mobile-pad {{ padding:16px !important; }}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background:#fbfbf8;font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">

  <!-- Preheader -->
  <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">
    PatchBrief #{issue} &middot; {item_count} security briefs &middot; {today}
    &zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;
  </div>

  <!-- Wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fbfbf8;padding:32px 16px;">
    <tr>
      <td align="center">
        <table class="email-body" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;">

          <!-- Header -->
          <tr>
            <td style="padding:0 0 20px;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border:1px solid #e2e5df;border-radius:6px;">
                <tr>
                  <td style="padding:20px 24px;border-bottom:1px solid #e2e5df;">
                    <table width="100%" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td>
                          <table cellpadding="0" cellspacing="0" border="0">
                            <tr>
                              <td style="width:32px;height:32px;border:1px solid #cdd3cc;border-radius:6px;background:#ffffff;text-align:center;vertical-align:middle;">
                                <span style="font-family:ui-monospace,monospace;font-size:11px;font-weight:800;color:#0f766e;">PB</span>
                              </td>
                              <td style="padding-left:10px;font-size:15px;font-weight:700;color:#111816;">PatchBrief</td>
                            </tr>
                          </table>
                        </td>
                        <td align="right">
                          <span style="font-size:12px;color:#66706d;">{label} Digest &middot; #{issue}</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="padding:16px 24px 18px;">
                    <p style="margin:0 0 4px;font-size:11px;font-weight:700;color:#0f766e;letter-spacing:0.04em;text-transform:uppercase;">Security intel feed</p>
                    <h1 style="margin:0 0 8px;font-size:22px;font-weight:800;color:#111816;line-height:1.15;">This week in exploited vulnerabilities</h1>
                    <p style="margin:0;font-size:13px;color:#66706d;">{today} &middot; {item_count} items from {total} in the feed</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Items -->
          {items_html}

          <!-- Upgrade CTA -->
          <tr>
            <td style="padding:0 0 20px;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#111816;border-radius:6px;overflow:hidden;">
                <tr>
                  <td style="padding:24px;">
                    <p style="margin:0 0 6px;font-size:11px;font-weight:700;color:rgba(255,255,255,0.5);letter-spacing:0.04em;text-transform:uppercase;">PatchBrief Pro</p>
                    <p style="margin:0 0 12px;font-size:17px;font-weight:700;color:#ffffff;line-height:1.3;">Get daily digests and vendor watchlist alerts.</p>
                    <p style="margin:0 0 16px;font-size:13px;color:rgba(255,255,255,0.65);line-height:1.5;">Pro subscribers get this digest daily (not just weekly), plus targeted alerts when vulnerabilities affect vendors they run. $9/month or $79/year.</p>
                    <a href="{pro_checkout_href}" style="display:inline-block;background:#0f766e;color:#ffffff;font-size:13px;font-weight:700;text-decoration:none;padding:10px 20px;border-radius:6px;">Upgrade to Pro &rarr;</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td>
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="padding:16px 0;border-top:1px solid #e2e5df;">
                    <table width="100%" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td>
                          <span style="font-size:12px;color:#66706d;">
                            <strong style="color:#111816;">PatchBrief</strong> &middot; Public security intel feed
                          </span>
                        </td>
                        <td align="right">
                          <a href="{base_url}/feed.html" style="font-size:12px;color:#66706d;text-decoration:none;margin-left:12px;">Feed</a>
                          <a href="{base_url}/rss.xml" style="font-size:12px;color:#66706d;text-decoration:none;margin-left:12px;">RSS</a>
                          <a href="{base_url}/pricing.html" style="font-size:12px;color:#66706d;text-decoration:none;margin-left:12px;">Pricing</a>
                        </td>
                      </tr>
                      <tr>
                        <td colspan="2" style="padding-top:8px;">
                          <p style="margin:0;font-size:11px;color:#89928f;line-height:1.5;">
                            PatchBrief uses public sources only. It does not scan your environment, verify exposure, or replace vendor guidance.
                            You are receiving this because you subscribed at patchbrief.org.
                            <a href="{base_url}/#newsletter" style="color:#89928f;">Unsubscribe</a>
                          </p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>"""
