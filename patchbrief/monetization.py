from __future__ import annotations

import os
from urllib.parse import urlencode


PLAN_PRICES = {
    "pro": {
        "monthly": "$9/mo",
        "yearly": "$79/yr",
    },
    "team": {
        "monthly": "$49/mo",
        "yearly": "$399/yr",
    },
}

PAYMENT_LINK_ENVS = {
    ("pro", "monthly"): "PATCHBRIEF_STRIPE_PRO_MONTHLY_URL",
    ("pro", "yearly"): "PATCHBRIEF_STRIPE_PRO_YEARLY_URL",
    ("team", "monthly"): "PATCHBRIEF_STRIPE_TEAM_MONTHLY_URL",
    ("team", "yearly"): "PATCHBRIEF_STRIPE_TEAM_YEARLY_URL",
}


def checkout_url(
    plan: str = "pro",
    billing: str = "yearly",
    source: str = "site",
    *,
    root_relative: bool = True,
    base_url: str | None = None,
) -> str:
    """Return a PatchBrief checkout URL with attribution query params."""
    normalized_plan = _normalize_plan(plan)
    normalized_billing = _normalize_billing(billing)
    path = "/checkout.html" if root_relative else "checkout.html"
    if base_url:
        path = f"{base_url.rstrip('/')}/checkout.html"
    return f"{path}?{urlencode({'plan': normalized_plan, 'billing': normalized_billing, 'source': source})}"


def paid_cta_url(
    plan: str = "pro",
    billing: str = "yearly",
    source: str = "site",
    *,
    root_relative: bool = True,
    base_url: str | None = None,
) -> str:
    """Return the configured payment link, or the internal checkout fallback."""
    normalized_plan = _normalize_plan(plan)
    normalized_billing = _normalize_billing(billing)
    env_name = PAYMENT_LINK_ENVS[(normalized_plan, normalized_billing)]
    configured_url = os.environ.get(env_name, "").strip()
    if configured_url:
        return configured_url
    return checkout_url(
        normalized_plan,
        normalized_billing,
        source,
        root_relative=root_relative,
        base_url=base_url,
    )


def _normalize_plan(plan: str) -> str:
    normalized = (plan or "pro").lower()
    if normalized not in PLAN_PRICES:
        return "pro"
    return normalized


def _normalize_billing(billing: str) -> str:
    normalized = (billing or "yearly").lower()
    if normalized not in {"monthly", "yearly"}:
        return "yearly"
    return normalized
