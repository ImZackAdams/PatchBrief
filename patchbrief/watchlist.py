from __future__ import annotations

from pathlib import Path
from typing import Union

import yaml

from patchbrief.models import Watchlist

VALID_CADENCES = {"important_only", "weekly", "monthly"}
MAX_TERMS = 10
MAX_TERM_LENGTH = 60


def load_watchlist(path: Union[str, Path]) -> Watchlist:
    """Load and validate a YAML watchlist file, returning a Watchlist dataclass."""
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("Watchlist file must contain a YAML mapping at the top level.")

    # Validate owner_email
    owner_email = data.get("owner_email", "").strip()
    if not owner_email:
        raise ValueError("Watchlist is missing required field: owner_email.")

    # Validate name (use filename as fallback)
    name = data.get("name", "").strip() or path.stem

    # Validate cadence
    cadence = data.get("cadence", "").strip()
    if cadence not in VALID_CADENCES:
        raise ValueError(
            f"Invalid cadence {cadence!r}. Must be one of: "
            + ", ".join(sorted(VALID_CADENCES))
            + "."
        )

    # Validate terms
    terms = data.get("terms", [])
    if not isinstance(terms, list):
        raise ValueError("Watchlist 'terms' must be a list.")
    if len(terms) == 0:
        raise ValueError("Watchlist must have at least 1 term.")
    if len(terms) > MAX_TERMS:
        raise ValueError(
            f"Watchlist has {len(terms)} terms but the maximum is {MAX_TERMS}."
        )
    for term in terms:
        if not isinstance(term, str):
            raise ValueError(f"Each term must be a string; got {type(term).__name__!r}.")
        if len(term) > MAX_TERM_LENGTH:
            raise ValueError(
                f"Term {term!r} is {len(term)} characters, which exceeds the "
                f"{MAX_TERM_LENGTH}-character limit."
            )

    return Watchlist(
        name=name,
        owner_email=owner_email,
        cadence=cadence,
        terms=[str(t) for t in terms],
    )
