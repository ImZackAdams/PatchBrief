"""Tests for patchbrief.watchlist.load_watchlist."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from patchbrief.watchlist import load_watchlist


def _write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "watchlist.yml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# 1. Valid watchlist loads correctly
def test_valid_watchlist(tmp_path):
    p = _write_yaml(
        tmp_path,
        """
        name: Test Watchlist
        owner_email: test@example.com
        cadence: weekly
        terms:
          - Microsoft
          - Chrome
        """,
    )
    wl = load_watchlist(p)
    assert wl.name == "Test Watchlist"
    assert wl.owner_email == "test@example.com"
    assert wl.cadence == "weekly"
    assert wl.terms == ["Microsoft", "Chrome"]


# 2. Empty terms raises ValueError
def test_empty_terms_raises(tmp_path):
    p = _write_yaml(
        tmp_path,
        """
        name: Bad Watchlist
        owner_email: test@example.com
        cadence: weekly
        terms: []
        """,
    )
    with pytest.raises(ValueError, match="at least 1 term"):
        load_watchlist(p)


# 3. More than 10 terms raises ValueError
def test_too_many_terms_raises(tmp_path):
    p = tmp_path / "watchlist.yml"
    lines = ["name: Big Watchlist", "owner_email: test@example.com", "cadence: weekly", "terms:"]
    for i in range(11):
        lines.append(f"  - term{i}")
    p.write_text("\n".join(lines), encoding="utf-8")
    with pytest.raises(ValueError, match="maximum is 10"):
        load_watchlist(p)


# 4. Term over 60 chars raises ValueError
def test_term_too_long_raises(tmp_path):
    long_term = "A" * 61
    p = _write_yaml(
        tmp_path,
        f"""
        name: Long Term Watchlist
        owner_email: test@example.com
        cadence: weekly
        terms:
          - {long_term}
        """,
    )
    with pytest.raises(ValueError, match="60-character limit"):
        load_watchlist(p)


# 5. Invalid cadence raises ValueError
def test_invalid_cadence_raises(tmp_path):
    p = _write_yaml(
        tmp_path,
        """
        name: Bad Cadence
        owner_email: test@example.com
        cadence: daily
        terms:
          - Microsoft
        """,
    )
    with pytest.raises(ValueError, match="cadence"):
        load_watchlist(p)
