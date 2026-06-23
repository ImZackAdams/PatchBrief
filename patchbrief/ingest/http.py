from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any


USER_AGENT = "PatchBrief-Ingest/1.0 (https://www.patchbrief.org)"


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 45,
    retries: int = 2,
) -> Any:
    """Fetch JSON with a small retry budget for transient source failures."""
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    last_error: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt >= retries:
                break
            time.sleep(2**attempt)

    raise RuntimeError(f"failed to fetch JSON from {url}: {last_error}")
