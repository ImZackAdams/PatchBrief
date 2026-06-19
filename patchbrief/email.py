from __future__ import annotations

import json
import urllib.error
import urllib.request


def send_brief(
    *,
    html: str,
    to: str,
    subject: str,
    from_address: str,
    api_key: str,
) -> dict:
    payload = json.dumps({"from": from_address, "to": [to], "subject": subject, "html": html}).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Resend API {exc.code}: {exc.read().decode()}") from exc
