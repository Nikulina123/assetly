import json
import logging
import urllib.request

from app.config import NOTIFICATION_FROM_EMAIL, SENDLY_API_KEY

log = logging.getLogger("webiz_backend")

SENDLY_SEND_URL = "https://app.sendly.ge/api/v1/email/send"


def send_email(to: str, subject: str, html: str, text: str | None = None) -> None:
    """Sends one email via Sendly.ge. Raises on failure (network error or a
    non-2xx response) -- this function is a pure Sendly client with no
    try/except of its own. Callers that must never let a notification
    failure affect their own behavior catch around their own call to this."""
    body = {"from": NOTIFICATION_FROM_EMAIL, "to": to, "subject": subject, "html": html}
    if text is not None:
        body["text"] = text
    req = urllib.request.Request(
        SENDLY_SEND_URL,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {SENDLY_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()
