import html
import json
import logging
import urllib.request

from app.config import NOTIFICATION_FROM_EMAIL, OPS_ALERT_EMAIL, SENDLY_API_KEY

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


def notify_checkin_success(
    to_email: str | None,
    hostname: str,
    full_name: str,
    department: str | None,
    custom_fields: dict,
) -> None:
    """Never raises -- a notification failure must not affect the checkin
    response. Silently no-ops if the company has no notification_email set
    (e.g. an older company created before this feature, not yet configured)."""
    if not to_email:
        return
    custom_lines = "".join(
        f"<p>{html.escape(key.replace('_', ' ').title())}: {html.escape(str(value))}</p>"
        for key, value in custom_fields.items()
    )
    html_body = (
        f"<p>Hi {html.escape(full_name)},</p>"
        f"<p>Your device <strong>{html.escape(hostname)}</strong> has successfully checked in.</p>"
        f"<p>Department: {html.escape(department) if department else 'N/A'}</p>"
        f"{custom_lines}"
    )
    try:
        send_email(to_email, f"[Webiz Inventory] Check-in complete – {full_name} / {hostname}", html_body)
    except Exception as e:
        log.warning(f"Failed to send checkin-success notification to {to_email}: {e}")


def notify_auth_failure(key_prefix: str) -> None:
    """Never raises, same reasoning as notify_checkin_success. No-ops if
    OPS_ALERT_EMAIL isn't configured."""
    if not OPS_ALERT_EMAIL:
        return
    html_body = f"<p>A check-in request was rejected: invalid or revoked API key (prefix: {html.escape(key_prefix)}).</p>"
    try:
        send_email(OPS_ALERT_EMAIL, "[Webiz Inventory] Auth failure on checkin endpoint", html_body)
    except Exception as e:
        log.warning(f"Failed to send auth-failure notification: {e}")
