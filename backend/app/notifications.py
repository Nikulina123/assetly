import datetime
import hashlib
import html
import json
import logging
import urllib.request

import asyncpg

from app.config import (
    AUTH_DIGEST_DAILY_CAP,
    AUTH_DIGEST_INTERVAL_SECONDS,
    NOTIFICATION_FROM_EMAIL,
    OPS_ALERT_EMAIL,
    SENDLY_API_KEY,
)

log = logging.getLogger("assetly_backend")

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
        send_email(to_email, f"[Assetly Inventory] Check-in complete – {full_name} / {hostname}", html_body)
    except Exception as e:
        log.warning(f"Failed to send checkin-success notification to {to_email}: {e}")


def safe_key_fingerprint(api_key: str) -> str:
    """A non-secret identifier for a rejected bearer.

    The previous implementation emailed api_key[:16], which for a key of the
    form as_live_ + hex hands 8 hex characters of live secret material to a
    third-party email vendor (audit finding L-2). The published prefix plus a
    hash fragment correlates repeated attempts just as well and discloses
    nothing: the fragment is derived from the full key, so it cannot be walked
    backwards into the key.
    """
    known_prefixes = ("as_live_", "wz_live_", "as_enroll_", "as_dev_")
    prefix = next((p for p in known_prefixes if api_key.startswith(p)), "unknown_")
    fragment = hashlib.sha256(api_key.encode()).hexdigest()[:8]
    return f"{prefix}#{fragment}"


async def record_auth_failure(
    pool: asyncpg.Pool, key_prefix: str, ip_address: str | None
) -> None:
    """Records one rejected credential. Never raises and never sends email --
    this runs on a path an unauthenticated caller controls, so it must not
    perform outbound network I/O. The digest below is what actually notifies."""
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO auth_failure_events (key_prefix, ip_address) VALUES ($1, $2)",
                key_prefix, ip_address,
            )
    except Exception as e:
        log.warning(f"Failed to record auth failure: {e}")


async def maybe_send_auth_failure_digest(pool: asyncpg.Pool) -> None:
    """Sends one digest if the interval has elapsed and the daily cap allows.

    Called opportunistically off request traffic -- there is no scheduler on
    this deployment. The claim is made with a conditional UPDATE ... RETURNING,
    so of two warm instances arriving at the same moment exactly one wins the
    row and sends; the loser's UPDATE matches nothing and it returns quietly.
    """
    if not OPS_ALERT_EMAIL:
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(seconds=AUTH_DIGEST_INTERVAL_SECONDS)
    try:
        async with pool.acquire() as conn:
            claimed = await conn.fetchrow(
                """
                UPDATE notification_state
                   SET last_digest_sent_at = $1,
                       digest_day = CURRENT_DATE,
                       digests_sent_today =
                           CASE WHEN digest_day = CURRENT_DATE
                                THEN digests_sent_today + 1 ELSE 1 END
                 WHERE id = TRUE
                   AND (last_digest_sent_at IS NULL OR last_digest_sent_at < $2)
                   AND (digest_day IS DISTINCT FROM CURRENT_DATE
                        OR digests_sent_today < $3)
                RETURNING TRUE
                """,
                now, cutoff, AUTH_DIGEST_DAILY_CAP,
            )
            if claimed is None:
                return

            rows = await conn.fetch(
                "SELECT key_prefix, count(*) AS hits, max(occurred_at) AS last_seen "
                "FROM auth_failure_events WHERE occurred_at >= $1 "
                "GROUP BY key_prefix ORDER BY hits DESC LIMIT 20",
                cutoff,
            )
            total = await conn.fetchval(
                "SELECT count(*) FROM auth_failure_events WHERE occurred_at >= $1",
                cutoff,
            )
            # Retention: the digest has been sent, so the window's rows have
            # served their purpose. Keeping a day lets an operator query
            # recent history without the table growing without bound.
            await conn.execute(
                "DELETE FROM auth_failure_events WHERE occurred_at < $1",
                now - datetime.timedelta(days=1),
            )
    except Exception as e:
        log.warning(f"Failed to prepare auth-failure digest: {e}")
        return

    if not total:
        return

    lines = "".join(
        f"<li>{html.escape(row['key_prefix'])} — {row['hits']} attempt(s), "
        f"last {html.escape(str(row['last_seen']))}</li>"
        for row in rows
    )
    html_body = (
        f"<p>{total} check-in request(s) were rejected with an invalid or revoked "
        f"credential in the last {AUTH_DIGEST_INTERVAL_SECONDS // 60} minutes.</p>"
        f"<ul>{lines}</ul>"
    )
    try:
        send_email(
            OPS_ALERT_EMAIL,
            f"[Assetly Inventory] {total} auth failure(s) on the checkin endpoint",
            html_body,
        )
    except Exception as e:
        log.warning(f"Failed to send auth-failure digest: {e}")
