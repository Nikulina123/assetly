"""Device staleness classification.

Deliberately free of database access so the boundaries are testable without a
fixture. This is the single source of truth for status -- devices.py must not
re-derive it in SQL.
"""
import datetime

from app.config import DEVICE_ONLINE_MAX_AGE_DAYS, DEVICE_PENDING_MAX_AGE_DAYS


def derive_status(
    last_seen_at: datetime.datetime | None,
    now: datetime.datetime,
) -> str:
    """Returns 'online', 'pending', or 'offline'."""
    if last_seen_at is None:
        return "offline"
    age_days = (now - last_seen_at).total_seconds() / 86400
    if age_days <= DEVICE_ONLINE_MAX_AGE_DAYS:
        return "online"
    if age_days <= DEVICE_PENDING_MAX_AGE_DAYS:
        return "pending"
    return "offline"
