"""Device staleness classification.

Deliberately free of database access so the boundaries are testable without a
fixture. This is the single source of truth for status -- devices.py must not
re-derive it in SQL.

Bands are proportional to the company's own check-in interval rather than fixed
day counts: a company prompting every 24 h would otherwise see every device
reported "online" for 180 days.
"""
import datetime

from app.config import PENDING_GRACE_MULTIPLIER


def derive_status(
    last_seen_at: datetime.datetime | None,
    now: datetime.datetime,
    interval_seconds: int,
) -> str:
    """Returns 'online', 'pending', or 'offline'.

    'online' means "reported within its own window", not "recently active".
    At the default 180-day interval the 1.5x grace reproduces the historic
    180/270-day boundaries exactly.
    """
    if last_seen_at is None:
        return "offline"
    age_seconds = (now - last_seen_at).total_seconds()
    if age_seconds <= interval_seconds:
        return "online"
    if age_seconds <= interval_seconds * PENDING_GRACE_MULTIPLIER:
        return "pending"
    return "offline"
