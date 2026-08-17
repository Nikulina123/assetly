"""Per-company check-in recurrence.

The parsing/formatting half is deliberately free of database access so it is
testable without a fixture -- the same split app/device_status.py uses. Only
resolve_schedule (added in Task 2) touches Postgres.

Intervals are stored as a single canonical seconds integer rather than a
(count, unit) pair. That collapses every agent's due-check to one elapsed-
seconds comparison, at the cost of "1 month" meaning 30 days. That is not a
regression: the guard this replaces approximated months as (day_delta / 30.0)
already, so calendar-exact recurrence was never a property of this system.
"""

import asyncpg
import uuid

from app.config import DEFAULT_CANCEL_RETRY_SECONDS, DEFAULT_CHECKIN_INTERVAL_SECONDS

# The agent wakes hourly on every platform (see the installers), so an interval
# shorter than that would be a setting the wake cadence cannot honour.
MIN_INTERVAL_SECONDS = 3600

UNIT_SECONDS = {
    "hours": 3600,
    "days": 86400,
    "weeks": 604800,
    "months": 2592000,    # 30 days
    "years": 31536000,    # 365 days
}

# Ordered longest-unit-first so format_interval reports the most readable form.
_FORMAT_UNITS = [
    ("year", 31536000),
    ("month", 2592000),
    ("week", 604800),
    ("day", 86400),
    ("hour", 3600),
]

# Drives the interval dropdown in the portal. Shortest first.
PRESETS = [
    ("12 hours", 43200),
    ("24 hours", 86400),
    ("2 days", 172800),
    ("1 week", 604800),
    ("2 weeks", 1209600),
    ("1 month", 2592000),
    ("3 months", 7776000),
    ("6 months", 15552000),
    ("1 year", 31536000),
]

# A separate, shorter list for the cancel-retry dropdown -- not a filtered view
# of PRESETS, because the sensible range for "ask again after a cancel" tops out
# far below the sensible range for the interval itself.
RETRY_PRESETS = [
    ("1 hour", 3600),
    ("4 hours", 14400),
    ("12 hours", 43200),
    ("24 hours", 86400),
    ("3 days", 259200),
    ("1 week", 604800),
]


def parse_interval(count: int, unit: str) -> int:
    """Converts an admin's "every N <unit>" into canonical seconds.

    Raises ValueError on anything the portal must report as a form error rather
    than let reach the database constraint.
    """
    if unit not in UNIT_SECONDS:
        raise ValueError(f"Unknown unit {unit!r}")
    if count <= 0:
        raise ValueError("Interval must be a positive number")
    seconds = count * UNIT_SECONDS[unit]
    if seconds < MIN_INTERVAL_SECONDS:
        raise ValueError("Interval must be at least 1 hour")
    return seconds


def format_interval(seconds: int) -> str:
    """Renders seconds as the largest unit that divides it exactly.

    Note 86400 renders as "24 hours" rather than "1 day": that is the label the
    PRESETS table offers, and test_preset_labels_match_their_seconds pins the
    two together so the summary line always reads back what the admin picked.
    """
    for label, size in _FORMAT_UNITS:
        if size == 86400 and seconds == 86400:
            # The one deliberate exception, so the dropdown and the summary
            # line agree. Everything else follows the largest-exact-unit rule.
            return "24 hours"
        if seconds % size == 0:
            count = seconds // size
            return f"{count} {label}" if count == 1 else f"{count} {label}s"
    return f"{seconds} seconds"


async def resolve_schedule(pool: asyncpg.Pool, company_id: str) -> dict:
    """The agent-facing schedule for one company.

    No set_config('app.company_id') here: unlike device_checkins/devices/
    company_fields, the companies table has no row-level security policy (admin
    routes read it directly via _get_company_or_404), so the explicit id filter
    is the isolation.
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT checkin_interval_seconds, cancel_retry_seconds "
            "FROM companies WHERE id = $1",
            uuid.UUID(company_id),
        )
    if row is None:
        # Only reachable if a company is deleted between authentication and
        # this call. Falling back to the configured defaults keeps the agent
        # running on the historical cadence rather than raising into a 500.
        return {
            "checkin_interval_seconds": DEFAULT_CHECKIN_INTERVAL_SECONDS,
            "cancel_retry_seconds": DEFAULT_CANCEL_RETRY_SECONDS,
        }
    return {
        "checkin_interval_seconds": row["checkin_interval_seconds"],
        "cancel_retry_seconds": row["cancel_retry_seconds"],
    }
