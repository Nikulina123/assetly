"""Pure-logic tests for app.schedule. No database, no fixtures -- the parsing
and formatting helpers are deliberately free of I/O so they can be tested
without a Postgres connection, the same split app/device_status.py uses."""
import uuid

import pytest

from app.schedule import (
    MIN_INTERVAL_SECONDS,
    PRESETS,
    RETRY_PRESETS,
    format_interval,
    parse_interval,
    resolve_schedule,
)


def test_parse_interval_converts_each_unit():
    assert parse_interval(12, "hours") == 43200
    assert parse_interval(2, "days") == 172800
    assert parse_interval(2, "weeks") == 1209600
    assert parse_interval(1, "months") == 2592000
    assert parse_interval(1, "years") == 31536000


def test_parse_interval_rejects_unknown_unit():
    with pytest.raises(ValueError):
        parse_interval(1, "fortnights")


def test_parse_interval_rejects_non_positive_count():
    with pytest.raises(ValueError):
        parse_interval(0, "days")
    with pytest.raises(ValueError):
        parse_interval(-1, "days")


def test_parse_interval_rejects_below_floor(monkeypatch):
    """The agent only wakes hourly, so anything shorter is a promise the wake
    cadence cannot keep.

    UNIT_SECONDS has no sub-hour unit today, so a sub-hour one is patched in
    here. Without that, parse_interval(30, "minutes") raises on the
    unknown-unit branch and the floor guard goes completely untested -- the
    match= is what pins which branch actually fired.
    """
    import app.schedule as schedule_module

    monkeypatch.setitem(schedule_module.UNIT_SECONDS, "minutes", 60)
    with pytest.raises(ValueError, match="at least 1 hour"):
        parse_interval(30, "minutes")


def test_format_interval_picks_largest_exact_unit():
    assert format_interval(15552000) == "6 months"
    assert format_interval(43200) == "12 hours"
    assert format_interval(604800) == "1 week"
    assert format_interval(31536000) == "1 year"


def test_format_interval_singular_and_plural():
    assert format_interval(3600) == "1 hour"
    assert format_interval(7200) == "2 hours"


def test_format_interval_falls_back_to_hours_for_inexact_values():
    """A custom value that is not a whole number of any larger unit still has
    to render as something an admin can read back."""
    assert format_interval(5400) == "5400 seconds"


def test_every_preset_is_at_or_above_the_floor():
    for label, seconds in PRESETS + RETRY_PRESETS:
        assert seconds >= MIN_INTERVAL_SECONDS, label


def test_preset_labels_match_their_seconds():
    """Guards against a typo'd table entry offering '2 weeks' that is secretly
    one week -- the label is what the admin trusts."""
    for label, seconds in PRESETS + RETRY_PRESETS:
        assert format_interval(seconds) == label


def test_presets_are_ordered_shortest_first():
    values = [seconds for _, seconds in PRESETS]
    assert values == sorted(values)


@pytest.mark.asyncio
async def test_resolve_schedule_returns_defaults_for_new_company(db_pool, company):
    """A company nobody has configured must behave exactly as the fleet did
    before this feature existed: 6 months, 24 h retry."""
    company_id, _ = company
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule == {
        "checkin_interval_seconds": 15552000,
        "cancel_retry_seconds": 86400,
    }


@pytest.mark.asyncio
async def test_resolve_schedule_reads_configured_values(db_pool, company):
    company_id, _ = company
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE companies SET checkin_interval_seconds = $2, "
            "cancel_retry_seconds = $3 WHERE id = $1",
            uuid.UUID(company_id), 43200, 14400,
        )
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 43200
    assert schedule["cancel_retry_seconds"] == 14400
