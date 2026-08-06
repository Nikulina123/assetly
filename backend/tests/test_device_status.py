import datetime

from app.device_status import derive_status

NOW = datetime.datetime(2026, 8, 5, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _ago(days):
    return NOW - datetime.timedelta(days=days)


def test_recent_checkin_is_online():
    assert derive_status(_ago(1), NOW) == "online"


def test_just_inside_online_boundary():
    assert derive_status(_ago(179), NOW) == "online"


def test_just_outside_online_boundary_is_pending():
    """The agent's INTERVAL_MONTHS is 6, so a device seen 181 days ago has
    missed its window and needs attention -- but is not yet abandoned."""
    assert derive_status(_ago(181), NOW) == "pending"


def test_just_outside_pending_boundary_is_offline():
    assert derive_status(_ago(271), NOW) == "offline"


def test_never_seen_is_offline():
    """A device row with no last_seen_at is exactly what an IT manager needs
    surfaced, so it sorts as offline rather than being hidden."""
    assert derive_status(None, NOW) == "offline"
