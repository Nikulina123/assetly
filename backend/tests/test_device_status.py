import datetime

from app.device_status import derive_status

NOW = datetime.datetime(2026, 8, 5, 12, 0, 0, tzinfo=datetime.timezone.utc)

SIX_MONTHS = 15552000   # the default interval: 180 days
ONE_DAY = 86400


def _ago(days):
    return NOW - datetime.timedelta(days=days)


def test_recent_checkin_is_online():
    assert derive_status(_ago(1), NOW, SIX_MONTHS) == "online"


def test_just_inside_online_boundary():
    assert derive_status(_ago(179), NOW, SIX_MONTHS) == "online"


def test_just_outside_online_boundary_is_pending():
    """A device seen 181 days ago has missed its window and needs attention --
    but is not yet abandoned."""
    assert derive_status(_ago(181), NOW, SIX_MONTHS) == "pending"


def test_just_outside_pending_boundary_is_offline():
    assert derive_status(_ago(271), NOW, SIX_MONTHS) == "offline"


def test_never_seen_is_offline():
    """A device row with no last_seen_at is exactly what an IT manager needs
    surfaced, so it sorts as offline rather than being hidden."""
    assert derive_status(None, NOW, SIX_MONTHS) == "offline"


def test_default_interval_reproduces_the_historic_180_270_bands():
    """The whole point of the 1.5x grace multiplier: at the default interval
    the boundaries are byte-for-byte the ones the fixed day constants gave,
    so no existing company's dashboard changes."""
    assert derive_status(_ago(180), NOW, SIX_MONTHS) == "online"
    assert derive_status(_ago(180.5), NOW, SIX_MONTHS) == "pending"
    assert derive_status(_ago(270), NOW, SIX_MONTHS) == "pending"
    assert derive_status(_ago(270.5), NOW, SIX_MONTHS) == "offline"


def test_short_interval_company_gets_proportionate_bands():
    """A company on a 24 h cadence must not see every device as 'online' for
    half a year -- the failure this change exists to prevent."""
    assert derive_status(_ago(0.5), NOW, ONE_DAY) == "online"
    assert derive_status(_ago(1.2), NOW, ONE_DAY) == "pending"
    assert derive_status(_ago(2), NOW, ONE_DAY) == "offline"
