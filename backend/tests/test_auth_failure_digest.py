import datetime

import pytest

from app.notifications import maybe_send_auth_failure_digest, record_auth_failure


@pytest.fixture
def sent(monkeypatch):
    """Records Sendly sends instead of performing them."""
    calls = []
    import app.notifications as notifications

    monkeypatch.setattr(
        notifications, "send_email", lambda to, subject, html, text=None: calls.append(
            {"to": to, "subject": subject, "html": html}
        )
    )
    monkeypatch.setattr(notifications, "OPS_ALERT_EMAIL", "ops@example.com")
    return calls


@pytest.mark.asyncio
async def test_recording_a_failure_sends_no_email(db_pool, sent):
    """The whole point of H-3: an unauthenticated request must not be able to
    cause outbound email."""
    for _ in range(50):
        await record_auth_failure(db_pool, "as_live_", "203.0.113.5")
    assert sent == []
    async with db_pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM auth_failure_events") == 50


@pytest.mark.asyncio
async def test_digest_sends_once_per_interval(db_pool, sent):
    await record_auth_failure(db_pool, "as_live_", "203.0.113.5")
    await maybe_send_auth_failure_digest(db_pool)
    assert len(sent) == 1

    await record_auth_failure(db_pool, "as_live_", "203.0.113.5")
    await maybe_send_auth_failure_digest(db_pool)
    assert len(sent) == 1, "a second digest went out inside the same interval"


@pytest.mark.asyncio
async def test_digest_resends_after_the_interval(db_pool, sent):
    await record_auth_failure(db_pool, "as_live_", "203.0.113.5")
    await maybe_send_auth_failure_digest(db_pool)
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE notification_state SET last_digest_sent_at = "
            "last_digest_sent_at - INTERVAL '2 hours'"
        )
    await record_auth_failure(db_pool, "as_live_", "203.0.113.5")
    await maybe_send_auth_failure_digest(db_pool)
    assert len(sent) == 2


@pytest.mark.asyncio
async def test_daily_cap_holds(db_pool, sent):
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE notification_state SET digests_sent_today = 24, digest_day = CURRENT_DATE"
        )
    await record_auth_failure(db_pool, "as_live_", "203.0.113.5")
    await maybe_send_auth_failure_digest(db_pool)
    assert sent == []


@pytest.mark.asyncio
async def test_digest_discloses_no_live_key_material(db_pool, sent):
    """L-2: the old code emailed the first 16 characters of the rejected
    bearer, which for as_live_ + hex is 8 hex characters of live secret sent
    to a third-party email vendor."""
    await record_auth_failure(db_pool, "as_live_", "203.0.113.5")
    await maybe_send_auth_failure_digest(db_pool)
    body = sent[0]["html"]
    assert "as_live_" in body
    assert "deadbeef" not in body


@pytest.mark.asyncio
async def test_no_digest_when_there_is_nothing_to_report(db_pool, sent):
    await maybe_send_auth_failure_digest(db_pool)
    assert sent == []
