import datetime

import asyncpg
import pytest
from starlette.requests import Request

from app.rate_limit import check_rate_limit, client_ip
from tests.conftest import ADMIN_TEST_DATABASE_URL


def _make_request(headers: dict[str, str]) -> Request:
    encoded_headers = [
        (k.lower().encode(), v.encode()) for k, v in headers.items()
    ]
    scope = {
        "type": "http",
        "headers": encoded_headers,
        "client": ("192.0.2.1", 12345),
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_allows_up_to_the_limit(db_pool):
    for attempt in range(5):
        allowed, retry_after = await check_rate_limit(
            db_pool, "test:allow", limit=5, window_seconds=900
        )
        assert allowed is True, f"attempt {attempt} was rejected"
        assert retry_after == 0


@pytest.mark.asyncio
async def test_rejects_past_the_limit(db_pool):
    for _ in range(5):
        await check_rate_limit(db_pool, "test:reject", limit=5, window_seconds=900)
    allowed, retry_after = await check_rate_limit(
        db_pool, "test:reject", limit=5, window_seconds=900
    )
    assert allowed is False
    assert 0 < retry_after <= 900


@pytest.mark.asyncio
async def test_buckets_are_independent(db_pool):
    for _ in range(5):
        await check_rate_limit(db_pool, "test:a", limit=5, window_seconds=900)
    allowed, _ = await check_rate_limit(db_pool, "test:b", limit=5, window_seconds=900)
    assert allowed is True


@pytest.mark.asyncio
async def test_a_new_window_resets_the_count(db_pool):
    """Proven by ageing the stored row rather than by sleeping: a test that
    waits out a real window is either slow or uses a window so short it
    proves nothing about the production configuration."""
    for _ in range(5):
        await check_rate_limit(db_pool, "test:window", limit=5, window_seconds=900)
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE rate_limit_hits SET window_start = window_start - INTERVAL '1 hour' "
            "WHERE bucket_key = $1",
            "test:window",
        )
    allowed, _ = await check_rate_limit(
        db_pool, "test:window", limit=5, window_seconds=900
    )
    assert allowed is True


@pytest.mark.asyncio
async def test_missing_table_fails_open_instead_of_raising(db_pool):
    """Reproduces deploying the code before migration 013: rate_limit_hits
    does not exist yet. check_rate_limit must not raise -- it must fail open
    (allow the request) so /admin/login, /api/v1/enroll, /checkin, /config,
    and /agent/manifest don't 500 on every call during that deploy gap."""
    admin_conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
    try:
        await admin_conn.execute("ALTER TABLE rate_limit_hits RENAME TO rate_limit_hits_hidden")
        try:
            allowed, retry_after = await check_rate_limit(
                db_pool, "test:missing-table", limit=1, window_seconds=900
            )
        finally:
            await admin_conn.execute(
                "ALTER TABLE rate_limit_hits_hidden RENAME TO rate_limit_hits"
            )
    finally:
        await admin_conn.close()

    assert allowed is True
    assert retry_after == 0


def test_client_ip_rejects_spoofed_leftmost_forwarded_for():
    """An attacker can send X-Forwarded-For: <victim-ip>, <junk> since the
    header is appended-to, not replaced, by each proxy hop. Taking the first
    entry would bucket the attacker's traffic under the victim's IP -- bucket
    poisoning against a per-IP rate limit. The last entry is the one the
    nearest trusted proxy appended and is not attacker-controlled."""
    request = _make_request(
        {"x-forwarded-for": "198.51.100.7, 203.0.113.9"}
    )
    ip = client_ip(request)
    assert ip != "198.51.100.7"
    assert ip == "203.0.113.9"


def test_client_ip_prefers_platform_header_over_forwarded_for():
    """x-vercel-forwarded-for is set by the Vercel platform itself and cannot
    be forged by the client through the proxy, so it must win over
    x-forwarded-for (whose leftmost entries are client-controlled)."""
    request = _make_request(
        {
            "x-forwarded-for": "198.51.100.7, 203.0.113.9",
            "x-vercel-forwarded-for": "203.0.113.55",
        }
    )
    assert client_ip(request) == "203.0.113.55"
