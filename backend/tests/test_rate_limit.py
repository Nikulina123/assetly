import datetime

import pytest

from app.rate_limit import check_rate_limit


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
