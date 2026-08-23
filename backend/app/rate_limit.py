"""Fixed-window rate limiting backed by Postgres.

Postgres rather than an in-process counter because this deploys serverless:
each warm instance has its own memory, so an in-process limiter enforces
nothing across the fleet of instances. See migrations/013_rate_limit.sql for
the fixed-vs-sliding-window reasoning.
"""
import datetime
import hashlib
import random

import asyncpg
from fastapi import HTTPException, Request

# Fraction of calls that also prune expired rows. There is no scheduler on this
# deployment and adding one for table hygiene is not warranted; at any real
# traffic level this keeps the table bounded, and at no traffic an unpruned
# table is not a problem.
_PRUNE_PROBABILITY = 0.01
_PRUNE_AGE = datetime.timedelta(hours=24)


def client_ip(request: Request) -> str:
    """The caller's IP. Vercel terminates TLS and forwards, so the socket peer
    is the platform's proxy for every request -- x-forwarded-for's FIRST entry
    is the original client. Later entries are proxies and the header is
    caller-controlled, so this is a best-effort key for rate limiting and must
    not be used as an authorisation input."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def hashed_bucket(prefix: str, value: str) -> str:
    """Bucket key for a per-account limit. The value is hashed so the
    rate_limit_hits table cannot be read as a list of admin email addresses --
    the table holds no tenant data and should hold no identifying data either."""
    digest = hashlib.sha256(value.strip().lower().encode()).hexdigest()[:32]
    return f"{prefix}:{digest}"


def _window_start(window_seconds: int, now: datetime.datetime) -> datetime.datetime:
    epoch_seconds = int(now.timestamp())
    return datetime.datetime.fromtimestamp(
        epoch_seconds - (epoch_seconds % window_seconds), tz=datetime.timezone.utc
    )


async def check_rate_limit(
    pool: asyncpg.Pool, bucket_key: str, limit: int, window_seconds: int
) -> tuple[bool, int]:
    """Records one hit and reports whether it was within the limit.

    Returns (allowed, retry_after_seconds). retry_after_seconds is 0 when
    allowed, and otherwise the seconds remaining in the current window.

    The hit is recorded even when it is over the limit: a rejected attempt is
    still an attempt, and not counting it would let an attacker stay just under
    the threshold forever by ignoring the 429s.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    window_start = _window_start(window_seconds, now)

    async with pool.acquire() as conn:
        count = await conn.fetchval(
            """
            INSERT INTO rate_limit_hits (bucket_key, window_start, count)
            VALUES ($1, $2, 1)
            ON CONFLICT (bucket_key, window_start)
            DO UPDATE SET count = rate_limit_hits.count + 1
            RETURNING count
            """,
            bucket_key, window_start,
        )
        if random.random() < _PRUNE_PROBABILITY:
            await conn.execute(
                "DELETE FROM rate_limit_hits WHERE window_start < $1", now - _PRUNE_AGE
            )

    if count <= limit:
        return True, 0
    window_end = window_start + datetime.timedelta(seconds=window_seconds)
    return False, max(1, int((window_end - now).total_seconds()))


async def enforce_rate_limit(
    pool: asyncpg.Pool, bucket_key: str, limit: int, window_seconds: int
) -> None:
    """check_rate_limit, raising 429 instead of returning a flag."""
    allowed, retry_after = await check_rate_limit(
        pool, bucket_key, limit, window_seconds
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
