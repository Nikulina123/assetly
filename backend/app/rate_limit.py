"""Fixed-window rate limiting backed by Postgres.

Postgres rather than an in-process counter because this deploys serverless:
each warm instance has its own memory, so an in-process limiter enforces
nothing across the fleet of instances. See migrations/013_rate_limit.sql for
the fixed-vs-sliding-window reasoning.
"""
import datetime
import hashlib
import logging
import random

import asyncpg
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

# Fraction of calls that also prune expired rows. There is no scheduler on this
# deployment and adding one for table hygiene is not warranted; at any real
# traffic level this keeps the table bounded, and at no traffic an unpruned
# table is not a problem.
_PRUNE_PROBABILITY = 0.01
_PRUNE_AGE = datetime.timedelta(hours=24)


def client_ip(request: Request) -> str:
    """The caller's IP, for use as a rate-limit bucket key.

    Deliberately does NOT take x-forwarded-for's first entry. x-forwarded-for
    is APPENDED to by each proxy, not replaced -- the client sets the header
    on the initial request, and every hop after that only adds its own entry
    to the right. That means the leftmost entry is attacker-controlled: a
    caller can send `X-Forwarded-For: <victim-ip>, <junk>` and have their own
    traffic bucketed under the victim's IP. Against a per-IP rate limit that
    is bucket poisoning, not just self-bucketing -- it lets an attacker burn a
    legitimate user's (e.g. an admin's) request budget from anywhere and lock
    them out. Do not "fix" this back to split(",")[0] -- that reintroduces the
    poisoning vector this comment exists to document.

    Preference order:
    1. x-vercel-forwarded-for / x-real-ip -- set by the Vercel platform itself
       (this app deploys on Vercel, see vercel.json) and overwritten on the
       way in, so a client cannot forge them through the proxy.
    2. The LAST entry of x-forwarded-for -- the nearest trusted proxy is the
       one that appended it, so it's the only entry in that header a client
       cannot control. Entries to its left may be attacker-supplied.
    3. request.client.host -- the raw socket peer.

    Still best-effort, and still must not be used as an authorisation input:
    it identifies a bucket to rate-limit, not a verified caller identity."""
    platform_ip = request.headers.get("x-vercel-forwarded-for") or request.headers.get(
        "x-real-ip"
    )
    if platform_ip:
        return platform_ip.split(",")[0].strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
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

    try:
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
    except asyncpg.UndefinedTableError:
        # Narrow and deliberate: this fires only when rate_limit_hits itself
        # does not exist, which means migration 013 has not been applied yet
        # against code that already calls enforce_rate_limit on /admin/login,
        # /api/v1/enroll, /checkin, /config, and /agent/manifest. Without this
        # catch, deploying the code before the migration turns every one of
        # those routes into a 500 -- the entire API goes down over a table
        # that exists purely to rate-limit, not to serve the request.
        #
        # Fail OPEN (allow) rather than reject: the alternative to "no rate
        # limiting for a few minutes during a bad deploy order" is "the API is
        # completely down", and the former is clearly the lesser failure.
        # This must stay a narrow except on UndefinedTableError specifically,
        # never a blanket `except Exception` -- broadening it would silently
        # disable rate limiting on any transient database hiccup, not just
        # this one unambiguous "table does not exist" case.
        logger.error(
            "rate_limit_hits table does not exist -- migration 013 has not "
            "been applied. Failing open (request allowed) for bucket %r. "
            "Apply migrations/013_rate_limit.sql before code that calls "
            "enforce_rate_limit is deployed.",
            bucket_key,
        )
        return True, 0

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
