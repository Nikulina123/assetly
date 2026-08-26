"""Enrollment tokens and per-device credentials.

Every query sets app.company_id inside its transaction so Postgres RLS enforces
tenant isolation, matching devices.py. Only hashes are stored -- plaintext
tokens and credentials are returned once at creation and never again.
"""
import datetime
import secrets
import uuid

import asyncpg

from app.auth import hash_api_key
from app.config import ENROLLMENT_TOKEN_DAYS


class EnrollmentError(Exception):
    """Raised for a token that is unknown, expired, revoked, or exhausted."""


class UnknownTokenError(EnrollmentError):
    """The bearer matched no enrollment token. Callers may fall back to the
    legacy company-key path; every other EnrollmentError is terminal."""


def _generate_token() -> str:
    return "as_enroll_" + secrets.token_hex(32)


def _generate_credential() -> str:
    return "as_dev_" + secrets.token_hex(32)


async def _scoped(conn, company_id: str) -> None:
    await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)


async def create_enrollment_token(
    pool: asyncpg.Pool,
    company_id: str,
    label: str,
    expires_at: datetime.datetime | None = None,
    max_devices: int | None = None,
    conn=None,
    token_id: uuid.UUID | None = None,
) -> str:
    """`conn`, when given, is used directly instead of acquiring a new one --
    so a caller running this inside an `audited()` block (see app/audit.py)
    can pass `scope.conn` and keep the insert in the same transaction as its
    audit row, rather than silently forking off a second connection.

    `token_id`, when given, is used as the row's primary key instead of
    letting the column's DEFAULT gen_random_uuid() pick one. That lets a
    caller know the id BEFORE this returns, which is what an audit row needs:
    `enrollment_token.created` and `enrollment_token.revoked` must carry the
    SAME target_id, or an investigator holding a revoke row has no way to
    find when the token was minted and by whom. The return value stays the
    plaintext token so every existing caller is unaffected.
    """
    token = _generate_token()
    if expires_at is None:
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=ENROLLMENT_TOKEN_DAYS
        )
    if token_id is None:
        token_id = uuid.uuid4()

    async def _insert(c):
        await _scoped(c, company_id)
        await c.execute(
            "INSERT INTO enrollment_tokens "
            "(id, company_id, token_hash, token_prefix, label, expires_at, max_devices) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7)",
            token_id, uuid.UUID(company_id), hash_api_key(token), token[:18],
            label, expires_at, max_devices,
        )

    if conn is not None:
        await _insert(conn)
    else:
        async with pool.acquire() as acquired:
            async with acquired.transaction():
                await _insert(acquired)
    return token


async def list_tokens(pool: asyncpg.Pool, company_id: str) -> list[dict]:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await _scoped(conn, company_id)
            rows = await conn.fetch(
                "SELECT id, token_prefix, label, created_at, expires_at, max_devices, "
                "used_count, revoked_at FROM enrollment_tokens "
                "WHERE company_id = $1 ORDER BY created_at DESC",
                uuid.UUID(company_id),
            )
    return [dict(r) for r in rows]


async def revoke_token(pool: asyncpg.Pool, company_id: str, token_id: str, conn=None) -> None:
    """See create_enrollment_token's docstring for what `conn` is for."""
    async def _revoke(c):
        await _scoped(c, company_id)
        await c.execute(
            "UPDATE enrollment_tokens SET revoked_at = NOW() "
            "WHERE company_id = $1 AND id = $2 AND revoked_at IS NULL",
            uuid.UUID(company_id), uuid.UUID(token_id),
        )

    if conn is not None:
        await _revoke(conn)
    else:
        async with pool.acquire() as acquired:
            async with acquired.transaction():
                await _revoke(acquired)


async def revoke_device_credential(
    pool: asyncpg.Pool, company_id: str, serial_number: str, conn=None
) -> int:
    """Returns the number of rows actually revoked (0 or 1) -- the caller
    needs this, not just a fire-and-forget completion, so a revoke that
    silently matched nothing (wrong serial, already revoked, wrong company)
    can be told apart from one that actually took effect. See
    create_enrollment_token's docstring for what `conn` is for."""
    # device_credentials.serial_number is stored normalised (see enroll_device
    # below) -- normalise the lookup key the same way, or a caller passing the
    # machine's real casing (e.g. from the devices table) would silently
    # match nothing and leave the credential live.
    normalized_serial = serial_number.strip().casefold()

    async def _revoke(c) -> int:
        await _scoped(c, company_id)
        status = await c.execute(
            "UPDATE device_credentials SET revoked_at = NOW() "
            "WHERE company_id = $1 AND serial_number = $2 AND revoked_at IS NULL",
            uuid.UUID(company_id), normalized_serial,
        )
        # asyncpg's execute() returns a command tag like "UPDATE 1" -- the
        # trailing token is the actual row count Postgres reports, which is
        # the real signal (not an assumption that the WHERE clause matched).
        return int(status.split()[-1])

    if conn is not None:
        return await _revoke(conn)
    async with pool.acquire() as acquired:
        async with acquired.transaction():
            return await _revoke(acquired)


async def list_device_credentials(pool: asyncpg.Pool, company_id: str) -> list[dict]:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await _scoped(conn, company_id)
            rows = await conn.fetch(
                "SELECT serial_number, hostname, enrolled_at, last_used_at, revoked_at "
                "FROM device_credentials WHERE company_id = $1 ORDER BY enrolled_at DESC",
                uuid.UUID(company_id),
            )
    return [dict(r) for r in rows]


async def _resolve_token_row(conn, token: str):
    return await conn.fetchrow(
        "SELECT id, company_id, expires_at, max_devices, used_count, revoked_at "
        "FROM enrollment_tokens WHERE token_hash = $1",
        hash_api_key(token),
    )


async def enroll_device(
    pool: asyncpg.Pool, token: str, serial_number: str, hostname: str | None
) -> str:
    """Exchanges an enrollment token for a per-device credential.

    Token lookup runs WITHOUT a tenant scope set, because the caller is an
    unauthenticated agent that does not yet know its company -- the token IS
    the claim. company_id comes from the matched row, and every write after
    that point is scoped to it.
    """
    credential = _generate_credential()
    now = datetime.datetime.now(datetime.timezone.utc)
    # Normalised for storage in device_credentials ONLY -- this is the value
    # checkin.py's binding check compares against, and install-time
    # enrollment (Task 12) now collects the serial via a root shell
    # (ioreg / dmidecode) rather than the agent's own collector, so a case or
    # whitespace drift between the two is likelier than it used to be.
    # devices.serial_number and device_checkins.serial_number are unaffected
    # by this: those are inventory/display values and must keep the
    # machine's real casing, so callers still pass the raw serial_number for
    # anything outside device_credentials.
    normalized_serial = serial_number.strip().casefold()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await _resolve_token_row(conn, token)
            if row is None:
                raise UnknownTokenError("Unknown enrollment token")
            if row["revoked_at"] is not None:
                raise EnrollmentError("Enrollment token has been revoked")
            if row["expires_at"] <= now:
                raise EnrollmentError("Enrollment token has expired")

            company_id = str(row["company_id"])
            await _scoped(conn, company_id)

            existing = await conn.fetchval(
                "SELECT id FROM device_credentials "
                "WHERE company_id = $1 AND serial_number = $2",
                row["company_id"], normalized_serial,
            )
            if existing is None and row["max_devices"] is not None:
                if row["used_count"] >= row["max_devices"]:
                    raise EnrollmentError("Enrollment token device limit reached")

            await conn.execute(
                "INSERT INTO device_credentials "
                "(company_id, credential_hash, serial_number, hostname, enrolled_via) "
                "VALUES ($1, $2, $3, $4, $5) "
                "ON CONFLICT (company_id, serial_number) DO UPDATE SET "
                "credential_hash = EXCLUDED.credential_hash, "
                "hostname = EXCLUDED.hostname, "
                "enrolled_at = NOW(), revoked_at = NULL",
                row["company_id"], hash_api_key(credential), normalized_serial,
                hostname, row["id"],
            )
            if existing is None:
                # Counts machines, not installer runs -- a re-enroll of a serial
                # already on file must not consume another slot.
                await conn.execute(
                    "UPDATE enrollment_tokens SET used_count = used_count + 1 WHERE id = $1",
                    row["id"],
                )
    return credential
