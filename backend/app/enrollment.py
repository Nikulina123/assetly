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
) -> str:
    token = _generate_token()
    if expires_at is None:
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=ENROLLMENT_TOKEN_DAYS
        )
    async with pool.acquire() as conn:
        async with conn.transaction():
            await _scoped(conn, company_id)
            await conn.execute(
                "INSERT INTO enrollment_tokens "
                "(company_id, token_hash, token_prefix, label, expires_at, max_devices) "
                "VALUES ($1, $2, $3, $4, $5, $6)",
                uuid.UUID(company_id), hash_api_key(token), token[:18],
                label, expires_at, max_devices,
            )
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


async def revoke_token(pool: asyncpg.Pool, company_id: str, token_id: str) -> None:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await _scoped(conn, company_id)
            await conn.execute(
                "UPDATE enrollment_tokens SET revoked_at = NOW() "
                "WHERE company_id = $1 AND id = $2 AND revoked_at IS NULL",
                uuid.UUID(company_id), uuid.UUID(token_id),
            )


async def revoke_device_credential(
    pool: asyncpg.Pool, company_id: str, serial_number: str
) -> None:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await _scoped(conn, company_id)
            await conn.execute(
                "UPDATE device_credentials SET revoked_at = NOW() "
                "WHERE company_id = $1 AND serial_number = $2 AND revoked_at IS NULL",
                uuid.UUID(company_id), serial_number,
            )


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
                row["company_id"], serial_number,
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
                row["company_id"], hash_api_key(credential), serial_number,
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
