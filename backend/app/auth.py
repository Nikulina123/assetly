import hashlib
import secrets

import asyncpg

from app.config import ALLOW_LEGACY_COMPANY_KEY_CHECKIN


def generate_api_key() -> str:
    # Keys issued before the Assetly rebrand carry a "wz_live_" prefix and keep
    # working: resolve_company_id matches on a SHA-256 hash of the whole string,
    # never on the prefix, so old and new keys coexist with no migration.
    return "as_live_" + secrets.token_hex(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


async def resolve_company_id(pool: asyncpg.Pool, api_key: str) -> str | None:
    key_hash = hash_api_key(api_key)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id FROM companies WHERE api_key_hash = $1 AND revoked_at IS NULL",
            key_hash,
        )
    return str(row["id"]) if row else None


async def resolve_credential(
    pool: asyncpg.Pool, bearer: str
) -> tuple[str, str | None, str | None] | None:
    """Returns (company_id, device_credential_id, enrolled_serial) for a device
    credential, (company_id, None, None) for a legacy company key, or None if
    neither matches.

    The enrolled serial is returned so the check-in handler can bind a payload
    to the machine its credential was issued for. It is None on the legacy
    path because a company key is not issued for any particular machine --
    that path is exempt from binding until ALLOW_LEGACY_COMPANY_KEY_CHECKIN
    is flipped to false.

    Device credentials are checked first: once a machine has enrolled it should
    never fall through to the shared key path.
    """
    key_hash = hash_api_key(bearer)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, company_id, serial_number FROM device_credentials "
            "WHERE credential_hash = $1 AND revoked_at IS NULL",
            key_hash,
        )
        if row is not None:
            return str(row["company_id"]), str(row["id"]), row["serial_number"]
        if not ALLOW_LEGACY_COMPANY_KEY_CHECKIN:
            return None
        row = await conn.fetchrow(
            "SELECT id FROM companies WHERE api_key_hash = $1 AND revoked_at IS NULL",
            key_hash,
        )
        return (str(row["id"]), None, None) if row else None
