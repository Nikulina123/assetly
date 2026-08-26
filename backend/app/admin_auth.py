import dataclasses
import uuid

import bcrypt
import asyncpg

from app import mfa

# Fixed dummy hash, used only to burn the same bcrypt cost as a real check
# when the email doesn't exist — otherwise a missing-row early return is
# measurably faster than a wrong-password check, letting an attacker
# enumerate valid admin emails by timing /admin/login responses.
_DUMMY_PASSWORD_HASH = "$2b$12$8wj2J/fjrDZRS.b.QmhxduLOuf3x12GCE2Y2qs2q4nwllKcEn1KYK"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


async def resolve_admin(pool: asyncpg.Pool, email: str, password: str) -> str | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, password_hash FROM admins WHERE email = $1", email
        )
    if row is None:
        verify_password(password, _DUMMY_PASSWORD_HASH)
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return str(row["id"])


@dataclasses.dataclass(frozen=True)
class AdminContext:
    """Who the caller is, read from the database on every admin request rather
    than trusted from the signed cookie.

    The cookie stays authoritative for identity only. Role and scope come from
    the row, so a demotion, a scope change, or a deleted account takes effect
    on the next request instead of at cookie expiry -- which is also a partial
    answer to M-3 (no server-side session revocation) for the cost of one
    primary-key lookup.
    """
    id: str
    email: str
    role: str
    company_id: str | None
    mfa_enrolled: bool

    @property
    def is_full_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_global(self) -> bool:
        return self.company_id is None


async def load_admin_context(pool, admin_id: str) -> AdminContext | None:
    """None when the id is unknown or unparseable -- a cookie naming a deleted
    admin authenticates nobody."""
    try:
        parsed_id = uuid.UUID(admin_id)
    except (ValueError, TypeError, AttributeError):
        return None
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, role, company_id, mfa_secret FROM admins WHERE id = $1",
            parsed_id,
        )
    if row is None:
        return None
    return AdminContext(
        id=str(row["id"]),
        email=row["email"],
        role=row["role"],
        company_id=str(row["company_id"]) if row["company_id"] else None,
        # Enrolled means "there is a secret we can actually read". A row whose
        # blob no longer decrypts (rotated key, corruption) is deliberately
        # reported as NOT enrolled, so the flow sends the admin to
        # re-enrollment instead of to a verification step that can never pass.
        mfa_enrolled=mfa.decrypt_secret(row["mfa_secret"]) is not None,
    )


async def get_mfa_secret(pool, admin_id: str) -> str | None:
    async with pool.acquire() as conn:
        blob = await conn.fetchval(
            "SELECT mfa_secret FROM admins WHERE id = $1", uuid.UUID(admin_id)
        )
    return mfa.decrypt_secret(blob)


async def set_mfa_secret(conn, admin_id: str, secret: str) -> None:
    """Takes a connection, not a pool: enrollment writes the secret and the
    recovery codes and the audit row in ONE transaction, so a half-enrolled
    admin -- secret set, codes missing -- cannot exist."""
    await conn.execute(
        "UPDATE admins SET mfa_secret = $1, mfa_enrolled_at = NOW() WHERE id = $2",
        mfa.encrypt_secret(secret), uuid.UUID(admin_id),
    )


async def replace_recovery_codes(conn, admin_id: str, codes: list[str]) -> None:
    """Replaces, never appends: regenerating a set must invalidate the old one,
    or a printout from a year ago stays live forever."""
    await conn.execute(
        "DELETE FROM admin_recovery_codes WHERE admin_id = $1", uuid.UUID(admin_id)
    )
    await conn.executemany(
        "INSERT INTO admin_recovery_codes (admin_id, code_hash) VALUES ($1, $2)",
        [(uuid.UUID(admin_id), mfa.hash_recovery_code(code)) for code in codes],
    )


async def consume_recovery_code(conn, admin_id: str, code: str) -> bool:
    """Marks the matching unused code used and reports whether one matched.

    Each stored hash has its own bcrypt salt, so this cannot be a WHERE clause
    on a hash -- it is a comparison per unused code. Bounded at 10, reached
    only on the recovery path, and rate-limited at the route.

    The UPDATE's `used_at IS NULL` predicate is what makes single-use hold
    under concurrency: two simultaneous requests presenting the same code both
    match the bcrypt compare, but only one UPDATE returns a row.
    """
    rows = await conn.fetch(
        "SELECT id, code_hash FROM admin_recovery_codes "
        "WHERE admin_id = $1 AND used_at IS NULL",
        uuid.UUID(admin_id),
    )
    for row in rows:
        if mfa.verify_recovery_code(code, row["code_hash"]):
            claimed = await conn.fetchval(
                "UPDATE admin_recovery_codes SET used_at = NOW() "
                "WHERE id = $1 AND used_at IS NULL RETURNING id",
                row["id"],
            )
            return claimed is not None
    return False


async def count_unused_recovery_codes(pool, admin_id: str) -> int:
    async with pool.acquire() as conn:
        return await conn.fetchval(
            "SELECT COUNT(*) FROM admin_recovery_codes "
            "WHERE admin_id = $1 AND used_at IS NULL",
            uuid.UUID(admin_id),
        )
