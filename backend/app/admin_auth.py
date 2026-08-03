import bcrypt
import asyncpg

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
