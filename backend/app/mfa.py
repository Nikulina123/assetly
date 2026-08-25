"""TOTP multi-factor authentication primitives for the admin tier.

Pure functions only -- no database, no request object. Persistence lives in
app/admin_auth.py and the flow lives in app/routers/admin.py, so this module
can be unit-tested against the RFC 6238 vectors without a database.

WHY THE SEED IS ENCRYPTED AT REST
A TOTP seed is not a password hash. A password hash is a one-way check and a
stolen one is near-useless; a TOTP seed is a live credential -- read it once
and you can generate valid second factors indefinitely, silently, leaving
nothing in any log. NIST SP 800-63B requires the verifier's copy of an
authenticator secret to be encrypted with the key held separately from the
secret. Database dumps travel to backups, laptops, and support tickets; the
environment does not travel with them, which is the separation being bought.

WHY THE KEY IS DERIVED RATHER THAN ITS OWN REQUIRED VARIABLE
A new REQUIRED environment variable creates a new deployment failure mode:
ship the code before setting the variable and admin login is dead. That shape
of failure -- a security change that silently breaks the product -- is exactly
what this remediation round is trying not to repeat. Deriving from
SESSION_SECRET_KEY via HKDF with a distinct info label keeps the key out of
the database (the property that actually matters) while keeping the rollout to
one migration and one code push. MFA_SECRET_KEY overrides it when the two need
to rotate independently.

THE TRADE, STATED PLAINLY: rotating SESSION_SECRET_KEY invalidates every
stored TOTP secret. That rotation already invalidates every session and logs
every admin out. Recovery codes are bcrypt-hashed independently of this key
and keep working, so the failure mode is "admins re-enroll", never "admins are
locked out". decrypt_secret() returns None rather than raising precisely so
that path degrades into forced re-enrollment.
"""
import base64
import re
import secrets

import bcrypt
import pyotp
import segno
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import MFA_SECRET_KEY, SESSION_SECRET_KEY

ISSUER = "Assetly"
RECOVERY_CODE_COUNT = 10

# No 'l', '1', 'o', '0' -- these are read off a screen and typed back by hand,
# often from a printout, and a code that fails because of a misread character
# sends someone down the account-recovery path this exists to avoid.
_RECOVERY_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"
_RECOVERY_GROUP_LEN = 5
_TOTP_CODE = re.compile(r"\A\d{6}\Z")


def _fernet() -> Fernet:
    """Fernet keyed on MFA_SECRET_KEY when set, else derived from
    SESSION_SECRET_KEY. The info label is versioned so a future scheme change
    can derive a different key from the same root secret."""
    root = (MFA_SECRET_KEY or SESSION_SECRET_KEY).encode()
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"assetly-mfa-secret-v1",
    ).derive(root)
    return Fernet(base64.urlsafe_b64encode(derived))


def generate_secret() -> str:
    return pyotp.random_base32()


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(blob: str | None) -> str | None:
    """None -- never an exception -- when the blob cannot be read, so a rotated
    key or a corrupt row becomes 'not enrolled' rather than a 500 on login."""
    if not blob:
        return None
    try:
        return _fernet().decrypt(blob.encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        return None


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def qr_svg(uri: str) -> str:
    """Inline SVG markup. Inline rather than an <img> pointing at an endpoint:
    the secret would otherwise sit in a URL, in access logs and in browser
    history, and the page would need a second authenticated request mid-flow."""
    return segno.make(uri, error="m").svg_inline(scale=5)


def verify_totp(secret: str, code: str | None) -> bool:
    """valid_window=1 allows one 30s step either side, for phone clock drift.
    Wider would meaningfully enlarge the guessing surface; narrower generates
    support tickets."""
    if not code or not _TOTP_CODE.fullmatch(code.strip() if isinstance(code, str) else ""):
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def looks_like_totp(value: str | None) -> bool:
    """Which of the two credentials the one input box received. The formats
    cannot collide -- 6 digits versus two hyphenated groups of five letters and
    digits -- so the user is never asked to say which they are entering."""
    return bool(value) and bool(_TOTP_CODE.fullmatch(value.strip()))


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    def one() -> str:
        chars = "".join(
            secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_GROUP_LEN * 2)
        )
        return f"{chars[:_RECOVERY_GROUP_LEN]}-{chars[_RECOVERY_GROUP_LEN:]}"

    codes: set[str] = set()
    while len(codes) < count:
        codes.add(one())
    return sorted(codes)


def hash_recovery_code(code: str) -> str:
    """bcrypt, not SHA-256. API keys and enrollment tokens are 256-bit random
    values where a fast hash is fine; a recovery code is short enough to be
    worth attacking offline if the table ever leaks."""
    return bcrypt.hashpw(code.strip().lower().encode(), bcrypt.gensalt()).decode()


def verify_recovery_code(code: str, code_hash: str) -> bool:
    try:
        return bcrypt.checkpw(code.strip().lower().encode(), code_hash.encode())
    except (ValueError, TypeError):
        return False
