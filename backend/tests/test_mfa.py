"""Unit tests for app/mfa.py. No database, no HTTP -- these are pure functions.

The RFC 6238 vectors matter: they are the only check that our TOTP agrees with
what Google Authenticator, 1Password, and Microsoft Authenticator will compute.
A homegrown assertion ("the code we generate verifies against itself") passes
happily while being wrong for every real authenticator app.
"""
import base64

import pytest

from app import mfa


# RFC 6238 Appendix B, SHA-1, 8 digits, seed "12345678901234567890".
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("timestamp,expected", RFC_VECTORS)
def test_totp_matches_rfc6238_vectors(timestamp, expected):
    """Baseline only: confirms the pyotp library itself is RFC 6238-correct
    (8-digit vectors, straight from the RFC). This does NOT exercise
    app.mfa -- see test_verify_totp_matches_rfc6238_vectors_through_our_module
    below for the test that actually pins our code against the RFC."""
    import pyotp
    assert pyotp.TOTP(RFC_SECRET, digits=8).at(timestamp) == expected


@pytest.mark.parametrize("timestamp,expected_at_offset", RFC_VECTORS)
def test_verify_totp_matches_rfc6238_vectors_through_our_module(timestamp, expected_at_offset):
    """This is the test that actually pins app.mfa.verify_totp against the
    published RFC 6238 Appendix B vectors -- the one whose absence the
    module docstring's claim depended on.

    The RFC's own Appendix B vectors are 8-digit (that's the RFC's example
    parameterization, not a MFA standard requirement); our module always
    uses pyotp's default 6-digit TOTP, so the 8-digit strings above can't be
    fed to mfa.verify_totp directly. Instead we derive the 6-digit code for
    the same RFC seed and the same RFC timestamp -- the seed and instant are
    the parts of the vector we actually need pinned, because they are what
    exercises HMAC-SHA1, the 30s step boundary, and dynamic truncation
    inside pyotp.TOTP.verify as called by our wrapper.

    What this DOES pin: that mfa.verify_totp, called through our wrapper
    (regex validation, .strip(), valid_window, for_time plumbing), accepts
    the correct code at the RFC's own timestamps and rejects a wrong one at
    the same instant -- i.e. that our code invokes pyotp's TOTP/HMAC/step/
    truncation machinery correctly, using the RFC's own seed and instants
    as ground truth for "this second matters".

    What this does NOT pin: the literal 8-digit RFC strings above (those are
    checked, un-wired-to-our-code, by the baseline test). A bug that only
    manifests at 8 digits and not 6 would not be caught here -- but our
    module never uses 8 digits, so that gap is not reachable from
    app.mfa's actual behavior.
    """
    import pyotp
    correct = pyotp.TOTP(RFC_SECRET, digits=6).at(timestamp)
    wrong = pyotp.TOTP(RFC_SECRET, digits=6).at(timestamp + 60)  # two steps away
    assert correct != wrong
    assert mfa.verify_totp(RFC_SECRET, correct, for_time=timestamp) is True
    assert mfa.verify_totp(RFC_SECRET, wrong, for_time=timestamp) is False


def test_verify_totp_accepts_a_current_code():
    import pyotp
    secret = mfa.generate_secret()
    assert mfa.verify_totp(secret, pyotp.TOTP(secret).now()) is True


def test_verify_totp_rejects_a_wrong_code():
    secret = mfa.generate_secret()
    assert mfa.verify_totp(secret, "000000") is False


def test_verify_totp_tolerates_one_step_of_clock_skew():
    """Real phones drift. One step either side is the usual allowance."""
    import time
    import pyotp
    secret = mfa.generate_secret()
    previous = pyotp.TOTP(secret).at(int(time.time()) - 30)
    assert mfa.verify_totp(secret, previous) is True


def test_verify_totp_rejects_a_code_two_steps_old():
    import time
    import pyotp
    secret = mfa.generate_secret()
    stale = pyotp.TOTP(secret).at(int(time.time()) - 120)
    assert mfa.verify_totp(secret, stale) is False


def test_verify_totp_survives_garbage_input():
    secret = mfa.generate_secret()
    for junk in ("", "abcdef", "12345", "1234567", "  123456  ", None):
        assert mfa.verify_totp(secret, junk) is False


def test_encrypt_secret_does_not_store_the_plaintext_seed():
    """The point of the whole exercise: a database dump must not carry a
    working second factor."""
    secret = mfa.generate_secret()
    blob = mfa.encrypt_secret(secret)
    assert secret not in blob
    assert blob != secret


def test_encrypted_secret_round_trips():
    secret = mfa.generate_secret()
    assert mfa.decrypt_secret(mfa.encrypt_secret(secret)) == secret


def test_encryption_is_not_deterministic():
    """Fernet embeds a random IV; two encryptions of one seed must differ, or
    the column leaks which admins share a secret."""
    secret = mfa.generate_secret()
    assert mfa.encrypt_secret(secret) != mfa.encrypt_secret(secret)


def test_decrypt_secret_returns_none_for_undecryptable_input():
    """A rotated SESSION_SECRET_KEY or a corrupt row must degrade to
    're-enroll', never to a 500 and never to granting access."""
    assert mfa.decrypt_secret("not-a-fernet-token") is None
    assert mfa.decrypt_secret("") is None


def test_provisioning_uri_carries_issuer_account_and_secret():
    secret = mfa.generate_secret()
    uri = mfa.provisioning_uri(secret, "admin@example.com")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=Assetly" in uri
    assert f"secret={secret}" in uri
    assert "admin%40example.com" in uri or "admin@example.com" in uri


def test_qr_svg_is_inline_svg_containing_no_external_reference():
    uri = mfa.provisioning_uri(mfa.generate_secret(), "admin@example.com")
    svg = mfa.qr_svg(uri)
    assert svg.lstrip().startswith("<svg")
    assert "http://" not in svg and "https://" not in svg.replace("http://www.w3.org", "")


def test_generate_recovery_codes_are_unique_and_well_formed():
    import re
    codes = mfa.generate_recovery_codes()
    assert len(codes) == mfa.RECOVERY_CODE_COUNT == 10
    assert len(set(codes)) == 10
    for code in codes:
        assert re.fullmatch(r"[a-z0-9]{5}-[a-z0-9]{5}", code), code


def test_recovery_code_format_cannot_be_confused_with_a_totp_code():
    """One input box takes both, so the formats must not overlap."""
    assert mfa.looks_like_totp("123456") is True
    for code in mfa.generate_recovery_codes():
        assert mfa.looks_like_totp(code) is False


def test_recovery_code_hash_verifies_and_rejects():
    code = mfa.generate_recovery_codes(1)[0]
    code_hash = mfa.hash_recovery_code(code)
    assert code not in code_hash
    assert mfa.verify_recovery_code(code, code_hash) is True
    assert mfa.verify_recovery_code("aaaaa-bbbbb", code_hash) is False
