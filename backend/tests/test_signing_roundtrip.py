import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.update_manifest import verify_signature

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def private_key_pem(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "key.pem"
    path.write_bytes(pem)
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return path, base64.b64encode(public_der).decode()


def test_signed_release_verifies_with_the_stdlib_verifier(private_key_pem, monkeypatch, tmp_path):
    """Signer and verifier must not drift apart: sign_release.py uses
    cryptography, every agent uses a hand-rolled stdlib implementation, and
    nothing else in the system would notice if they stopped agreeing."""
    key_path, public_key = private_key_pem
    updates_dir = tmp_path / "updates"
    monkeypatch.setenv("UPDATES_DIR", str(updates_dir))

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "backend" / "scripts" / "sign_release.py"),
         "--version", "9.9.9", "--key", str(key_path)],
        capture_output=True, text=True, env={**os.environ, "UPDATES_DIR": str(updates_dir)},
    )
    assert result.returncode == 0, result.stderr

    manifest_bytes = (updates_dir / "manifest.json").read_bytes()
    signature = (updates_dir / "manifest.sig").read_text().strip()

    assert verify_signature(manifest_bytes, signature, public_key) is True
    assert json.loads(manifest_bytes)["version"] == "9.9.9"

    # And a single flipped byte must break it.
    assert verify_signature(manifest_bytes + b" ", signature, public_key) is False
