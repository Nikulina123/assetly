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


class TestWindowsBaseBytes:
    """_windows_base_bytes must stay behaviourally identical to
    Split-EmbeddedConfig in AssetlyAgent_Windows.ps1. If the two ever
    diverge on what counts as "the base image", a real installed .exe and
    this signer disagree about the hash of the same release, and every
    machine in the Windows fleet sits in a permanent "update available"
    loop, downloading and re-applying forever."""

    @staticmethod
    def _base_bytes():
        from scripts.sign_release import _windows_base_bytes

        return _windows_base_bytes

    def test_no_config_block_returns_bytes_unchanged(self):
        base = self._base_bytes()
        data = b"plain exe bytes with no marker anywhere"
        assert base(data) == data

    def test_proper_trailing_block_is_stripped(self):
        base = self._base_bytes()
        exe = b"\x4d\x5a" + b"fake pe image bytes"
        block = b"ASSETLY-CONFIG-BEGIN:" + b'{"url": "https://example.com"}' + b":ASSETLY-CONFIG-END"
        data = exe + block
        assert base(data) == exe

    def test_begin_marker_early_with_no_trailing_end_marker_is_unchanged(self):
        """The regression this fix exists to prevent: an early, incidental
        occurrence of the begin-marker text must never be treated as a real
        config block unless the file also ends with the end-marker."""
        base = self._base_bytes()
        data = b"ASSETLY-CONFIG-BEGIN:" + b"decoy text from an embedded script copy" + b"trailing bytes, no end marker"
        assert base(data) == data

    def test_begin_marker_beyond_8192_bytes_from_end_is_unchanged(self):
        """Must match the agent's bounded search window: a begin-marker that
        sits further than 8192 bytes from the end -- even with a genuine
        trailing end-marker -- is outside where Split-EmbeddedConfig looks,
        so it must not be treated as a config block either."""
        base = self._base_bytes()
        begin = b"ASSETLY-CONFIG-BEGIN:"
        end = b":ASSETLY-CONFIG-END"
        padding = b"x" * 9000
        data = begin + padding + end
        assert base(data) == data
