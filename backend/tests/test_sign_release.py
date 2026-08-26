import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _run_sign_release(tmp_path, monkeypatch, env_extra=None):
    """Runs sign_release.py against a fake repo layout under tmp_path so it
    never touches the real backend/static or backend/app/static/updates."""
    key_path = tmp_path / "release_key.pem"
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    fake_exe = tmp_path / "AssetlyAgent_Windows.exe"
    fake_exe.write_bytes(b"fake-pe-bytes")
    fake_posix = tmp_path / "inventory_agent.py"
    fake_posix.write_text("# fake agent\n")

    updates_dir = tmp_path / "updates"

    env = {
        "UPDATES_DIR": str(updates_dir),
    }
    if env_extra:
        env.update(env_extra)
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    import importlib

    import scripts.sign_release as sign_release

    importlib.reload(sign_release)
    monkeypatch.setattr(
        sign_release,
        "ARTIFACTS",
        {"windows_exe": fake_exe, "posix_py": fake_posix},
    )
    sign_release.UPDATES_DIR = updates_dir

    sys_argv = sys.argv
    sys.argv = ["sign_release.py", "--version", "9.9.9", "--key", str(key_path)]
    try:
        sign_release.main()
    finally:
        sys.argv = sys_argv

    return updates_dir


def test_manifest_records_unsigned_sha256_for_windows_exe(tmp_path, monkeypatch):
    updates_dir = _run_sign_release(tmp_path, monkeypatch)
    manifest = json.loads((updates_dir / "manifest.json").read_text())
    entry = manifest["artifacts"]["windows_exe"]
    assert "unsigned_sha256" in entry
    assert entry["unsigned_sha256"] == hashlib.sha256(b"fake-pe-bytes").hexdigest()


def test_sha256_equals_unsigned_sha256_when_signing_is_not_configured(tmp_path, monkeypatch):
    updates_dir = _run_sign_release(tmp_path, monkeypatch)
    manifest = json.loads((updates_dir / "manifest.json").read_text())
    entry = manifest["artifacts"]["windows_exe"]
    assert entry["sha256"] == entry["unsigned_sha256"]
