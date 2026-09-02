import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

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
    # --no-msi: these tests cover the signing and manifest round-trip, not
    # installer packaging, and an MSI can only be built on Windows -- so
    # requiring one here would make a signing test fail for a reason that has
    # nothing to do with signing.
    sys.argv = [
        "sign_release.py", "--version", "9.9.9", "--key", str(key_path), "--no-msi",
    ]
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


def test_a_failed_msi_build_leaves_the_published_directory_untouched(tmp_path, monkeypatch):
    """Signing must be all-or-nothing.

    An earlier version wrote each artifact as it went and handled the MSI
    afterwards, so a missing or invalid installer aborted with the NEW
    executable already on disk and manifest.json still describing the previous
    release. That directory is what the portal serves and what agents verify
    against, so the half-written state was worse than either release on its
    own: a fresh download got an executable no signed manifest covered, and
    self-update rejected the same bytes it had just fetched.
    """
    import sys as _sys
    from pathlib import Path

    import pytest
    from cryptography.hazmat.primitives.asymmetric import rsa

    key_path = tmp_path / "release_key.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    fake_exe = tmp_path / "AssetlyAgent_Windows.exe"
    fake_exe.write_bytes(b"new-pe-bytes")
    fake_posix = tmp_path / "inventory_agent.py"
    fake_posix.write_text("# new agent\n")

    # A published directory from a previous release, which must survive intact.
    updates_dir = tmp_path / "updates"
    updates_dir.mkdir()
    previous = {
        "AssetlyAgent_Windows.exe": b"previous-release-bytes",
        "manifest.json": b'{"version": "1.0.0"}',
        "manifest.sig": b"previous-signature\n",
    }
    for filename, content in previous.items():
        (updates_dir / filename).write_bytes(content)

    monkeypatch.setenv("UPDATES_DIR", str(updates_dir))

    import importlib

    import scripts.sign_release as sign_release

    importlib.reload(sign_release)
    monkeypatch.setattr(
        sign_release, "ARTIFACTS", {"windows_exe": fake_exe, "posix_py": fake_posix}
    )
    sign_release.UPDATES_DIR = updates_dir

    sys_argv = _sys.argv
    # An --msi that is not there: the failure a release owner hits when the CI
    # artifact was never downloaded, or landed in another directory.
    _sys.argv = [
        "sign_release.py", "--version", "9.9.9", "--key", str(key_path),
        "--msi", str(tmp_path / "not-downloaded" / "AssetlyAgent.msi"),
    ]
    try:
        with pytest.raises(RuntimeError, match="No MSI at"):
            sign_release.main()
    finally:
        _sys.argv = sys_argv

    for filename, content in previous.items():
        assert (updates_dir / filename).read_bytes() == content, (
            f"{filename} was modified by a run that did not complete"
        )
    assert not (updates_dir / "AssetlyAgent.msi").exists()
    assert not (updates_dir / "inventory_agent.py").exists()
