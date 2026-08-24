import base64
import hashlib
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


@pytest.mark.asyncio
async def test_signed_artifact_is_reachable_through_the_running_app(
    private_key_pem, monkeypatch, tmp_path, db_pool, enrolled_device
):
    """The whole point of the C-1 remediation: an agent that fetches the
    manifest, verifies it, and asks for the artifact at the `path` the
    manifest names must actually get bytes back -- not a 404 -- and those
    bytes must hash to the sha256 the manifest declares.

    This signs a real release into a tmpdir (never into the tracked repo
    tree) with sign_release.py, points app.update_manifest at that tmpdir,
    and repoints the app's own /static mount at the same tmpdir so the
    artifact is fetched through the actual running app rather than off disk
    directly -- proving the served path and the written path agree.
    """
    key_path, public_key = private_key_pem
    updates_dir = tmp_path / "updates"

    # A small fake "posix_py" source artifact so signing has something to
    # hash quickly, without depending on the real inventory_agent.py content.
    fake_source = tmp_path / "inventory_agent.py"
    fake_source.write_text("# fake agent for the round-trip test\n")

    import scripts.sign_release as sign_release

    monkeypatch.setattr(sign_release, "UPDATES_DIR", updates_dir)
    monkeypatch.setattr(
        sign_release,
        "ARTIFACTS",
        {"posix_py": fake_source},
    )

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "backend" / "scripts" / "sign_release.py"),
            "--version", "5.0.0",
            "--key", str(key_path),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "UPDATES_DIR": str(updates_dir)},
    )
    assert result.returncode == 0, result.stderr

    import app.update_manifest as update_manifest
    import app.routers.agent_update as agent_update
    from app.main import app

    monkeypatch.setattr(update_manifest, "UPDATES_DIR", str(updates_dir))
    monkeypatch.setattr(agent_update, "load_manifest", update_manifest.load_manifest)

    # Repoint the app's real /static mount at the tmpdir, so "through the
    # app" means through the exact same StaticFiles route production uses,
    # not a bespoke test-only server.
    static_route = next(r for r in app.router.routes if getattr(r, "name", None) == "static")
    monkeypatch.setattr(static_route.app, "all_directories", [str(updates_dir.parent)])

    import httpx

    credential, _serial = enrolled_device
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        manifest_resp = await client.get(
            "/api/v1/agent/manifest",
            headers={"Authorization": f"Bearer {credential}"},
        )
        assert manifest_resp.status_code == 200
        manifest = json.loads(manifest_resp.json()["manifest"])
        artifact = manifest["artifacts"]["posix_py"]

        artifact_resp = await client.get(artifact["path"])
        assert artifact_resp.status_code == 200
        assert hashlib.sha256(artifact_resp.content).hexdigest() == artifact["sha256"]

    # This test exercises the app's own DB pool (via get_current_company_id),
    # which caches a pool bound to this test's event loop. Left open, the
    # next module's pool-closing teardown blows up trying to close it on an
    # already-closed loop -- see the _reset_app_pool fixture other test
    # modules use for the same reason.
    import app.db as db_module
    await db_module.close_pool()
