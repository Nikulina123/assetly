import re

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.main import app

from .pkg_reader import read_flat_package

pytestmark = pytest.mark.asyncio


def _postinstall_of(pkg_bytes: bytes) -> str:
    """The macOS download is a binary .pkg, so assertions about what the
    installer will actually do have to go through the archive rather than the
    response body. Unpacking it here also means every macOS download test
    doubles as a check that the package we hand out is well-formed."""
    return read_flat_package(pkg_bytes)["postinstall"].decode()


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    yield
    await db_module.close_pool()


async def _client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


async def _logged_in_client(login_as, admin_tuple):
    client = await _client()
    await login_as(client, admin_tuple)
    return client


async def _get_csrf_token(client, company_id):
    resp = await client.get(f"/admin/companies/{company_id}")
    return resp.text.split('name="csrf_token" value="')[1].split('"')[0]


async def test_download_macos_requires_login(company):
    company_id, _ = company
    async with await _client() as client:
        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": "irrelevant"},
            follow_redirects=False,
        )
    assert resp.status_code == 303


async def test_download_macos_embeds_a_fresh_enrollment_token(login_as, enrolled_admin, company, db_pool):
    """Downloads used to rotate the shared company key (invalidating every
    previously-downloaded installer); they now mint an additive enrollment
    token instead. Assert the new contract: a fresh, working token is
    embedded, and the company's legacy key -- untouched by the download --
    still resolves."""
    from app.auth import resolve_company_id
    from app.enrollment import enroll_device

    company_id, old_api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert 'filename="AssetlyAgent_macOS.pkg"' in resp.headers.get("content-disposition", "")

    scripts = read_flat_package(resp.content)
    # The agent travels inside the package: an installed Mac must not have to
    # reach GitHub to get it.
    assert scripts["inventory_agent.py"].startswith(b"#!/usr/bin/env python3")

    body = scripts["postinstall"].decode()
    assert "APPS_SCRIPT_URL" not in body
    assert 'CHECKIN_API_URL="https://api.example.com/api/v1/inventory/checkin"' in body

    match = re.search(r'ENROLLMENT_TOKEN="(as_enroll_[a-f0-9]+)"', body)
    assert match is not None, "no ENROLLMENT_TOKEN found in the package's postinstall"
    token = match.group(1)

    # The embedded token actually works.
    credential = await enroll_device(db_pool, token, "SN-MACOS-DL", "host-macos-dl")
    assert credential.startswith("as_dev_")

    # The download did not touch the company's shared key at all.
    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved == company_id


async def test_download_linux_embeds_a_fresh_enrollment_token(login_as, enrolled_admin, company, db_pool):
    from app.auth import resolve_company_id
    from app.enrollment import enroll_device

    company_id, old_api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    body = resp.text
    assert "APPS_SCRIPT_URL" not in body
    match = re.search(r'ENROLLMENT_TOKEN="(as_enroll_[a-f0-9]+)"', body)
    assert match is not None
    token = match.group(1)

    credential = await enroll_device(db_pool, token, "SN-LINUX-DL", "host-linux-dl")
    assert credential.startswith("as_dev_")

    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved == company_id


async def test_download_blocked_for_revoked_company(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        # Fetch the CSRF token BEFORE revoking, so this test isolates "is the
        # download blocked for a revoked company" from any side effect of
        # revocation on CSRF/detail-page rendering.
        csrf_token = await _get_csrf_token(client, company_id)

        async with db_pool.acquire() as conn:
            await conn.execute("UPDATE companies SET revoked_at = NOW() WHERE id = $1", company_id)

        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 404


async def test_download_without_csrf_token_is_rejected(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.post(f"/admin/companies/{company_id}/download/macos", data={})
    finally:
        await client.aclose()
    assert resp.status_code == 422


async def test_download_windows_without_exe_returns_clear_error(login_as, enrolled_admin, company, monkeypatch):
    from pathlib import Path

    import app.routers.admin as admin_module

    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", Path("/nonexistent/AssetlyAgent_Windows.exe"))

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 503


def _embedded_windows_config(exe_bytes: bytes) -> dict:
    import json

    match = re.search(
        rb"ASSETLY-CONFIG-BEGIN:(.*?):ASSETLY-CONFIG-END", exe_bytes, re.DOTALL
    )
    assert match is not None, "no embedded config block found in the downloaded exe"
    return json.loads(match.group(1))


async def test_download_windows_serves_one_exe_with_config_embedded(login_as, enrolled_admin, company, db_pool, tmp_path, monkeypatch):
    """A single file, not a zip of two: the config rides on the end of the PE
    image so there is nothing for a deployer to separate it from."""
    import app.routers.admin as admin_module
    from app.auth import resolve_company_id
    from app.enrollment import enroll_device

    placeholder = tmp_path / "AssetlyAgent_Windows.exe"
    placeholder.write_bytes(b"PLACEHOLDER-EXE-BYTES-NOT-A-REAL-BINARY")
    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", placeholder)

    company_id, old_api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert 'filename="AssetlyAgent_Windows.exe"' in resp.headers.get("content-disposition", "")

    # The executable itself is byte-for-byte the build artifact -- appending must
    # not disturb the image, or Windows will not load it.
    assert resp.content.startswith(b"PLACEHOLDER-EXE-BYTES-NOT-A-REAL-BINARY")

    config = _embedded_windows_config(resp.content)
    token = config["enrollment_token"]
    assert token.startswith("as_enroll_")
    assert config["checkin_api_url"] == "https://api.example.com/api/v1/inventory/checkin"

    # The embedded token actually works.
    credential = await enroll_device(db_pool, token, "SN-WIN-DL", "host-win-dl")
    assert credential.startswith("as_dev_")

    # The download did not touch the company's shared key at all.
    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved == company_id


async def test_download_windows_does_not_mint_token_when_exe_missing(login_as, enrolled_admin, company, db_pool, monkeypatch):
    """The exe-missing check must happen BEFORE any token is minted -- verify
    no token was created (and the legacy key is unaffected either way, since
    downloads no longer touch it)."""
    from pathlib import Path

    import app.routers.admin as admin_module
    from app.auth import resolve_company_id
    from app.enrollment import list_tokens

    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", Path("/nonexistent/AssetlyAgent_Windows.exe"))

    company_id, old_api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 503

    resolved = await resolve_company_id(db_pool, old_api_key)
    assert resolved == company_id
    assert await list_tokens(db_pool, str(company_id)) == []


async def test_download_windows_msi_serves_a_zip_with_the_msi_and_a_deploy_command(
    login_as, enrolled_admin, company, db_pool, tmp_path, monkeypatch
):
    """The MSI must leave the route byte-for-byte as it was published.

    Config cannot be appended to it the way it is to the .exe: an MSI is a
    structured OLE compound document, and trailing bytes are precisely what
    invalidates an Authenticode signature. Since the MSI exists to be the
    artifact that reaches a managed fleet with its signature intact, this
    asserts the bytes are unmodified and that the token instead travels in a
    separate Deploy.cmd.
    """
    import io as _io
    import zipfile as _zipfile

    import app.routers.admin as admin_module
    from app.enrollment import list_tokens

    placeholder = tmp_path / "AssetlyAgent.msi"
    # Real MSIs start with the OLE compound-document magic; using it here keeps
    # the fixture honest about what is being served.
    msi_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"placeholder-msi" * 64
    placeholder.write_bytes(msi_bytes)
    monkeypatch.setattr(admin_module, "WINDOWS_MSI_PATH", placeholder)

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows-msi",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"

    archive = _zipfile.ZipFile(_io.BytesIO(resp.content))
    assert sorted(archive.namelist()) == ["AssetlyAgent.msi", "Deploy.cmd"]
    # The whole point: unmodified, so a signature over it still verifies.
    assert archive.read("AssetlyAgent.msi") == msi_bytes

    deploy = archive.read("Deploy.cmd").decode()
    tokens = await list_tokens(db_pool, str(company_id))
    assert len(tokens) == 1
    # The freshly minted token has to actually reach the command line, or the
    # download is a file the admin cannot deploy.
    assert "ENROLLMENTTOKEN=" in deploy
    assert "CHECKINAPIURL=" in deploy
    assert "msiexec" in deploy
    # A batch file with bare LF line endings behaves unpredictably under cmd.
    assert "\r\n" in deploy


async def test_download_windows_msi_does_not_mint_token_when_msi_missing(
    login_as, enrolled_admin, company, db_pool, monkeypatch
):
    """Same validate-before-mutate ordering the .exe route has: an unsigned
    instance (no release published yet) must not leave tokens behind."""
    from pathlib import Path

    import app.routers.admin as admin_module
    from app.enrollment import list_tokens

    monkeypatch.setattr(admin_module, "WINDOWS_MSI_PATH", Path("/nonexistent/AssetlyAgent.msi"))

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows-msi",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()

    assert resp.status_code == 503
    assert await list_tokens(db_pool, str(company_id)) == []


async def test_downloading_two_platforms_leaves_both_installers_working(login_as, enrolled_admin, company, db_pool):
    """The bug this whole design exists to fix: downloading macOS then Linux
    used to invalidate the macOS installer's key (both installers embedded
    the single shared company key, and each download rotated it). Tokens are
    additive, so both must now enroll successfully."""
    from app.enrollment import list_device_credentials

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        mac = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
        lin = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()

    mac_token = re.search(r'ENROLLMENT_TOKEN="([^"]+)"', _postinstall_of(mac.content)).group(1)
    lin_token = re.search(r'ENROLLMENT_TOKEN="([^"]+)"', lin.text).group(1)
    assert mac_token != lin_token

    async with await _client() as client:
        for token, serial in ((mac_token, "SN-MAC"), (lin_token, "SN-LIN")):
            resp = await client.post(
                "/api/v1/enroll",
                json={"serial_number": serial, "hostname": serial.lower()},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200, f"{serial} failed to enroll"

    assert len(await list_device_credentials(db_pool, company_id)) == 2


async def test_company_detail_shows_download_buttons(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Download for macOS" in resp.content
    assert b"Download for Linux" in resp.content
    assert b"Download for Windows" in resp.content
    # The MSI card, in the redesigned platform-grid layout: the button label is
    # the shared "Download" string, so the platform is asserted through the
    # markup that actually distinguishes the cards -- the visible name and the
    # aria-label a screen reader announces.
    assert b"Download for Windows MSI" in resp.content
    assert b">Windows MSI<" in resp.content
    assert b"Not yet available" not in resp.content
    # The page must tell the admin that downloading one platform does NOT break
    # installers already downloaded for others. It previously warned the exact
    # opposite, which was true of the old rotate-on-download behaviour and is
    # false now -- so this asserts the corrected promise, not just any copy.
    assert b"enrollment token" in resp.content.lower()
    # Fragment chosen to sit on a single source line -- the full sentence wraps
    # across a line break in the template, so a longer substring would never match.
    assert b"not affect installers you downloaded earlier" in resp.content.lower()
    assert b"invalidat" not in resp.content.lower()


async def test_diagnostics_reports_what_is_on_disk(login_as, enrolled_admin, company):
    """Guards the deploy check itself: it is only useful if it reports the
    real size and hash of the artifacts the download routes read."""
    import hashlib

    from app.config import REPO_ROOT

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get("/admin/diagnostics")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    body = resp.json()

    agent = REPO_ROOT / "inventory_agent.py"
    assert body["agent_source"]["exists"] is True
    assert body["agent_source"]["bytes"] == agent.stat().st_size
    assert body["agent_source"]["sha256"] == hashlib.sha256(agent.read_bytes()).hexdigest()
    assert body["macos_postinstall"]["exists"] is True


async def test_diagnostics_requires_login():
    async with await _client() as client:
        resp = await client.get("/admin/diagnostics", follow_redirects=False)
    assert resp.status_code == 303


async def test_diagnostics_refuses_scoped_admin(login_as, scoped_admin):
    """A full admin scoped to one company has no legitimate need to see
    deployment-wide internals (repo_root, the full artifact listing) that
    have nothing to do with their one tenant. require_global_admin is the
    existing dependency for exactly this class of route (see company
    creation) -- diagnostics should use it too."""
    client = await _logged_in_client(login_as, scoped_admin)
    try:
        resp = await client.get("/admin/diagnostics")
    finally:
        await client.aclose()
    assert resp.status_code == 403


async def test_download_mints_a_capped_token(login_as, enrolled_admin, company, db_pool):
    """Unlimited devices for 90 days makes a leaked installer maximally
    valuable and gives no natural expiry pressure."""
    import datetime
    import uuid

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token, "device_count": "25", "token_days": "14"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT max_devices, expires_at FROM enrollment_tokens "
            "WHERE company_id = $1 ORDER BY created_at DESC LIMIT 1",
            uuid.UUID(company_id),
        )
    assert row["max_devices"] is not None
    assert row["max_devices"] >= 25
    lifetime = row["expires_at"] - datetime.datetime.now(datetime.timezone.utc)
    assert 13 <= lifetime.days <= 14


async def test_download_rejects_a_bad_device_count(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token, "device_count": "0", "token_days": "14"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 400


async def test_download_rejects_an_unlisted_lifetime(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token, "device_count": "5", "token_days": "3650"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 400


def test_portal_serves_the_signed_windows_agent():
    """The portal must hand out the artifact the release manifest signs.

    These were two different files until 2026-08-24, when they diverged and put
    a real endpoint into a permanent update loop: a freshly downloaded agent
    compared itself against the signed manifest, found a mismatch, "updated" to
    the signed build, and the older build's legacy GitHub-raw path pulled it
    back. Pointing WINDOWS_EXE_PATH inside UPDATES_DIR collapses the two
    channels into one source of truth, so a fresh install is by construction
    already up to date. Reverting this reopens that loop.
    """
    from pathlib import Path

    from app.config import UPDATES_DIR, WINDOWS_EXE_PATH

    assert WINDOWS_EXE_PATH.parent == Path(UPDATES_DIR), (
        "the portal must serve the signed artifact, not CI's unsigned build output"
    )
