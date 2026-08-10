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


async def _logged_in_client(email, password):
    client = await _client()
    await client.post("/admin/login", data={"email": email, "password": password})
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


async def test_download_macos_embeds_a_fresh_enrollment_token(admin, company, db_pool):
    """Downloads used to rotate the shared company key (invalidating every
    previously-downloaded installer); they now mint an additive enrollment
    token instead. Assert the new contract: a fresh, working token is
    embedded, and the company's legacy key -- untouched by the download --
    still resolves."""
    from app.auth import resolve_company_id
    from app.enrollment import enroll_device

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token},
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


async def test_download_linux_embeds_a_fresh_enrollment_token(admin, company, db_pool):
    from app.auth import resolve_company_id
    from app.enrollment import enroll_device

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token},
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


async def test_download_blocked_for_revoked_company(admin, company, db_pool):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        # Fetch the CSRF token BEFORE revoking, so this test isolates "is the
        # download blocked for a revoked company" from any side effect of
        # revocation on CSRF/detail-page rendering.
        csrf_token = await _get_csrf_token(client, company_id)

        async with db_pool.acquire() as conn:
            await conn.execute("UPDATE companies SET revoked_at = NOW() WHERE id = $1", company_id)

        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 404


async def test_download_without_csrf_token_is_rejected(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.post(f"/admin/companies/{company_id}/download/macos", data={})
    finally:
        await client.aclose()
    assert resp.status_code == 422


async def test_download_windows_without_exe_returns_clear_error(admin, company, monkeypatch):
    from pathlib import Path

    import app.routers.admin as admin_module

    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", Path("/nonexistent/AssetlyAgent_Windows.exe"))

    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token},
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


async def test_download_windows_serves_one_exe_with_config_embedded(
    admin, company, db_pool, tmp_path, monkeypatch
):
    """A single file, not a zip of two: the config rides on the end of the PE
    image so there is nothing for a deployer to separate it from."""
    import app.routers.admin as admin_module
    from app.auth import resolve_company_id
    from app.enrollment import enroll_device

    placeholder = tmp_path / "AssetlyAgent_Windows.exe"
    placeholder.write_bytes(b"PLACEHOLDER-EXE-BYTES-NOT-A-REAL-BINARY")
    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", placeholder)

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token},
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


async def test_download_windows_does_not_mint_token_when_exe_missing(admin, company, db_pool, monkeypatch):
    """The exe-missing check must happen BEFORE any token is minted -- verify
    no token was created (and the legacy key is unaffected either way, since
    downloads no longer touch it)."""
    from pathlib import Path

    import app.routers.admin as admin_module
    from app.auth import resolve_company_id
    from app.enrollment import list_tokens

    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", Path("/nonexistent/AssetlyAgent_Windows.exe"))

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 503

    resolved = await resolve_company_id(db_pool, old_api_key)
    assert resolved == company_id
    assert await list_tokens(db_pool, str(company_id)) == []


async def test_downloading_two_platforms_leaves_both_installers_working(admin, company, db_pool):
    """The bug this whole design exists to fix: downloading macOS then Linux
    used to invalidate the macOS installer's key (both installers embedded
    the single shared company key, and each download rotated it). Tokens are
    additive, so both must now enroll successfully."""
    from app.enrollment import list_device_credentials

    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        mac = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token},
        )
        lin = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token},
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


async def test_company_detail_shows_download_buttons(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Download for macOS" in resp.content
    assert b"Download for Linux" in resp.content
    assert b"Download for Windows" in resp.content
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


async def test_diagnostics_reports_what_is_on_disk(admin, company):
    """Guards the deploy check itself: it is only useful if it reports the
    real size and hash of the artifacts the download routes read."""
    import hashlib

    from app.config import REPO_ROOT

    _, email, password = admin
    client = await _logged_in_client(email, password)
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
