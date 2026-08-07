import re

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.main import app

pytestmark = pytest.mark.asyncio


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
    assert "attachment" in resp.headers.get("content-disposition", "")
    body = resp.text
    assert "APPS_SCRIPT_URL" not in body
    assert 'CHECKIN_API_URL="https://api.example.com/api/v1/inventory/checkin"' in body

    match = re.search(r'ENROLLMENT_TOKEN="(as_enroll_[a-f0-9]+)"', body)
    assert match is not None, "no ENROLLMENT_TOKEN found in downloaded script"
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


async def test_download_windows_zips_placeholder_exe_and_config(admin, company, db_pool, tmp_path, monkeypatch):
    import io
    import json
    import zipfile

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
    assert "attachment" in resp.headers.get("content-disposition", "")

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert "AssetlyAgent_Windows.exe" in names
    assert "config.json" in names
    assert zf.read("AssetlyAgent_Windows.exe") == b"PLACEHOLDER-EXE-BYTES-NOT-A-REAL-BINARY"

    config = json.loads(zf.read("config.json"))
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

    mac_token = re.search(r'ENROLLMENT_TOKEN="([^"]+)"', mac.text).group(1)
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
