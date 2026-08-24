import httpx
import pytest
import pytest_asyncio

import app.db as db_module
from app.main import app


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    # app.db caches a module-level asyncpg pool bound to whichever event loop
    # created it. pytest-asyncio gives each test its own event loop, so a pool
    # left over from a previous test breaks (or hangs) on reuse. Close it after
    # every test so the next one lazily creates a fresh pool on its own loop.
    yield
    await db_module.close_pool()


@pytest.mark.asyncio
async def test_login_is_rate_limited_per_ip(db_pool, admin):
    """Eleven wrong passwords from one address: the eleventh must be refused
    outright rather than merely answered with 'invalid password'."""
    _admin_id, email, _password = admin
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        statuses = []
        for _ in range(11):
            resp = await client.post(
                "/admin/login",
                data={"email": email, "password": "wrong"},
                headers={"x-forwarded-for": "203.0.113.9"},
            )
            statuses.append(resp.status_code)
    assert statuses[-1] == 429
    assert statuses[0] == 200  # the login form, re-rendered with an error


@pytest.mark.asyncio
async def test_enroll_is_rate_limited_per_ip(db_pool, monkeypatch):
    """A flood of different (bogus) tokens from one address must still be
    capped by the secondary per-IP bucket, even though each bogus token gets
    its own per-token bucket. Limit patched down so the test doesn't need
    hundreds of requests to prove it."""
    import app.routers.enroll as enroll_module

    monkeypatch.setattr(enroll_module, "RATE_LIMIT_ENROLL_IP", (5, 3600))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        last = None
        for i in range(6):
            last = await client.post(
                "/api/v1/enroll",
                json={"serial_number": "S1"},
                headers={
                    "Authorization": f"Bearer as_enroll_bogus_{i}",
                    "x-forwarded-for": "203.0.113.10",
                },
            )
    assert last.status_code == 429


@pytest.mark.asyncio
async def test_enroll_single_token_can_enroll_well_past_the_old_ip_limit(
    db_pool, company, monkeypatch
):
    """The scenario this fix exists for: a 100-seat MDM/GPO rollout pushing
    the installer from one egress IP, all presenting the SAME enrollment
    token. Under the old IP-keyed limit this would 429 after 30 enrollments
    and fall back to writing the token to disk (the C-2 regression). Keyed on
    the token instead, a single token must be able to enroll well past the
    old 30-per-hour IP ceiling from one IP."""
    from app.enrollment import create_enrollment_token

    company_id, _api_key = company
    token = await create_enrollment_token(
        db_pool, company_id, label="site rollout", max_devices=100
    )

    import app.routers.enroll as enroll_module

    # A generous per-IP bucket so this test proves the TOKEN bucket is what's
    # keying enrollment, not incidentally relying on a high IP limit too.
    monkeypatch.setattr(enroll_module, "RATE_LIMIT_ENROLL_IP", (1000, 3600))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        statuses = []
        for i in range(40):
            resp = await client.post(
                "/api/v1/enroll",
                json={"serial_number": f"SEAT-{i}"},
                headers={
                    "Authorization": f"Bearer {token}",
                    "x-forwarded-for": "203.0.113.10",
                },
            )
            statuses.append(resp.status_code)
    # 40 enrollments from one IP with one token, well past the old 30/hour
    # IP-keyed limit -- every single one must succeed.
    assert all(status == 200 for status in statuses), statuses


@pytest.mark.asyncio
async def test_checkin_is_rate_limited_per_credential(db_pool, enrolled_device):
    credential, serial = enrolled_device
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        last = None
        for _ in range(61):
            last = await client.get(
                "/api/v1/inventory/config",
                headers={"Authorization": f"Bearer {credential}"},
            )
    assert last.status_code == 429
    assert "Retry-After" in last.headers
