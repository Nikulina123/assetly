"""Language selection, and the guarantee that both languages actually render.

The point of the render tests is not to check any particular wording -- it is
to catch the failure mode this feature invites: a template that references a
key nobody added, which `translate` deliberately renders as the raw key
rather than as an empty string.
"""
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module

from app.i18n import DEFAULT_LANGUAGE, LANGUAGE_COOKIE, STRINGS, resolve_language, translate
from app.main import app

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    """Same guard the portal route tests use: the app-level pool is bound to
    the event loop that created it, so a parametrized async test reusing it
    across loops fails on a closed connection rather than on anything real."""
    yield
    await db_module.close_pool()


class _FakeRequest:
    def __init__(self, cookies=None, headers=None):
        self.cookies = cookies or {}
        self.headers = headers or {}


def test_cookie_beats_accept_language():
    req = _FakeRequest({LANGUAGE_COOKIE: "en"}, {"accept-language": "ka-GE,ka;q=0.9"})
    assert resolve_language(req) == "en"


def test_accept_language_used_when_no_cookie():
    assert resolve_language(_FakeRequest(headers={"accept-language": "ka-GE,ka;q=0.9"})) == "ka"


def test_unknown_values_fall_back_rather_than_raising():
    assert resolve_language(_FakeRequest({LANGUAGE_COOKIE: "../etc/passwd"})) == DEFAULT_LANGUAGE
    assert resolve_language(_FakeRequest(headers={"accept-language": "fr-FR,fr"})) == DEFAULT_LANGUAGE
    assert resolve_language(_FakeRequest()) == DEFAULT_LANGUAGE


def test_every_key_has_both_languages():
    missing = [k for k, v in STRINGS.items() if not v.get("en") or not v.get("ka")]
    assert not missing, f"keys missing a translation: {missing}"


def test_missing_key_renders_visibly_not_silently():
    assert translate("ka", "no.such.key") == "no.such.key"


def test_a_stray_placeholder_does_not_take_the_page_down():
    # translate() swallows a bad .format rather than 500-ing the request.
    assert translate("en", "settings.revoke_named") == STRINGS["settings.revoke_named"]["en"]


async def test_switching_language_sets_the_cookie_and_returns_to_the_page():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/admin/language", data={"lang": "ka", "next": "/admin/login"}
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/login"
    assert resp.cookies[LANGUAGE_COOKIE] == "ka"


async def test_switcher_refuses_an_offsite_next():
    """Without this check the switcher is an open redirect on the real domain."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for hostile in ("https://evil.example.com/x", "//evil.example.com/x"):
            resp = await client.post(
                "/admin/language", data={"lang": "ka", "next": hostile}
            )
            assert resp.headers["location"] == "/admin/companies", hostile


async def test_an_unknown_language_is_ignored():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/admin/language", data={"lang": "de", "next": "/admin/login"})
    assert LANGUAGE_COOKIE not in resp.cookies


@pytest.mark.parametrize("lang,probe", [("en", "Password"), ("ka", "პაროლი")])
async def test_login_page_renders_in_both_languages(lang, probe):
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test", cookies={LANGUAGE_COOKIE: lang}
    ) as client:
        resp = await client.get("/admin/login")
    assert resp.status_code == 200
    assert probe in resp.text
    assert f'lang="{lang}"' in resp.text


@pytest.mark.parametrize("lang", ["en", "ka"])
async def test_settings_page_renders_with_no_unresolved_keys(
    lang, login_as, enrolled_admin, company
):
    """A template referencing a key that was never added renders as the bare
    dotted key. Catch that here rather than on the demo site."""
    from tests.test_admin_companies import _logged_in_client

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        client.cookies.set(LANGUAGE_COOKIE, lang)
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    import re
    leaked = re.findall(r">\s*((?:settings|common|nav|device|audit|computers|dashboard|companies|login|mfa|recovery|saved)\.[a-z_.]+)\s*<", resp.text)
    assert not leaked, f"unresolved translation keys rendered: {set(leaked)}"
