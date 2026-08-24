import base64
import json

import pytest
import pytest_asyncio

import app.db as db_module
from app.update_manifest import verify_signature


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    yield
    await db_module.close_pool()


@pytest.fixture(scope="module")
def keypair():
    """A throwaway RSA keypair. cryptography is a dev-only dependency and is
    used here to SIGN; the code under test verifies with stdlib only, which is
    the whole point -- the agents cannot take a pip dependency."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_der = private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def sign(data: bytes) -> str:
        sig = private.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return base64.b64encode(sig).decode()

    return sign, base64.b64encode(public_der).decode()


def test_accepts_a_genuine_signature(keypair):
    sign, public_key = keypair
    manifest = json.dumps({"version": "1.0.0"}).encode()
    assert verify_signature(manifest, sign(manifest), public_key) is True


def test_rejects_a_tampered_manifest(keypair):
    sign, public_key = keypair
    manifest = json.dumps({"version": "1.0.0"}).encode()
    signature = sign(manifest)
    tampered = json.dumps({"version": "6.6.6"}).encode()
    assert verify_signature(tampered, signature, public_key) is False


def test_rejects_a_garbage_signature(keypair):
    _sign, public_key = keypair
    manifest = json.dumps({"version": "1.0.0"}).encode()
    assert verify_signature(manifest, base64.b64encode(b"nope").decode(), public_key) is False


def test_rejects_a_signature_from_the_wrong_key(keypair):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    _sign, public_key = keypair
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    manifest = json.dumps({"version": "1.0.0"}).encode()
    forged = base64.b64encode(
        attacker.sign(manifest, padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    assert verify_signature(manifest, forged, public_key) is False


@pytest.mark.asyncio
async def test_manifest_endpoint_requires_a_credential(db_pool):
    import httpx
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/agent/manifest")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_manifest_endpoint_returns_raw_bytes(db_pool, enrolled_device, tmp_path, monkeypatch):
    import httpx
    import app.update_manifest as update_manifest
    from app.main import app

    credential, _serial = enrolled_device
    manifest_text = '{\n  "version": "1.2.3"\n}\n'
    monkeypatch.setattr(
        update_manifest, "load_manifest", lambda: (manifest_text.encode(), "c2ln")
    )
    import app.routers.agent_update as agent_update
    monkeypatch.setattr(agent_update, "load_manifest", lambda: (manifest_text.encode(), "c2ln"))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/agent/manifest",
            headers={"Authorization": f"Bearer {credential}"},
        )
    assert resp.status_code == 200
    # Byte-for-byte, including whitespace: the signature covers these exact bytes.
    assert resp.json()["manifest"] == manifest_text
    assert resp.json()["signature"] == "c2ln"


@pytest.mark.asyncio
async def test_manifest_endpoint_404s_when_no_release_is_signed(db_pool, enrolled_device, monkeypatch):
    import httpx
    import app.routers.agent_update as agent_update
    from app.main import app

    credential, _serial = enrolled_device

    def _missing():
        raise FileNotFoundError

    monkeypatch.setattr(agent_update, "load_manifest", _missing)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/agent/manifest",
            headers={"Authorization": f"Bearer {credential}"},
        )
    assert resp.status_code == 404
