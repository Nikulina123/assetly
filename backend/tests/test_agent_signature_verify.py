"""The agent's verifier is a hand-rolled stdlib copy of the backend's. If the
two ever disagree, agents silently stop updating -- so test them against the
same signatures."""
import base64
import importlib.util
import json
from pathlib import Path

import pytest

from app.update_manifest import verify_signature as backend_verify

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def agent_module():
    spec = importlib.util.spec_from_file_location(
        "inventory_agent_under_test", REPO_ROOT / "inventory_agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def signed():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    manifest = json.dumps({"version": "1.0.0"}, sort_keys=True).encode()
    signature = base64.b64encode(
        key.sign(manifest, padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return manifest, signature, base64.b64encode(public_der).decode()


def test_agent_accepts_what_the_backend_accepts(agent_module, signed):
    manifest, signature, public_key = signed
    assert agent_module.verify_signature(manifest, signature, public_key) is True
    assert backend_verify(manifest, signature, public_key) is True


def test_agent_rejects_a_tampered_manifest(agent_module, signed):
    manifest, signature, public_key = signed
    assert agent_module.verify_signature(manifest + b" ", signature, public_key) is False


def test_agent_rejects_a_signature_from_another_key(agent_module, signed):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    manifest, _signature, public_key = signed
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = base64.b64encode(
        attacker.sign(manifest, padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    assert agent_module.verify_signature(manifest, forged, public_key) is False
