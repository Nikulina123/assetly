"""The Windows agent's check-in payload, checked against the API's own model.

AssetlyAgent_Windows.ps1 is a from-scratch PowerShell reimplementation of
inventory_agent.py rather than a caller of it, so nothing tied the fields it
sends to the fields the endpoint requires. It shipped without checkin_id, which
the endpoint rejects with 422 -- and because the agent reports every failure as
"offline" and queues it, submissions were silently lost instead of erroring.

There is no PowerShell in CI, so the payload literal is read out of the script
and validated against CheckinRequest directly. That is narrow, but it covers the
one thing that went wrong: the two halves disagreeing about required fields.
"""

import re

import pytest
from pydantic import ValidationError

from app.config import REPO_ROOT
from app.models import CheckinRequest

AGENT = REPO_ROOT / "AssetlyAgent_Windows.ps1"

# Fields needing a type-correct value; everything else is a plain string.
TYPED_SAMPLES = {
    "timestamp": "2026-08-10T12:00:00",
    "checkin_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
}


def _payload_keys() -> set[str]:
    source = AGENT.read_text(encoding="utf-8-sig")
    block = re.search(r"^\$payload = @\{\n(.*?)^\}", source, re.S | re.M)
    assert block is not None, "could not find the $payload literal in the agent script"
    keys = set(re.findall(r"^\s{4}(\w+)\s*=", block.group(1), re.M))
    assert keys, "parsed the $payload literal but found no fields in it"
    return keys


def test_windows_payload_is_accepted_by_the_checkin_endpoint_model():
    """Fails if the agent stops sending a field the API requires."""
    payload = {key: TYPED_SAMPLES.get(key, "x") for key in _payload_keys()}
    try:
        CheckinRequest(**payload)
    except ValidationError as exc:
        missing = ", ".join(".".join(map(str, e["loc"])) for e in exc.errors())
        pytest.fail(f"the Windows agent's payload would be rejected with 422: {missing}")


def test_windows_payload_carries_an_idempotency_key():
    """checkin_id is what makes a queued retry safe. Without it a flushed
    submission that already landed would be recorded a second time instead of
    coming back as 409."""
    assert "checkin_id" in _payload_keys()
