"""Unit coverage for the config block appended to the Windows agent.

Kept out of test_admin_downloads.py because that module marks every test
asyncio; nothing here needs an event loop.
"""

import json
import re

import pytest

from app.config import WINDOWS_EXE_PATH
from app.routers.admin import (
    WINDOWS_CONFIG_BEGIN,
    WINDOWS_CONFIG_END,
    embed_windows_config,
)


def _embedded_windows_config(exe_bytes: bytes) -> dict:
    match = re.search(rb"ASSETLY-CONFIG-BEGIN:(.*?):ASSETLY-CONFIG-END", exe_bytes, re.DOTALL)
    assert match is not None, "no embedded config block found in the exe"
    return json.loads(match.group(1))


def test_a_marker_inside_the_executable_is_not_mistaken_for_a_config_block():
    """The regression this module exists for.

    The agent searches its own tail for this marker, so the marker is
    necessarily present in the agent's source -- and ps2exe stores that source
    as plain text inside the .exe. An unanchored search finds that copy and
    truncates the binary at it, which is how every Windows download came out as
    a 16 KB fragment that Windows refused to run.
    """
    exe = b"MZ" + b"\x00" * 500 + WINDOWS_CONFIG_BEGIN + b"(.*?)" + WINDOWS_CONFIG_END + b"\x00" * 500

    out = embed_windows_config(exe, {"enrollment_token": "as_enroll_abc"})

    assert out.startswith(exe), "the executable was truncated"
    assert _embedded_windows_config(out[len(exe):]) == {"enrollment_token": "as_enroll_abc"}


def test_embedding_replaces_a_block_at_the_end():
    """Re-embedding, not appending: an already-configured exe put back over the
    build artifact would otherwise accumulate blocks, and the agent reads the
    tail of its own file -- so the stale one could win."""
    once = embed_windows_config(b"MZ-fake-pe-image", {"enrollment_token": "first"})
    twice = embed_windows_config(once, {"enrollment_token": "second"})

    assert twice.startswith(b"MZ-fake-pe-image")
    assert twice.count(WINDOWS_CONFIG_BEGIN) == 1
    assert _embedded_windows_config(twice) == {"enrollment_token": "second"}


def test_replacement_survives_a_decoy_marker_earlier_in_the_file():
    """Both hazards at once: a decoy in the body and a real block at the end.
    Only the trailing block may be replaced; the decoy comes through untouched."""
    exe = b"MZ" + WINDOWS_CONFIG_BEGIN + b"decoy" + WINDOWS_CONFIG_END + b"\x00" * 200

    once = embed_windows_config(exe, {"enrollment_token": "first"})
    twice = embed_windows_config(once, {"enrollment_token": "second"})

    assert twice.startswith(exe), "the decoy region was damaged"
    # Two markers survive by design: the decoy in the body, and exactly one
    # real block at the end -- not two real blocks stacked up.
    assert twice.count(WINDOWS_CONFIG_BEGIN) == 2
    assert _embedded_windows_config(twice[len(exe):]) == {"enrollment_token": "second"}


@pytest.mark.skipif(
    not WINDOWS_EXE_PATH.is_file(), reason="the Windows agent has not been built yet"
)
def test_the_real_agent_executable_is_served_intact():
    """Against the actual committed binary, not a synthetic stand-in.

    The `b"MZ-fake-pe-image"` above is exactly why this bug shipped: it holds no
    marker, so it could never reproduce the failure. A real ps2exe build always
    does.
    """
    exe = WINDOWS_EXE_PATH.read_bytes()
    config = {
        "checkin_api_url": "https://api.assetly.ge/api/v1/inventory/checkin",
        "enrollment_token": "as_enroll_" + "a" * 64,
    }

    out = embed_windows_config(exe, config)

    assert out[: len(exe)] == exe, "the real executable was altered or truncated"
    expected = len(exe) + len(WINDOWS_CONFIG_BEGIN) + len(json.dumps(config).encode()) + len(
        WINDOWS_CONFIG_END
    )
    assert len(out) == expected
    assert _embedded_windows_config(out[len(exe):]) == config
