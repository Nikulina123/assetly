"""Unit coverage for the config block appended to the Windows agent.

Kept out of test_admin_downloads.py because that module marks every test
asyncio; nothing here needs an event loop.
"""

import json
import re

from app.routers.admin import embed_windows_config


def _embedded_windows_config(exe_bytes: bytes) -> dict:
    match = re.search(rb"ASSETLY-CONFIG-BEGIN:(.*?):ASSETLY-CONFIG-END", exe_bytes, re.DOTALL)
    assert match is not None, "no embedded config block found in the exe"
    return json.loads(match.group(1))


def test_embedding_windows_config_replaces_an_existing_block():
    """Re-embedding, not appending: an already-configured exe put back over the
    build artifact would otherwise accumulate blocks, and the agent reads the
    tail of its own file -- so the stale one could win."""
    once = embed_windows_config(b"MZ-fake-pe-image", {"enrollment_token": "first"})
    twice = embed_windows_config(once, {"enrollment_token": "second"})

    assert twice.startswith(b"MZ-fake-pe-image")
    assert twice.count(b"ASSETLY-CONFIG-BEGIN:") == 1
    assert _embedded_windows_config(twice) == {"enrollment_token": "second"}
