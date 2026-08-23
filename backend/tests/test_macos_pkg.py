"""Format-level tests for the pure-Python .pkg builder.

None of this can be verified by running macOS Installer in CI, so these assert
the specific structural facts Installer depends on: a parseable xar container,
a TOC whose declared offsets and lengths actually address the heap, a Scripts
cpio it can extract, and a Distribution that names the component it ships.
"""

import hashlib
import struct
import zlib
from pathlib import Path
from xml.etree import ElementTree

import pytest

from app.macos_pkg import build_flat_package

from .pkg_reader import read_flat_package, read_xar

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

SCRIPTS = {
    "postinstall": b"#!/bin/bash\nexit 0\n",
    "inventory_agent.py": b"print('hello')\n",
}


def _build(**overrides) -> bytes:
    kwargs = {
        "identifier": "com.assetly.inventory-agent",
        "version": "2.0",
        "title": "Assetly Inventory Agent",
        "scripts": SCRIPTS,
        "component_name": "AssetlyAgent.pkg",
    }
    kwargs.update(overrides)
    return build_flat_package(**kwargs)


def test_scripts_survive_a_round_trip():
    assert read_flat_package(_build()) == SCRIPTS


def test_header_declares_the_toc_that_follows_it():
    pkg = _build()
    magic, header_size, version, compressed_len, uncompressed_len, cksum_alg = struct.unpack(
        ">IHHQQI", pkg[:28]
    )
    assert (magic, header_size, version, cksum_alg) == (0x78617221, 28, 1, 1)

    toc = pkg[header_size : header_size + compressed_len]
    assert len(zlib.decompress(toc)) == uncompressed_len
    # The heap opens with the TOC's own checksum, at the offset/size the TOC's
    # <checksum> element declares. Installer rejects the package if this is
    # wrong, and nothing else in the archive would notice.
    assert pkg[header_size + compressed_len :][:20] == hashlib.sha1(toc).digest()


def test_every_file_entry_addresses_real_heap_bytes():
    """Offsets are computed by hand while laying out the heap, so a
    one-file-too-far bug is the most likely way this module breaks. Checking the
    recorded SHA-1 against the bytes the offsets actually point at catches it."""
    pkg = _build()
    _magic, header_size, _v, compressed_len, _u, _c = struct.unpack(">IHHQQI", pkg[:28])
    toc = ElementTree.fromstring(zlib.decompress(pkg[header_size : header_size + compressed_len]))
    heap = pkg[header_size + compressed_len :]

    entries = [e for e in toc.iter("file") if e.find("data") is not None]
    assert {e.find("name").text for e in entries} == {"Scripts", "PackageInfo", "Distribution"}
    for entry in entries:
        data = entry.find("data")
        offset = int(data.find("offset").text)
        length = int(data.find("length").text)
        stored = heap[offset : offset + length]
        assert len(stored) == length, f"{entry.find('name').text} runs past the end of the heap"
        assert hashlib.sha1(stored).hexdigest() == data.find("archived-checksum").text


def test_distribution_points_at_the_component_and_carries_the_title():
    files = read_xar(_build(component_name="AssetlyAgent.pkg"))
    distribution = files["Distribution"].decode()
    assert "<title>Assetly Inventory Agent</title>" in distribution
    assert "#AssetlyAgent.pkg" in distribution
    assert 'identifier="com.assetly.inventory-agent"' in files["PackageInfo"].decode()


def test_title_and_identifier_are_xml_escaped():
    """Both reach the archive from configuration, and an unescaped ampersand
    produces a package macOS refuses to open at all."""
    files = read_xar(_build(title="Assetly & Co <Agent>", identifier='com.assetly."x"'))
    assert "<title>Assetly &amp; Co &lt;Agent&gt;</title>" in files["Distribution"].decode()
    # Parsing is the real assertion: malformed XML raises here.
    ElementTree.fromstring(files["Distribution"])
    ElementTree.fromstring(files["PackageInfo"])


def test_output_is_reproducible_apart_from_the_creation_timestamp():
    """Identical inputs must give identical bytes so that a re-download is
    diffable against the previous one -- the cpio would otherwise carry the
    build machine's mtimes and inode numbers."""
    first, second = _build(), _build()
    assert read_xar(first)["Scripts"] == read_xar(second)["Scripts"]


def test_a_package_without_a_postinstall_is_rejected():
    with pytest.raises(ValueError, match="postinstall"):
        _build(scripts={"inventory_agent.py": b""})


def test_seed_config_is_not_world_readable():
    """C-2: chmod 644 on this file exposed a 90-day, unlimited-use,
    company-wide enrollment credential to every local user, every unprivileged
    process, and any MDM or backup agent that reads that path."""
    script = (REPO_ROOT / "AssetlyAgent_macOS_postinstall.sh").read_text()
    chmod_644_lines = [line.strip() for line in script.splitlines() if "chmod 644" in line]
    # The LaunchAgent plist is deliberately 644 -- launchd requires it and it
    # carries no secret. Every other chmod 644 would be a credential file.
    assert chmod_644_lines == ['chmod 644 "$PLIST_FILE"']
    assert "chmod 600" in script


def test_postinstall_removes_the_enrollment_token_after_enrolling():
    script = (REPO_ROOT / "AssetlyAgent_macOS_postinstall.sh").read_text()
    assert "/api/v1/enroll" in script
    assert "enrollment_token" in script
    # The token must not survive a successful enrollment.
    assert "rm -f" in script or "shred" in script
