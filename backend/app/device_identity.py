"""Rejecting firmware placeholder serial numbers.

A device's identity is its serial number: devices are keyed
UNIQUE (company_id, serial_number). Agents read that from the machine's
firmware, which is reliable on branded hardware and not reliable anywhere
else -- integrators of custom-built machines routinely leave the SMBIOS
fields at their factory defaults, so every whitebox PC in an office reports
the same literal "System Serial Number".

Without this guard those machines collapse into a single device row sharing
a single credential, each check-in overwriting the last, and an inventory
product silently reports ten machines as one.

The agents resolve a real identifier themselves (BIOS serial, else SMBIOS
UUID, else the OS machine id). This module is the server-side backstop for
the case the agents cannot cover: an older agent, already deployed, that
still sends the placeholder. Rejecting at enrollment keeps the bad row out
of the table rather than needing it cleaned up later.

Kept in sync with $PlaceholderIdentifiers in AssetlyAgent_Windows.ps1 and
PLACEHOLDER_SERIALS in inventory_agent.py.
"""
import re

# Compared case-insensitively after trimming. These are values firmware ships
# when the field was never programmed, not values anyone chose.
PLACEHOLDER_SERIALS = frozenset({
    "system serial number", "chassis serial number", "serial number",
    "to be filled by o.e.m.", "to be filled by oem", "default string",
    "not specified", "not applicable", "not available", "none", "null",
    "n/a", "na", "unknown", "invalid", "oem", "o.e.m.", "default",
    "system uuid", "product uuid", "0", "1234567890", "123456789",
})

# The two SMBIOS UUIDs that mean "unset" rather than a value, and stub strings
# made only of zeros or dashes.
_ALL_ZEROS = re.compile(r"^[0\s\-]+$")
_ALL_EFF = re.compile(r"^[f\s\-]+$")


def is_placeholder_serial(serial: str | None) -> bool:
    """True when this serial identifies no particular machine."""
    if serial is None:
        return True
    trimmed = serial.strip()
    # Below three characters there is nothing that could distinguish machines
    # from each other, whatever the string happens to be.
    if len(trimmed) < 3:
        return True
    lowered = trimmed.casefold()
    if lowered in PLACEHOLDER_SERIALS:
        return True
    return bool(_ALL_ZEROS.match(lowered) or _ALL_EFF.match(lowered))
