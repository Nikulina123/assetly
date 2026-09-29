"""Memory and system-disk detail collected by inventory_agent.py (2.3.0+).

Every source here is a command's text output, so each test feeds the parser a
captured sample of that output through a fake _run -- the parsing is where
this breaks, not the subprocess call.
"""
import importlib.util
import json
import plistlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def agent():
    spec = importlib.util.spec_from_file_location(
        "inventory_agent", REPO_ROOT / "inventory_agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["inventory_agent"] = module
    spec.loader.exec_module(module)
    return module


def _fake_run(outputs: dict):
    """A _run stand-in answering by the command's first two words, and
    recording every call so a test can assert what was (not) run."""
    calls = []

    def run(cmd, sudo=False):
        calls.append((tuple(cmd), sudo))
        return outputs.get(tuple(cmd[:2]), "")

    run.calls = calls
    return run


# ── Linux: dmidecode -t 17 ───────────────────────────────────────────────────

DMIDECODE_TWO_OF_FOUR = """\
# dmidecode 3.3
Getting SMBIOS data from sysfs.
SMBIOS 3.2.0 present.

Handle 0x0040, DMI type 17, 84 bytes
Memory Device
\tArray Handle: 0x003F
\tTotal Width: 64 bits
\tSize: 8 GB
\tForm Factor: DIMM
\tLocator: DIMM_A1
\tType: DDR4
\tType Detail: Synchronous
\tSpeed: 3200 MT/s
\tConfigured Memory Speed: 2933 MT/s
\tVolatile Size: 8 GB
\tCache Size: None
\tLogical Size: None

Handle 0x0041, DMI type 17, 84 bytes
Memory Device
\tArray Handle: 0x003F
\tSize: No Module Installed
\tForm Factor: Unknown
\tLocator: DIMM_A2
\tType: Unknown
\tSpeed: Unknown
\tConfigured Memory Speed: Unknown

Handle 0x0042, DMI type 17, 84 bytes
Memory Device
\tArray Handle: 0x003F
\tSize: 8192 MB
\tForm Factor: DIMM
\tLocator: DIMM_B1
\tType: DDR4
\tSpeed: 3200 MT/s
\tConfigured Memory Speed: 3200 MT/s

Handle 0x0043, DMI type 17, 84 bytes
Memory Device
\tArray Handle: 0x003F
\tSize: No Module Installed
\tLocator: DIMM_B2
\tType: Unknown
\tSpeed: Unknown
\tConfigured Memory Speed: Unknown
"""


def test_linux_memory_reports_type_speed_and_slot_occupancy(agent):
    details = agent._parse_dmidecode_memory(DMIDECODE_TWO_OF_FOUR)
    # The bus runs at the slowest module's configured speed, and the
    # "Volatile Size" / "Type Detail" lines must not be read as Size / Type.
    assert details == {"ram_type": "DDR4", "ram_speed": "2933 MHz", "ram_slots": "2/4"}


def test_linux_memory_accepts_older_dmidecode_clock_speed_label(agent):
    older = (
        "Memory Device\n\tSize: 4096 MB\n\tType: DDR3\n"
        "\tSpeed: 1600 MHz\n\tConfigured Clock Speed: 1333 MHz\n"
    )
    assert agent._parse_dmidecode_memory(older) == {
        "ram_type": "DDR3", "ram_speed": "1333 MHz", "ram_slots": "1/1",
    }


def test_linux_memory_falls_back_to_rated_speed_when_configured_is_unknown(agent):
    sample = (
        "Memory Device\n\tSize: 16 GB\n\tType: DDR5\n"
        "\tSpeed: 4800 MT/s\n\tConfigured Memory Speed: Unknown\n"
    )
    assert agent._parse_dmidecode_memory(sample)["ram_speed"] == "4800 MHz"


def test_linux_memory_without_root_reports_nothing(agent):
    """Unprivileged dmidecode prints its banner and no tables. That is "not
    collected", not "0 slots"."""
    assert agent._parse_dmidecode_memory("# dmidecode 3.3\n") == {}
    assert agent._parse_dmidecode_memory("") == {}


# ── Linux: lsblk ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "name, lsblk_out, expected",
    [
        ("nvme0n1", "nvme 0", "NVMe SSD"),
        ("sda", "sata 0", "SATA SSD"),
        ("sda", "sata 1", "SATA HDD"),
        ("sdb", "usb 0", "USB SSD"),
        # lsblk older than 2.33 leaves TRAN empty for NVMe.
        ("nvme0n1", " 0", "NVMe SSD"),
        ("mmcblk0", " 0", "eMMC"),
        ("vda", " 1", "Virtual disk"),
        ("sda", "", None),
    ],
)
def test_linux_storage_type(agent, name, lsblk_out, expected):
    assert agent._linux_storage_type(name, lsblk_out) == expected


def test_linux_collection_skips_loop_devices_and_reports_disk_details(agent, monkeypatch):
    monkeypatch.setattr(agent, "_sys", "Linux")
    monkeypatch.setattr(agent, "get_ip", lambda: "10.0.0.1")
    monkeypatch.setattr(agent.Path, "read_text", lambda self: "x\n")
    fake = _fake_run({
        ("cat", "/proc/cpuinfo"): "model name : Fake CPU\n",
        ("cat", "/proc/meminfo"): "MemTotal:       16000000 kB\n",
        ("lsblk", "-d"): "nvme0n1 512G Samsung SSD 980",
        ("lsblk", "-dn"): "nvme 0",
        ("dmidecode", "-t"): DMIDECODE_TWO_OF_FOUR,
    })
    monkeypatch.setattr(agent, "_run", fake)

    hw = agent.collect_hardware()

    lsblk = [cmd for cmd, _ in fake.calls if cmd[0] == "lsblk"]
    assert "-e" in lsblk[0] and "7,11" in lsblk[0]  # no loop / optical devices
    assert lsblk[1][-1] == "/dev/nvme0n1"          # details of that same disk
    assert hw["storage"] == "nvme0n1 512G Samsung SSD 980"
    assert hw["storage_type"] == "NVMe SSD"
    assert (hw["ram_type"], hw["ram_speed"], hw["ram_slots"]) == ("DDR4", "2933 MHz", "2/4")


# ── macOS: system_profiler SPMemoryDataType -json ────────────────────────────

INTEL_IMAC_MEMORY = json.dumps({"SPMemoryDataType": [{
    "_name": "memory",
    "is_memory_upgradeable": "Yes",
    "_items": [
        {"_name": "BANK 0/ChannelA-DIMM0", "dimm_size": "8 GB",
         "dimm_speed": "2667 MHz", "dimm_type": "DDR4"},
        {"_name": "BANK 1/ChannelA-DIMM1", "dimm_size": "empty",
         "dimm_speed": "empty", "dimm_type": "empty"},
        {"_name": "BANK 0/ChannelB-DIMM0", "dimm_size": "8 GB",
         "dimm_speed": "2667 MHz", "dimm_type": "DDR4"},
        {"_name": "BANK 1/ChannelB-DIMM1", "dimm_size": "empty",
         "dimm_speed": "empty", "dimm_type": "empty"},
    ],
}]})

INTEL_MACBOOK_MEMORY = json.dumps({"SPMemoryDataType": [{
    "_name": "memory",
    "is_memory_upgradeable": "No",
    "_items": [
        {"_name": "BANK 0/ChannelA-DIMM0", "dimm_size": "8 GB",
         "dimm_speed": "2133 MHz", "dimm_type": "LPDDR3"},
        {"_name": "BANK 1/ChannelB-DIMM0", "dimm_size": "8 GB",
         "dimm_speed": "2133 MHz", "dimm_type": "LPDDR3"},
    ],
}]})

APPLE_SILICON_MEMORY = json.dumps({"SPMemoryDataType": [{
    "SPMemoryDataType": "16 GB",
    "dimm_manufacturer": "Hynix",
    "dimm_type": "LPDDR5",
}]})


def test_macos_intel_memory_with_slots(agent):
    assert agent._parse_macos_memory(INTEL_IMAC_MEMORY) == {
        "ram_type": "DDR4", "ram_speed": "2667 MHz", "ram_slots": "2/4",
    }


def test_macos_soldered_intel_memory_is_not_reported_as_slots(agent):
    assert agent._parse_macos_memory(INTEL_MACBOOK_MEMORY) == {
        "ram_type": "LPDDR3", "ram_speed": "2133 MHz", "ram_slots": "Soldered",
    }


def test_macos_apple_silicon_memory_has_type_but_no_speed(agent):
    """Unified memory: no slots, and macOS does not report a speed."""
    assert agent._parse_macos_memory(APPLE_SILICON_MEMORY) == {
        "ram_type": "LPDDR5", "ram_slots": "Soldered",
    }


def test_macos_memory_unparseable_output_reports_nothing(agent):
    assert agent._parse_macos_memory("") == {}
    assert agent._parse_macos_memory("not json") == {}


# ── macOS: diskutil info -plist / ────────────────────────────────────────────

def _diskutil(protocol, solid_state):
    return plistlib.dumps({"BusProtocol": protocol, "SolidState": solid_state}).decode()


@pytest.mark.parametrize(
    "protocol, solid, expected",
    [
        ("Apple Fabric", True, "Integrated SSD (Apple Fabric)"),
        ("PCI-Express", True, "PCIe SSD"),
        ("SATA", True, "SATA SSD"),
        ("SATA", False, "SATA HDD"),
        ("USB", True, "USB SSD"),
    ],
)
def test_macos_storage_type(agent, protocol, solid, expected):
    assert agent._parse_macos_storage_type(_diskutil(protocol, solid)) == expected


def test_macos_storage_type_unparseable_output_reports_nothing(agent):
    assert agent._parse_macos_storage_type("") is None
    assert agent._parse_macos_storage_type(plistlib.dumps({}).decode()) is None


# ── Payload gating ───────────────────────────────────────────────────────────

def test_detail_fields_follow_their_parent_hardware_toggle(agent, monkeypatch):
    """A company that switched RAM off in the portal must not get the RAM
    detail either -- the detail fields have no toggle of their own."""
    sent = {}
    monkeypatch.setattr(agent, "_post_to_sheets", lambda p: sent.update(p) or True)
    hw = {
        "serial_number": "S", "hostname": "h", "brand": "b", "model": "m",
        "os": "o", "timestamp": "t", "ram": "16 GB", "storage": "512G",
        "ram_type": "DDR4", "ram_speed": "3200 MHz", "ram_slots": "2/4",
        "storage_type": "NVMe SSD",
    }
    agent.submit_to_sheets({"first_name": "A"}, hw, ["storage"])

    assert "ram" not in sent and "ram_type" not in sent
    assert "ram_speed" not in sent and "ram_slots" not in sent
    assert sent["storage"] == "512G"
    assert sent["storage_type"] == "NVMe SSD"
