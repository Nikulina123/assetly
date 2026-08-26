import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_inventory_agent():
    spec = importlib.util.spec_from_file_location(
        "inventory_agent", REPO_ROOT / "inventory_agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["inventory_agent"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def inventory_agent():
    return _load_inventory_agent()


def test_collect_hardware_prefers_sysfs_serial_on_linux(inventory_agent, monkeypatch):
    monkeypatch.setattr(inventory_agent, "_sys", "Linux")
    monkeypatch.setattr(
        inventory_agent.socket, "gethostname", lambda: "test-host"
    )
    monkeypatch.setattr(inventory_agent, "get_ip", lambda: "10.0.0.1")

    dmidecode_calls = []

    def fake_run(cmd, sudo=False):
        if cmd and cmd[0] == "dmidecode":
            dmidecode_calls.append((cmd, sudo))
            return ""
        if cmd == ["cat", "/proc/cpuinfo"]:
            return "model name : Fake CPU\n"
        if cmd == ["cat", "/proc/meminfo"]:
            return "MemTotal:       16000000 kB\n"
        return ""

    monkeypatch.setattr(inventory_agent, "_run", fake_run)

    def fake_read_text(self):
        mapping = {
            "sys_vendor": "Dell Inc.\n",
            "product_name": "OptiPlex 7090\n",
            "product_serial": "SYSFS-SERIAL-456\n",
        }
        for key, value in mapping.items():
            if key in str(self):
                return value
        raise FileNotFoundError

    monkeypatch.setattr(inventory_agent.Path, "read_text", fake_read_text)

    hw = inventory_agent.collect_hardware()
    assert hw["serial_number"] == "SYSFS-SERIAL-456"
    assert hw["brand"] == "Dell Inc."
    assert hw["model"] == "OptiPlex 7090"
    assert dmidecode_calls == []  # dmidecode never invoked when sysfs works


def test_clean_normalizes_sysfs_and_dmidecode_output_identically(inventory_agent):
    assert inventory_agent._clean("SYSFS-SERIAL-456\n") == "SYSFS-SERIAL-456"
    assert inventory_agent._clean("SYSFS-SERIAL-456  \n") == "SYSFS-SERIAL-456"
