from app.hardware import normalize_os


def test_normalize_macos_string():
    platform, version = normalize_os("macOS 14.4.1")
    assert platform == "macos"
    assert version == "14.4.1"


def test_normalize_linux_string():
    platform, version = normalize_os("Linux 6.8.0-31-generic")
    assert platform == "linux"
    assert version == "6.8.0-31-generic"


def test_normalize_windows_string():
    platform, version = normalize_os("Windows 11 Pro 23H2")
    assert platform == "windows"
    assert version == "23H2"


def test_normalize_unrecognized_string_returns_unknown_platform():
    platform, version = normalize_os("SomeOtherOS 1.0")
    assert platform == "unknown"
    assert version == "1.0"
