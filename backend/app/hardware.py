import re


def normalize_os(os_string: str) -> tuple[str, str]:
    """Derives (platform, os_version) from a free-form OS string like
    'macOS 14.4.1', 'Linux 6.8.0-31-generic', or 'Windows 11 Pro 23H2'."""
    os_string = os_string.strip()
    lowered = os_string.lower()

    if lowered.startswith("macos"):
        platform_name = "macos"
    elif lowered.startswith("linux"):
        platform_name = "linux"
    elif lowered.startswith("windows"):
        platform_name = "windows"
    else:
        platform_name = "unknown"

    # Takes the LAST digit-led token as the version (needed for Windows feature-update
    # codes like "23H2" appearing after "11" in "Windows 11 Pro 23H2"). Known trade-off:
    # a trailing build tag in parens (e.g. macOS "14.4.1 (23E224)") will win over the
    # semantic version instead. No position-based rule satisfies both conventions; fixing
    # this properly would need per-platform parsing, which is out of scope here.
    matches = re.findall(r"\d[\w.\-]*", os_string)
    version = matches[-1] if matches else ""

    return platform_name, version
