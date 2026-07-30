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

    match = re.search(r"(\d[\w.\-]*)$", os_string)
    version = match.group(1) if match else os_string

    return platform_name, version
