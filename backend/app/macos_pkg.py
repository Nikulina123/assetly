"""Builds macOS flat installer packages (.pkg) in pure Python.

The admin portal runs on Linux (Vercel), where Apple's pkgbuild/productbuild do
not exist, so the download route has to assemble the archive itself. Only the
payload-free shape is supported: everything the installer does happens in a
postinstall script rather than by laying down a file payload. That is a
deliberate restriction, not a shortcut -- a package with a payload also needs a
Bom (Apple's undocumented binary bill-of-materials), whereas
`pkgbuild --nopayload` emits just PackageInfo + Scripts and no Bom at all.
Reproducing that exact shape keeps this module to the four pieces of the xar
container below, with no binary format left to reverse-engineer.

A .pkg is a xar archive:

    [ 28-byte header ][ zlib-compressed TOC (XML) ][ heap ]

The heap starts with the SHA-1 of the compressed TOC, and every file's bytes
follow at the offsets the TOC declares. Files here are stored uncompressed
(`application/octet-stream`), so archived and extracted size/checksum are the
same value -- the packages this produces are tens of kilobytes, and skipping
per-file gzip removes a whole class of offset/length bookkeeping bugs.
"""

import hashlib
import struct
import zlib
from datetime import datetime, timezone
from xml.sax.saxutils import escape, quoteattr

_XAR_MAGIC = 0x78617221  # 'xar!'
_XAR_HEADER_SIZE = 28
_XAR_VERSION = 1
_XAR_CKSUM_SHA1 = 1
_SHA1_SIZE = 20

# cpio "odc" (POSIX portable ASCII, magic 070707): a 76-byte all-octal header,
# then the NUL-terminated name, then the data, with no padding anywhere. Chosen
# over "newc" because the fixed-width octal fields make it the least
# error-prone of the cpio variants to emit by hand.
_CPIO_MAGIC = "070707"
_CPIO_TRAILER = "TRAILER!!!"
_S_IFREG = 0o100000
_S_IFDIR = 0o040000


def _cpio_header(name: str, mode: int, size: int, ino: int) -> bytes:
    return (
        _CPIO_MAGIC
        + f"{0:06o}"       # dev
        + f"{ino:06o}"     # ino
        + f"{mode:06o}"    # mode
        + f"{0:06o}"       # uid  (root -- the installer runs scripts as root)
        + f"{0:06o}"       # gid
        + f"{1:06o}"       # nlink
        + f"{0:06o}"       # rdev
        + f"{0:011o}"      # mtime (zeroed: the archive must be reproducible)
        + f"{len(name) + 1:06o}"
        + f"{size:011o}"
    ).encode() + name.encode() + b"\0"


def build_scripts_archive(scripts: dict[str, bytes]) -> bytes:
    """cpio.gz of a package's Scripts directory, the form Installer expects.

    Every entry is mode 0755: `postinstall` has to be executable to run at all,
    and the payload files it copies into place are re-chmod'd by the script
    itself once they reach their destination.
    """
    out = bytearray()
    out += _cpio_header(".", _S_IFDIR | 0o755, 0, ino=1)
    for i, (name, data) in enumerate(sorted(scripts.items()), start=2):
        out += _cpio_header(f"./{name}", _S_IFREG | 0o755, len(data), ino=i)
        out += data
    out += _cpio_header(_CPIO_TRAILER, 0, 0, ino=0)
    # mtime=0 so identical inputs produce identical bytes.
    return gzip_bytes(bytes(out))


def gzip_bytes(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


class _HeapFile:
    """One TOC <file> entry plus the heap bytes it points at."""

    def __init__(self, name: str, data: bytes, offset: int, *, nested: bool):
        self.name = name
        self.data = data
        self.offset = offset
        self.nested = nested
        self.checksum = hashlib.sha1(data).hexdigest()

    def toc_xml(self, file_id: int, indent: str) -> str:
        return (
            f'{indent}<file id="{file_id}">\n'
            f"{indent} <name>{escape(self.name)}</name>\n"
            f"{indent} <type>file</type>\n"
            f"{indent} <data>\n"
            f'{indent}  <archived-checksum style="sha1">{self.checksum}</archived-checksum>\n'
            f'{indent}  <extracted-checksum style="sha1">{self.checksum}</extracted-checksum>\n'
            f'{indent}  <encoding style="application/octet-stream"/>\n'
            f"{indent}  <offset>{self.offset}</offset>\n"
            f"{indent}  <size>{len(self.data)}</size>\n"
            f"{indent}  <length>{len(self.data)}</length>\n"
            f"{indent} </data>\n"
            f"{indent}</file>\n"
        )


def _package_info(identifier: str, version: str) -> bytes:
    """PackageInfo for a payload-free component.

    `<payload/>` is omitted entirely rather than declared with zero counts,
    matching what `pkgbuild --nopayload` writes; auth="root" is what lets the
    postinstall write to /Library and load a system LaunchAgent.
    """
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<pkg-info overwrite-permissions="true" relocatable="false" identifier={quoteattr(identifier)} '
        f'postinstall-action="none" version={quoteattr(version)} format-version="2" auth="root">\n'
        "    <scripts>\n"
        '        <postinstall file="./postinstall" timeout="1800"/>\n'
        "    </scripts>\n"
        "</pkg-info>\n"
    ).encode()


def _distribution(identifier: str, version: str, title: str, component_name: str) -> bytes:
    """Product-archive wrapper.

    Without it macOS Installer titles the window with the raw component
    filename; with it the user sees the product's real name. `customize="never"`
    removes the pointless one-item package-selection pane.
    """
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<installer-gui-script minSpecVersion="1">\n'
        f"    <title>{escape(title)}</title>\n"
        f"    <pkg-ref id={quoteattr(identifier)}/>\n"
        '    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>\n'
        "    <choices-outline>\n"
        '        <line choice="default">\n'
        f"            <line choice={quoteattr(identifier)}/>\n"
        "        </line>\n"
        "    </choices-outline>\n"
        '    <choice id="default"/>\n'
        f'    <choice id={quoteattr(identifier)} visible="false">\n'
        f"        <pkg-ref id={quoteattr(identifier)}/>\n"
        "    </choice>\n"
        f'    <pkg-ref id={quoteattr(identifier)} version={quoteattr(version)} onConclusion="none" '
        f'installKBytes="0" updateKBytes="0">#{escape(component_name)}</pkg-ref>\n'
        "</installer-gui-script>\n"
    ).encode()


def build_flat_package(
    *,
    identifier: str,
    version: str,
    title: str,
    scripts: dict[str, bytes],
    component_name: str = "component.pkg",
) -> bytes:
    """Returns the bytes of an installable, payload-free .pkg.

    `scripts` maps filenames to contents for the package's Scripts directory;
    it must contain "postinstall", which Installer runs as root with the
    extracted Scripts directory as its working directory -- that is how any
    other file in `scripts` gets to the target machine.
    """
    if "postinstall" not in scripts:
        raise ValueError("a payload-free package does nothing without a 'postinstall' script")

    scripts_blob = build_scripts_archive(scripts)
    package_info = _package_info(identifier, version)
    distribution = _distribution(identifier, version, title, component_name)

    # Heap layout: TOC checksum first (the TOC's <checksum> entry points at
    # offset 0), then each file at the offset recorded for it below.
    offset = _SHA1_SIZE
    heap_files = []
    for name, data, nested in (
        ("Scripts", scripts_blob, True),
        ("PackageInfo", package_info, True),
        ("Distribution", distribution, False),
    ):
        heap_files.append(_HeapFile(name, data, offset, nested=nested))
        offset += len(data)

    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    toc = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        "<xar>\n",
        " <toc>\n",
        '  <checksum style="sha1">\n',
        f"   <size>{_SHA1_SIZE}</size>\n",
        "   <offset>0</offset>\n",
        "  </checksum>\n",
        f"  <creation-time>{created}</creation-time>\n",
        # The component is a directory in the TOC; its two files are nested
        # inside it, and their <name> elements are leaf names, not paths.
        '  <file id="1">\n',
        f"   <name>{escape(component_name)}</name>\n",
        "   <type>directory</type>\n",
    ]
    next_id = 2
    for heap_file in heap_files:
        if heap_file.nested:
            toc.append(heap_file.toc_xml(next_id, "   "))
            next_id += 1
    toc.append("  </file>\n")
    for heap_file in heap_files:
        if not heap_file.nested:
            toc.append(heap_file.toc_xml(next_id, "  "))
            next_id += 1
    toc.append(" </toc>\n")
    toc.append("</xar>\n")

    toc_bytes = "".join(toc).encode()
    toc_compressed = zlib.compress(toc_bytes, 9)

    header = struct.pack(
        ">IHHQQI",
        _XAR_MAGIC,
        _XAR_HEADER_SIZE,
        _XAR_VERSION,
        len(toc_compressed),
        len(toc_bytes),
        _XAR_CKSUM_SHA1,
    )

    out = bytearray(header)
    out += toc_compressed
    out += hashlib.sha1(toc_compressed).digest()
    for heap_file in heap_files:
        out += heap_file.data
    return bytes(out)
