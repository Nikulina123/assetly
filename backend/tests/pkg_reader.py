"""Reads back the macOS flat packages app.macos_pkg builds.

Deliberately an independent implementation rather than an inverse of the
builder's own helpers: a test that unpacks a package using the packer's
constants would keep passing if both agreed on a format Apple's tools reject.
This parses the container the way the format documents it -- fixed-offset xar
header, zlib'd TOC, offsets into the heap, POSIX cpio -- so a round trip here is
evidence about the bytes, not about shared code.
"""

import gzip
import struct
import zlib
from xml.etree import ElementTree

_XAR_MAGIC = 0x78617221
_CPIO_ODC_MAGIC = b"070707"
_S_IFMT = 0o170000
_S_IFREG = 0o100000


def read_xar(archive: bytes) -> dict[str, bytes]:
    """Maps each file's name in the archive to its stored bytes.

    Names are the TOC's leaf names, so a component's Scripts blob comes back
    under "Scripts" regardless of which .pkg directory holds it -- fine here,
    where every package has exactly one component.
    """
    magic, header_size, _version, toc_compressed_len, _toc_len, _cksum = struct.unpack(
        ">IHHQQI", archive[:28]
    )
    if magic != _XAR_MAGIC:
        raise ValueError(f"not a xar archive: magic {magic:#x}")

    toc = zlib.decompress(archive[header_size : header_size + toc_compressed_len])
    heap = archive[header_size + toc_compressed_len :]

    files = {}
    for element in ElementTree.fromstring(toc).iter("file"):
        data = element.find("data")
        if data is None:  # directories carry no <data>
            continue
        offset = int(data.find("offset").text)
        length = int(data.find("length").text)
        files[element.find("name").text] = heap[offset : offset + length]
    return files


def read_cpio_odc(archive: bytes) -> dict[str, bytes]:
    """Extracts the regular files from a POSIX ("odc") cpio archive."""
    entries = {}
    position = 0
    while True:
        header = archive[position : position + 76]
        if header[:6] != _CPIO_ODC_MAGIC:
            raise ValueError(f"not an odc cpio header at offset {position}: {header[:6]!r}")
        mode = int(header[18:24], 8)
        name_size = int(header[59:65], 8)
        file_size = int(header[65:76], 8)
        position += 76

        name = archive[position : position + name_size - 1].decode()
        position += name_size
        if name == "TRAILER!!!":
            return entries

        contents = archive[position : position + file_size]
        position += file_size
        if mode & _S_IFMT == _S_IFREG:
            entries[name.removeprefix("./")] = contents


def read_flat_package(pkg: bytes) -> dict[str, bytes]:
    """Maps the names in a package's Scripts directory to their contents."""
    return read_cpio_odc(gzip.decompress(read_xar(pkg)["Scripts"]))
