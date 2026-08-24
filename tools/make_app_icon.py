#!/usr/bin/env python3
"""Renders assetly_icon.png -- the square app icon -- from the logo's geometry.

The macOS agent needs a square icon for its .app bundle, and assetly_logo.svg
is a 400x180 wordmark whose node-graph mark is only ~166px wide once
rasterised into assetly_logo.png. Cropping that raster and scaling it up to
1024 gives a visibly soft icon, so this redraws the mark from the SVG's own
coordinates at full size instead.

Stdlib only (zlib + struct), matching the constraint the agent itself works
under -- this repo has no image library, and adding one for a file that is
regenerated roughly never is not a trade worth making.

Run from the repo root when the mark changes:

    python3 tools/make_app_icon.py

and commit the resulting assetly_icon.png.
"""

import math
import struct
import zlib
from pathlib import Path

SIZE = 1024        # 1024 is the largest size iconutil asks for.
SS = 4             # 4x supersampling; the mark is all curves and diagonals.

# The mark in assetly_logo.svg's 400x180 user space.
NODES = [((70.0, 57.0), (0xF2, 0xF5, 0xF7)),
         ((36.0, 123.0), (0x4E, 0xCD, 0xB4)),
         ((104.0, 123.0), (0x4E, 0xCD, 0xB4))]
EDGES = [(((70.0, 57.0), (36.0, 123.0)), (0x5F, 0xD8, 0xBE)),
         (((70.0, 57.0), (104.0, 123.0)), (0x4C, 0xC3, 0xA6)),
         (((36.0, 123.0), (104.0, 123.0)), (0x3A, 0xA9, 0x8F))]
NODE_R = 7.5
EDGE_W = 3.5
BACKDROP = (0x0D, 0x11, 0x19)

# The mark's bounding box is x 28.5..111.5, y 49.5..130.5. A 122-unit square
# centred on it leaves roughly the 10% margin macOS icons are drawn with.
VIEW_C = (70.0, 90.0)
VIEW_SIZE = 122.0

# macOS rounds icon corners itself in some contexts but not all, so the
# backdrop carries the same 18/400 radius the SVG's rect uses, scaled up.
CORNER_R = 18.0 / 400.0 * VIEW_SIZE * 1.9


def _dist_to_segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def _inside_rounded_square(x, y, half, r):
    """Rounded-square coverage test in view units, centred on the origin."""
    ax, ay = abs(x), abs(y)
    if ax > half or ay > half:
        return False
    if ax <= half - r or ay <= half - r:
        return True
    return math.hypot(ax - (half - r), ay - (half - r)) <= r


def render() -> bytes:
    """Returns SIZE x SIZE RGBA pixel rows, supersampled SS times per axis."""
    scale = VIEW_SIZE / SIZE
    origin_x = VIEW_C[0] - VIEW_SIZE / 2.0
    origin_y = VIEW_C[1] - VIEW_SIZE / 2.0
    half = VIEW_SIZE / 2.0

    rows = []
    for py in range(SIZE):
        row = bytearray()
        for px in range(SIZE):
            r_acc = g_acc = b_acc = a_acc = 0
            for sy in range(SS):
                for sx in range(SS):
                    # Sample at the centre of each subpixel.
                    ux = origin_x + (px + (sx + 0.5) / SS) * scale
                    uy = origin_y + (py + (sy + 0.5) / SS) * scale

                    if not _inside_rounded_square(ux - VIEW_C[0], uy - VIEW_C[1],
                                                  half, CORNER_R):
                        continue  # transparent outside the rounded backdrop

                    colour = BACKDROP
                    # Painter's order matches the SVG: edges, then nodes.
                    for (a, b), edge_colour in EDGES:
                        if _dist_to_segment(ux, uy, a[0], a[1], b[0], b[1]) <= EDGE_W / 2.0:
                            colour = edge_colour
                            break
                    for (cx, cy), node_colour in NODES:
                        if math.hypot(ux - cx, uy - cy) <= NODE_R:
                            colour = node_colour
                            break

                    r_acc += colour[0]
                    g_acc += colour[1]
                    b_acc += colour[2]
                    a_acc += 255

            n = SS * SS
            if a_acc == 0:
                row += b"\x00\x00\x00\x00"
            else:
                # Un-premultiply: the accumulated colour is only over covered
                # subpixels, so divide by coverage rather than by n.
                covered = a_acc // 255
                row += bytes((r_acc // covered, g_acc // covered,
                              b_acc // covered, a_acc // n))
        rows.append(bytes(row))
    return rows


def write_png(path: Path, rows: list) -> None:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    raw = b"".join(b"\x00" + row for row in rows)   # filter type 0 per row
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    path.write_bytes(png)


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "assetly_icon.png"
    write_png(out, render())
    print(f"wrote {out} ({out.stat().st_size} bytes, {SIZE}x{SIZE})")
