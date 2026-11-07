"""Generate credstore's app icons (PNG and ICO) with the standard library only.

The mark (docs/VISUAL.md): an obsidian rounded tile with a thin gray edge, an ice gray
slot across the middle (a key's opening), and one racing red dot top right, the same
red that means a request is waiting. Drawn on a 64-unit grid, like the SVG in
app/ui/index.html. Run from anywhere:
    python app/icons/make_icons.py
"""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OBSIDIAN = (0x0E, 0x0F, 0x12)
EDGE = (0x3A, 0x40, 0x48)
ICE = (0xDC, 0xE3, 0xEA)
RED = (0xD4, 0x00, 0x00)
SS = 6  # supersamples per axis


def in_rrect(x, y, x0, y0, x1, y1, r):
    """Point inside the rounded rectangle (x0, y0)-(x1, y1) with corner radius r."""
    if not (x0 <= x <= x1 and y0 <= y <= y1):
        return False
    cx = min(max(x, x0 + r), x1 - r)
    cy = min(max(y, y0 + r), y1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def color_at(x, y):
    """Color at (x, y) on the 64-unit grid, or None outside the tile."""
    if not in_rrect(x, y, 0, 0, 64, 64, 16):
        return None
    if not in_rrect(x, y, 2, 2, 62, 62, 14):
        return EDGE
    if (x - 47) ** 2 + (y - 16) ** 2 <= 25:
        return RED
    if in_rrect(x, y, 13, 27, 51, 37, 5):
        return ICE
    return OBSIDIAN


def pixel(px, py, n):
    acc = [0.0, 0.0, 0.0, 0.0]
    for sy in range(SS):
        for sx in range(SS):
            x = (px + (sx + 0.5) / SS) * 64 / n
            y = (py + (sy + 0.5) / SS) * 64 / n
            c = color_at(x, y)
            if c is None:
                continue
            acc[0] += c[0]
            acc[1] += c[1]
            acc[2] += c[2]
            acc[3] += 255
    count = SS * SS
    alpha = acc[3] / count
    if alpha == 0:
        return (0, 0, 0, 0)
    # Straight (not premultiplied) alpha: average color over covered samples.
    covered = acc[3] / 255
    return (round(acc[0] / covered), round(acc[1] / covered), round(acc[2] / covered), round(alpha))


def png(n):
    rows = b""
    for y in range(n):
        rows += b"\x00" + b"".join(bytes(pixel(x, y, n)) for x in range(n))

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


def ico(images):
    """ICO with PNG-compressed entries (Windows Vista and later)."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    data = b""
    for n, blob in images:
        dim = 0 if n >= 256 else n
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset + len(data))
        data += blob
    return header + entries + data


def main():
    sizes = {n: png(n) for n in (16, 24, 32, 48, 64, 128, 256)}
    for name, n in (("32x32.png", 32), ("128x128.png", 128), ("icon.png", 256)):
        with open(os.path.join(HERE, name), "wb") as f:
            f.write(sizes[n])
    with open(os.path.join(HERE, "icon.ico"), "wb") as f:
        f.write(ico(sorted(sizes.items())))
    print("wrote icons to", HERE)


if __name__ == "__main__":
    main()
