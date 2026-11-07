"""Generate credstore's app icons (PNG and ICO) with the standard library only.

The icon is a rounded square with a keyhole. Run from anywhere:
    python app/icons/make_icons.py
"""
import math
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
BG = (24, 94, 88)       # deep teal
FG = (240, 247, 245)    # off-white


def pixel(x, y, n):
    """RGBA at (x, y) for an n x n icon, with 4x4 supersampling."""
    acc = [0.0, 0.0, 0.0, 0.0]
    for sy in range(4):
        for sx in range(4):
            u = (x + (sx + 0.5) / 4) / n
            v = (y + (sy + 0.5) / 4) / n
            # Rounded square, corner radius 0.2.
            r = 0.2
            dx = max(abs(u - 0.5) - (0.5 - r), 0)
            dy = max(abs(v - 0.5) - (0.5 - r), 0)
            if math.hypot(dx, dy) > r:
                continue
            # Keyhole: circle on top, tapered slot below.
            cx, cy = 0.5, 0.42
            in_circle = math.hypot(u - cx, v - cy) < 0.14
            half = 0.045 + (v - 0.42) * 0.12
            in_slot = 0.42 <= v <= 0.74 and abs(u - cx) < half
            c = FG if (in_circle or in_slot) else BG
            acc[0] += c[0]
            acc[1] += c[1]
            acc[2] += c[2]
            acc[3] += 255
    return tuple(int(round(a / 16)) for a in acc)


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
    sizes = {32: png(32), 128: png(128), 256: png(256)}
    with open(os.path.join(HERE, "32x32.png"), "wb") as f:
        f.write(sizes[32])
    with open(os.path.join(HERE, "128x128.png"), "wb") as f:
        f.write(sizes[128])
    with open(os.path.join(HERE, "icon.png"), "wb") as f:
        f.write(sizes[256])
    with open(os.path.join(HERE, "icon.ico"), "wb") as f:
        f.write(ico([(32, sizes[32]), (256, sizes[256])]))
    print("wrote icons to", HERE)


if __name__ == "__main__":
    main()
