"""Identify a PS Vita PUP: header fields, segment table, and any plaintext clues
about whether it is retail or DevKit/TestKit firmware.
"""
import sys, struct, re

if len(sys.argv) < 2:
    sys.exit("usage: pup_info.py <file.PUP>")
PATH = sys.argv[1]

f = open(PATH, "rb")
head = f.read(0x400)

print("file:", PATH)
print("size:", f.seek(0, 2), "bytes")
f.seek(0)

print("\n--- first 0x100 bytes ---")
for off in range(0, 0x100, 16):
    chunk = head[off:off + 16]
    hexs = " ".join("%02x" % b for b in chunk)
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    print("  %04x  %-47s |%s|" % (off, hexs, asc))

magic = head[:8]
print("\nmagic:", magic)
if magic[:5] == b"SCEUF":
    pkg_ver, img_ver = struct.unpack_from("<II", head, 8)
    file_ver, seg_num = struct.unpack_from("<QQ", head, 0x10)
    print("package_version : 0x%x" % pkg_ver)
    print("image_version   : 0x%x  (%d -> %s)" % (img_ver, img_ver,
          "%d.%02d" % (img_ver >> 24, (img_ver >> 16) & 0xFF)))
    print("file_version    : 0x%x" % file_ver)
    print("segment_count   : %d" % seg_num)
    print("\n--- segment table ---")
    for i in range(min(seg_num, 24)):
        ent = struct.unpack_from("<QQQQ", head, 0x80 + i * 0x20)
        print("  seg %2d: id=0x%-6x offset=0x%-10x size=0x%-10x flags=0x%x" % (i, ent[0], ent[1], ent[2], ent[3]))

# Scan the whole file for plaintext markers that reveal target audience.
print("\n--- scanning for plaintext markers (this reads the whole file) ---")
MARKERS = [b"razor", b"Razor", b"deci", b"DECI", b"devkit", b"DevKit", b"TOOL", b"tool",
           b"DEM-", b"PDEL", b"PTEL", b"testkit", b"TestKit", b"psp2-updater", b"version.txt"]
counts = {}
f.seek(0)
prev = b""
while True:
    buf = f.read(8 << 20)
    if not buf:
        break
    window = prev + buf
    for m in MARKERS:
        c = window.count(m)
        if c:
            counts[m] = counts.get(m, 0) + c
    prev = buf[-64:]
for m, c in sorted(counts.items(), key=lambda kv: -kv[1]):
    print("  %-16r x%d" % (m, c))
if not counts:
    print("  none found (expected: PUP payload segments are encrypted)")
