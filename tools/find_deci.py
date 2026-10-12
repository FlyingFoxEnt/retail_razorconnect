"""Locate the DECI greeting constant in the Target Manager binaries and dump context.

Shows bytes around every occurrence of b'DECI' so adjacent magic constants /
expected responses become visible.
"""
import sys, os

TARGETS = [
    r"C:\Program Files (x86)\SCE\PSP2\Tools\Target Manager Server\bin\psp2tm.exe",
    r"C:\Program Files (x86)\SCE\PSP2\Tools\Target Manager Server\api\psp2tmapix64.dll",
    r"C:\Program Files (x86)\SCE\PSP2\Tools\Target Manager Server\api\psp2tmapix86.dll",
]

NEEDLE = b"DECI"
CTX = 48

def hexdump(data, base):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {base + off:08x}  {hexpart:<47}  |{asciipart}|")
    return "\n".join(out)

for path in TARGETS:
    if not os.path.exists(path):
        print(f"== {path}: NOT FOUND")
        continue
    data = open(path, "rb").read()
    hits = []
    start = 0
    while True:
        i = data.find(NEEDLE, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    print(f"== {path}: {len(hits)} occurrence(s) of {NEEDLE!r}, size {len(data)}")
    for i in hits[:20]:
        lo = max(0, i - CTX)
        hi = min(len(data), i + CTX)
        print(f"-- offset 0x{i:08x}")
        print(hexdump(data[lo:hi], lo))
    print()
