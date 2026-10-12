"""Checks plugin/pa_encode.c against the Python reference decoders.

Builds tools/pa_encode_host.c with MSVC (vcvars64.bat), drives it with a random
schedule plus PC samples, and decodes the output with pa_frames / pa_systrace / pa_pft.
Run: python check_pa_encode.py
"""
import glob
import collections
import os
import random
import struct
import subprocess
import sys
import tempfile

import pa_frames as pf
import pa_pft
import pa_systrace as st

HERE = os.path.dirname(os.path.abspath(__file__))


def build():
    vcvars = sorted(glob.glob(r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat"))[-1]
    tmp = tempfile.gettempdir()
    exe = os.path.join(tmp, "pa_encode_host.exe")
    src = [os.path.join(HERE, "pa_encode_host.c"), os.path.join(HERE, "..", "plugin", "pa_encode.c")]
    cmd = 'call "%s" >nul && cl /nologo /O2 /W3 /DPA_HOSTED /Fe"%s" /Fo"%s\\\\" "%s" "%s"' % (
        vcvars, exe, tmp, src[0], src[1])
    subprocess.run(cmd, shell=True, check=True, cwd=tmp)
    return exe


def main():
    rnd = random.Random(7)
    pid = 0x40010045
    tids = [0x40010201 + i for i in range(6)]
    lines, want_hist, want_intervals = [], collections.Counter(), 0
    t = {c: 5_000_000 for c in range(3)}
    for _ in range(3000):
        cpu = rnd.randrange(3)
        tid = rnd.choice(tids)
        start = t[cpu] + rnd.randrange(1, 400_000)
        end = start + rnd.randrange(10_000, 900_000)
        lines.append("in %d %d %x %x %d" % (cpu, start, pid, tid, 160))
        for _ in range(rnd.randrange(0, 3)):
            pc = rnd.choice([0x81000100, 0x81004000, 0x81000235, 0x81123450])
            lines.append("pc %d %x" % (cpu, pc))
            want_hist[pc & ~1] += 1
        lines.append("out %d %d %x %x %d" % (cpu, end, pid, tid, rnd.choice([2, 8])))
        want_intervals += 1
        t[cpu] = end
    out = os.path.join(tempfile.gettempdir(), "pa_encode_host.raw")
    exe = build()
    subprocess.run([exe, out], input="\n".join(lines).encode(), check=True)
    raw = open(out, "rb").read()
    assert len(raw) % pf.FRAME_SIZE == 0

    sys0 = [b for b in pf.iter_bookmarks(raw) if b[0] == 1 and b[1] == 6]
    d = st.razor_decode(sys0)
    n_int = len(d["intervals"])
    n_warn = len(d["warnings"]) if isinstance(d["warnings"], list) else d["warnings"]
    assert n_int == want_intervals, (n_int, want_intervals)
    assert n_warn == 0, d["warnings"][:5]

    slots = []
    for f in range(0, len(raw), pf.FRAME_SIZE):
        for i, desc in enumerate(struct.unpack_from("<7H", raw, f + 2)):
            if (desc >> 8) & 0x7F == 0x10:
                slots.append((desc, raw[f + 0x10 + i * 0x10:f + 0x20 + i * 0x10]))
    streams = pa_pft.razor_deformat(slots)
    got = collections.Counter()
    for s in (streams.values() if isinstance(streams, dict) else streams):
        if s:
            got.update(pa_pft.razor_decode_pc_samples(bytes(s)))
    assert got == want_hist, (got, want_hist)
    print("pa_encode.c OK: %d bytes, %d intervals, %d PC samples" % (len(raw), want_intervals, sum(got.values())))


if __name__ == "__main__":
    sys.exit(main())
