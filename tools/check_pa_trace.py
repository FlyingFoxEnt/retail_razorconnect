"""Checks plugin/pa_trace.c: windowed encoding == the one-pass encoder, and valid output.

Builds tools/pa_trace_host.c with MSVC (vcvars64.bat), runs it over several seeds, ring
sizes and record counts (including a wrapped ring and an empty one), then decodes each
reference trace with the Python readers (pa_frames / pa_systrace / pa_pft) the same way
check_pa_encode.py does.
Run: python check_pa_trace.py
"""
import glob
import os
import struct
import subprocess
import sys
import tempfile

import pa_frames as pf
import pa_pft
import pa_systrace as st

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.join(HERE, "..", "plugin")


def build():
    vcvars = sorted(glob.glob(r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat"))[-1]
    tmp = tempfile.mkdtemp(prefix="pa_trace_")
    exe = os.path.join(tmp, "pa_trace_host.exe")
    src = [os.path.join(HERE, "pa_trace_host.c"), os.path.join(PLUGIN, "pa_trace.c"),
           os.path.join(PLUGIN, "pa_encode.c")]
    cmd = 'call "%s" >nul && cl /nologo /O2 /W3 /DPA_HOSTED /Fe"%s" /Fo"%s\\\\" %s' % (
        vcvars, exe, tmp, " ".join('"%s"' % s for s in src))
    subprocess.run(cmd, shell=True, check=True, cwd=tmp, stdout=subprocess.DEVNULL)
    return exe, tmp


def decode(raw):
    assert len(raw) % pf.FRAME_SIZE == 0
    sys0 = [b for b in pf.iter_bookmarks(raw) if b[0] == 1 and b[1] == 6]
    d = st.razor_decode(sys0)
    warnings = d["warnings"] if isinstance(d["warnings"], list) else [d["warnings"]] * d["warnings"]
    slots = []
    for f in range(0, len(raw), pf.FRAME_SIZE):
        for i, desc in enumerate(struct.unpack_from("<7H", raw, f + 2)):
            if (desc >> 8) & 0x7F == 0x10:
                slots.append((desc, raw[f + 0x10 + i * 0x10:f + 0x20 + i * 0x10]))
    streams = pa_pft.razor_deformat(slots)
    samples = 0
    for s in (streams.values() if isinstance(streams, dict) else streams):
        if s:
            samples += sum(pa_pft.razor_decode_pc_samples(bytes(s)).values())
    return len(d["intervals"]), warnings, samples


def main():
    exe, tmp = build()
    cases = [
        (1, 5000, 3000),      # ring not full
        (2, 5000, 20000),     # wrapped several times
        (3, 65536, 60000),    # the kernel's ring size, nearly full
        (4, 32768, 90000),    # the old ring size, wrapped
        (5, 4096, 0),         # no records: the fallback interval
        (6, 300, 5000),       # tiny ring, heavy wrap
        (7, 65536, 65536),
    ]
    for seed, cap, n in cases:
        out = os.path.join(tmp, "trace_%d.raw" % seed)
        r = subprocess.run([exe, str(seed), str(cap), str(n), out], capture_output=True, text=True)
        if r.returncode != 0:
            print("FAIL seed %d cap %d records %d: %s" % (seed, cap, n, (r.stderr or r.stdout).strip()))
            return 1
        stats = dict(kv.split("=") for kv in r.stdout.split())
        raw = open(out, "rb").read()
        intervals, warnings, samples = decode(raw)
        assert intervals == int(stats["intervals"]), (intervals, stats)
        assert not warnings, warnings[:5]
        assert samples == int(stats["samples"]), (samples, stats)
        print("seed %d cap %6d records %6s: %8s bytes (%5.1f B/record), %6d intervals, %6d PC samples - windowed reads identical"
              % (seed, cap, stats["records"], stats["bytes"],
                 int(stats["bytes"]) / max(1, int(stats["records"])), intervals, samples))
    print("pa_trace.c OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
