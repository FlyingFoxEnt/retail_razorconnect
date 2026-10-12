"""Decodes a CPU (PA) trace read back from the console, the way Razor does, and summarises it.

    python check_trace_file.py trace.raw

The trace comes from tools/pa_capture (`pa_capture cpu <seconds> trace.raw`). Prints the time
span, intervals per CPU and per thread, PC samples, and any scheduler warnings Razor would log.
Exit status 1 if Razor would reject the trace (no intervals) or report missing events.
"""
import collections
import struct
import sys

import pa_frames as pf
import pa_pft
import pa_systrace as st

TICKS_PER_S = 333_000_000


def main(path):
    raw = open(path, "rb").read()
    if not raw:
        print("empty file: this is what Razor calls 'Capture buffer is empty'")
        return 1
    if len(raw) % pf.FRAME_SIZE:
        print("size %d is not a multiple of 0x%x" % (len(raw), pf.FRAME_SIZE))
        return 1
    sys0 = [b for b in pf.iter_bookmarks(raw) if b[0] == 1 and b[1] == 6]
    d = st.razor_decode(sys0)
    ivs = d["intervals"]
    warnings = d["warnings"] if isinstance(d["warnings"], list) else [d["warnings"]]

    slots = []
    for f in range(0, len(raw), pf.FRAME_SIZE):
        for i, desc in enumerate(struct.unpack_from("<7H", raw, f + 2)):
            if (desc >> 8) & 0x7F == 0x10:
                slots.append((desc, raw[f + 0x10 + i * 0x10:f + 0x20 + i * 0x10]))
    streams = pa_pft.razor_deformat(slots)
    pcs = collections.Counter()
    for s in (streams.values() if isinstance(streams, dict) else streams):
        if s:
            pcs.update(pa_pft.razor_decode_pc_samples(bytes(s)))

    print("%s: %d bytes, %d frames, %d SYS_0 bookmarks" % (path, len(raw), len(raw) // pf.FRAME_SIZE, len(sys0)))
    if ivs:
        t0 = min(iv["start"] for iv in ivs)
        t1 = max(iv["end"] for iv in ivs)
        print("span %.3f s, %d intervals, %d PC samples (%d distinct PCs)"
              % ((t1 - t0) / TICKS_PER_S, len(ivs), sum(pcs.values()), len(pcs)))
        per_cpu = collections.Counter(iv["cpu"] for iv in ivs)
        busy = collections.Counter()
        for iv in ivs:
            busy[iv["cpu"]] += iv["end"] - iv["start"]
        for cpu in sorted(per_cpu):
            print("  cpu %d: %6d intervals, %5.1f%% of the span in the traced process"
                  % (cpu, per_cpu[cpu], 100.0 * busy[cpu] / max(1, t1 - t0)))
        per_tid = collections.Counter()
        for iv in ivs:
            per_tid[iv["tid"]] += iv["end"] - iv["start"]
        print("  busiest threads:")
        for tid, t in per_tid.most_common(8):
            print("    0x%08x  %8.1f ms" % (tid, t * 1000.0 / TICKS_PER_S))
        if pcs:
            print("  hottest PCs:")
            for pc, n in pcs.most_common(8):
                print("    0x%08x  %d" % (pc, n))
    for w in warnings:
        print("WARNING (Razor would log): %s" % w)
    return 1 if (not ivs or warnings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
