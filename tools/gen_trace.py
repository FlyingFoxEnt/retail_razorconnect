"""Synthesize a PA trace buffer for mock_pamp.py (TRACEFILE) to test Razor's decoder.

python gen_trace.py out.raw [variant]
  pc      one timestamp bookmark + PC samples (PFT I-sync) on CPUs 0 and 1
  sched   one timestamp bookmark + scheduler switch in/out packets (FIFO B SYS_0)
  full    both
"""
import random
import sys

import pa_frames as pf
import pa_pft
import pa_systrace

TEXT_BASE = 0x81000000           # mock_pamp.py game module text segment
HOT = [(0x81000100, 50), (0x81004000, 25), (0x81010020, 15), (0x81123450, 10)]
GAME_PID = 0x40010045            # mock_pamp.py PROCS / THREADS
SHELL_PID = 0x40010003
TID_MAIN, TID_RENDER = 0x40010201, 0x40010202


def schedule(seconds, slice_ms=4):
    """main on CPU 0 and RenderThread on CPU 1, each giving way to a SceShell-less gap."""
    w = pa_systrace.SysTraceWriter()
    t = pf.ticks(0.006)
    end = t + pf.ticks(seconds)
    step = pf.ticks(slice_ms / 1000.0)
    while t + step < end:
        w.switch_in(0, t, GAME_PID, TID_MAIN, 160)
        w.switch_in(1, t + 100, GAME_PID, TID_RENDER, 160)
        w.switch_out(0, t + step * 3 // 4, pa_systrace.SCE_THREAD_READY)
        w.switch_out(1, t + step * 3 // 4 + 100, pa_systrace.SCE_THREAD_WAITING)
        t += step
    w.close_all(end)
    return [pf.Bookmark(*b) for b in w.sorted_bookmarks()]


def pc_samples(n, seconds, cpus=(0, 1), seed=1):
    rnd = random.Random(seed)
    addrs = [a for a, w in HOT for _ in range(w)]
    out = []
    t0 = pf.ticks(0.010)
    for i in range(n):
        t = t0 + int(pf.ticks(seconds) * i / n)
        out.append((cpus[i % len(cpus)], t, rnd.choice(addrs), 0, 0))
    return out


def build(variant):
    events = [pf.Bookmark(pf.FIFO_A, 0, 1, pf.ticks(0.005), 0)]
    if variant in ("sched", "full"):
        events += schedule(2.0)
    if variant in ("pc", "full"):
        samples = pc_samples(4000, 2.0)
        for t, desc, slot in pa_pft.samples_to_timed_slots(samples):
            events.append(pf.PftChunk(desc & 0xFF, t, slot))
    return pf.pack(events)


if __name__ == "__main__":
    out = sys.argv[1]
    raw = build(sys.argv[2] if len(sys.argv) > 2 else "pc")
    open(out, "wb").write(raw)
    print("wrote %s: %d bytes, %d frames" % (out, len(raw), len(raw) // pf.FRAME_SIZE))
