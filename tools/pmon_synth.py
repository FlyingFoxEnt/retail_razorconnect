"""Synthesise a Razor GPU trace (.pmon) from the UE4.15 PSP2 GXM GPU-profiler CSV, so PSP2Razor
can load it offline and show GPU frame / vertex(TA) / fragment(3D) job rows.

Format reverse-engineered from PSP2Razor.dll 3.60.0.5 (see RAZOR_GPU_TRACE_FORMAT.md and
PMON_SYNTH_NOTES.md). All facts cite functions in that doc.

Container (verified FUN_101cee80 / FUN_101ce280 / FUN_101cec80 / FUN_101bc930 / FUN_101c2630):
  [0x00] 0xE0  PMON header : dword0 magic 'PMON'=0x4E4F4D50 ; +0x0c u32 version (0x10002/0x10003);
               +0x10 u32 flags ; +0x14 u32 dataEndOff ; +0x20 u32 dataStartOff ; +0x30/0x32 u16
               counted/sample period ; +0x34..+0x53 counted enable masks (all 0xFFFFFFFF) ;
               +0x74/+0x84/+0x94/+0xa4 sampled selection ; other fields 0.
  [0xE0] 0x10  PMNQ header : dword0 magic 'PMNQ'=0x4E4F4D51 ; rest 0.
  [0xF0] data  : a PS Vita PA trace buffer = 0x80-byte frames. Per frame:
               u16 pad(0) + 7 u16 descriptors + 7 x 16-byte slots.
               descriptor = (slotType<<8)|chanByte ; slotType 0x7f = timestamped bookmark.
               bookmark slot bytes:  [0:4] time_low32  [4:6] time_high16  [6:10] 0
                                     [10:12] bmDesc = fifo<<12 | regno<<8 | master
                                     [12:16] word1 (the bookmark data; matched by TypeMask/Value)
Times are ticks of the 333 MHz timebase (ClockRate in the export = 333000000): ticks = round(us*333).

Usage:  python pmon_synth.py <in.csv> <out.pmon> [--pid 0x40010003] [--version 0x10002]

How Razor turns this into GPU jobs (PMON_SYNTH_NOTES.md "Round 4"):
  * GPU job intervals are NOT taken from bookmarks: they are the event bars of the metrics
    "Vertex/Fragment Processing Job Active" (PERF_OVERVIEW_0 TA/3D_PROCESSING). Those metrics are
    Sampled="n", so FUN_101c7540 evaluates them from the COUNTED stream (type 0x61): a bar opens on
    the first non-zero count and closes on the first zero count. Counted columns are indexed by the
    sampled position (e + core*8)*8 + bit (map at metric set +0x28) while FUN_101bce70 packs them by
    enabled ordinal, so ALL 256 counted channels must be enabled (header +0x34..+0x53).
    Rounds 1-3 enabled one counted bit with value 0 = column 0 = core-0 Vertex -> error 0x71a.
  * FUN_10204da0 / FUN_10202000 make one job per COMBINED bar and need a per-core bar inside it on
    all four cores (job+0x58 & 0x1f == 0x1f, FUN_101ff8e0), so every job is active on cores 0-3.
  * Bookmarks are consumed in order, one per job: Frame (TA|3D|SPM, earliest wins, SPM keeps the
    scene open), Process ID as a (low16, high16|0x02000000) pair, TAFLAGS/RENDERFLAGS, MT LLS
    (3D jobs), MASTER_VDM_BATCH_NUM (at/after the TA job end). FUN_102044a0 closes a TA scene on
    TAFLAGS bit1 (LASTKICK) and a 3D scene when RENDERFLAGS bits 13-15 are clear, then pairs TA and
    3D scenes by (frame, pid, index in frame); the first frame of every pid is dropped.
"""
from __future__ import annotations
import argparse, bisect, struct, sys

TB_HZ = 333_000_000
TICKS_PER_US = TB_HZ / 1_000_000.0          # 333
MAGIC_PMON = 0x4E4F4D50
MAGIC_PMNQ = 0x4E4F4D51

# --- bookmark channels (RAZOR_GPU_TRACE_FORMAT.md §1) -------------------------------------------
FIFO_A, FIFO_B = 0, 1
A_GPU_GENERAL = 8          # RAZOR_GPU_GENERAL  -> [ARM] CPU Frame + libgxm scene calls
B_KERNEL_GPU0 = 2          # RAZOR_KERNEL_GPU_0 -> GPU Frame/Scene/ProcessID bookmarks

# --- bookmark data words (word1) : TypeValue | payload, TypeMask from Bookmarks.xml -------------
BM_CPU_FRAME        = 0xB0BAFE77                    # [ARM] CPU Frame (sceGxmPadHeartbeat), A8, mask ffffffff
def frame_ta(frame):  return 0x10000000 | (frame & 0x00FFFFFF)   # GPU Frame (TA)   mask ff000000
def frame_3d(frame):  return 0x11000000 | (frame & 0x00FFFFFF)   # GPU Frame (3D)   mask ff000000
def frame_spm(frame): return 0x12000000 | (frame & 0x00FFFFFF)   # GPU Frame (SPM)  mask ff000000
def mt_lls(n):        return 0x14000000 | (n & 0x00FFFFFF)       # GPU MT LLS       mask ff000000
def scene_taflags(v): return 0x20000000 | (v & 0x0FFFFFFF)       # GPU Scene TAFLAGS      mask f0000000
def scene_render(v):  return 0x50000000 | (v & 0x0FFFFFFF)       # GPU Scene RENDERFLAGS  mask f0000000
def scene_vdm(v):     return 0x40000000 | (v & 0x00001FFF)       # GPU Scene MASTER_VDM_BATCH_NUM (job keeps & 0x1fff)


# GPU Process ID (TA/3D), mask fc000000: a pid is TWO bookmarks, low 16 bits first, then the high 16
# bits with payload bit 25 set (FUN_10204da0 / FUN_10202000: pid = second.word << 16 |
# (u16)first.word; a leading bookmark with bit 25 set is skipped as a stray high half).
PID_HIGH_FLAG = 0x02000000
def pid_pair(base, pid):
    return (base | (pid & 0xFFFF), base | PID_HIGH_FLAG | ((pid >> 16) & 0xFFFF))
PID_TA_BASE = 0x30000000
PID_3D_BASE = 0x34000000

# SGXMKIF_TAFLAGS: FUN_102044a0 closes a TA scene on bit1 (LASTKICK) with bit26 and bits 22-25 clear.
TAFLAGS_FIRSTKICK = 0x1
TAFLAGS_LASTKICK = 0x2
# RENDERFLAGS: bits 13/14/15 clear -> the 3D scene closes after this job (needs MT LLS, flag 0x100).
RENDERFLAGS_DEFAULT = 0x0

FRAME_SIZE = 0x80
SLOT_TYPE_BOOKMARK = 0x7f
SLOT_TYPE_SAMPLED = 0x60      # PmonPacketParserGpuSampled  (FUN_101bcd90 / flush FUN_101bcf50)
SLOT_TYPE_COUNTED = 0x61      # PmonPacketParserGpuCounted  (FUN_101bcc30 / flush FUN_101bce70)

# --- display-driver (B3) and libgxm (A8) bookmarks -------------------------------------------
# Razor builds the VSync / Display Flip / Display Service / Scene Construction event traces from
# these; when the definitions resolve but the trace holds no instances it prints
# "... Event Trace could not be created. The GPU Trace must be triggered using System Software
# 1.800 or later." (FUN_101bdfb0 looks up "sceDisplaySetFrameBuf()" / "_sceDisplayVbStartInterrupt()").
B_DISPLAY = 3                                   # RAZOR_KERNEL_GPU_1, Channels="B3"
BM_DISP_SETFRAMEBUF   = 0x10000000              # sceDisplaySetFrameBuf()            mask ff000000
BM_DISP_VBSTART_INT   = 0x11000000              # _sceDisplayVbStartInterrupt()
BM_DISP_WAITVB_BEGIN  = 0x12000000              # _sceDisplayWaitVblankStartMulti() Begin
BM_DISP_WAITVB_END    = 0x13000000              # _sceDisplayWaitVblankStartMulti() End
BM_GXM_BEGIN_SCENE    = 0x10000000              # sceGxmBeginScene()  on A8           mask ff000000
BM_GXM_END_SCENE      = 0x11000000              # sceGxmEndScene()    on A8
# "GPU Firmware Submit Events" of the Scene Construction event trace (FUN_101be9b0 ->
# FUN_101bf780 pairs Begin/End); without them Razor logs "... without GPU Firmware Submit Events.
# The GPU Trace must be triggered using System Software 2.500 or later."
BM_GXM_KICK_BEGIN     = 0x1D000000              # sceGxmKick() Begin  on A8
BM_GXM_KICK_END       = 0x1E000000              # sceGxmKick() End    on A8

# --- sampled bit map (FUN_101cc330 + register table DAT_1053d988) -----------------------------
# Header fields at +0x74/+0x84/+0x94/+0xa4 are four u32[4] (indexed by GPU core). Entry e (0..7)
# takes the low/high u16 of field e>>1 : {byte0 = register group, byte1 = first bit}. Each entry
# maps 8 consecutive register bits to sampled-stream bit positions (e + core*8)*8 + bit.
# We program the "Overview" group from metricgroups_embedded.xml:
#   TraceGroups   = 00 00 00 00 02 02 02 02   (groups 0,0,0,0,2,2,2,2)
#   TraceCounters = 00 08 10 18 00 08 10 18   (first bits)
# which is what FUN_101cb150 hashes into the metric-group signature, so Razor resolves MetricGroup 0.
ENTRY_ORDERS = {
    # exact "Overview" signature -> Razor shows "Metrics Group: M0: Overview" and selects the
    # Vertex/Fragment Processing Job Active + Firmware Active event metrics. DEFAULT.
    "overview": [(0x00, 0x00), (0x00, 0x08), (0x00, 0x10), (0x00, 0x18),
                 (0x02, 0x00), (0x02, 0x08), (0x02, 0x10), (0x02, 0x18)],
    # group 2 first (TA_PROCESSING -> position 32). TESTED: this loses the "M0: Overview" group
    # match and with it the event metrics, so it is worse; kept only for reference.
    "shifted":  [(0x02, 0x00), (0x02, 0x08), (0x02, 0x10), (0x02, 0x18),
                 (0x00, 0x00), (0x00, 0x08), (0x00, 0x10), (0x00, 0x18)],
}
N_SAMPLED_DWORDS = 8                            # 8 u32 = 256 bits = 4 cores x 64
N_COUNTED = 256                                 # counted channels: all 8 enable masks = 0xFFFFFFFF
N_GPU_CORES = 4


def sampled_positions(entries):
    """(group, registerBit) -> {core: sampled-stream bit position}, per FUN_101cc330:
    entry e covers register bits [start, start+8) of `group` at positions (e + core*8)*8 + i."""
    pos = {}
    for e, (group, start) in enumerate(entries):
        for i in range(8):
            key = (group, start + i)
            pos.setdefault(key, {})
            for core in range(4):
                pos[key][core] = (e + core * 8) * 8 + i
    return pos


# register table (pmon/regtable.txt): PERF_OVERVIEW_0_PERF_TA_PROCESSING = group 0 bit 0,
# PERF_OVERVIEW_0_PERF_3D_PROCESSING = group 0 bit 1, PERF_OVERVIEW_0_PERF_UKERNEL_RUNNING = bit 2.
REG_TA_PROCESSING = (0x00, 0)
REG_3D_PROCESSING = (0x00, 1)
REG_UKERNEL_RUNNING = (0x00, 2)                 # "Firmware Active"
KIND_REG = {"v": REG_TA_PROCESSING, "f": REG_3D_PROCESSING, "w": REG_UKERNEL_RUNNING}

S_FIELDS = ["frame", "fence", "kind", "width", "height", "draws", "indices", "open_us", "endcall_us",
            "submit_us", "done_us", "gpu_us", "queue_us", "serial_us", "path", "sections"]
F_FIELDS = ["frame", "start_us", "end_us", "scenes", "game_us", "render_us", "beginscene_us",
            "endscene_us", "flip_us", "throttle_us", "present_us", "render_stall_us",
            "engine_sleep_us", "dropped_scenes"]
INT_S = set(S_FIELDS) - {"kind", "path", "sections"}


def parse_csv(path):
    """Reuse the columns from tools/gxm_gpu_report.py."""
    scenes, frames = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            p = line.split(",")
            if p[0] == "S" and len(p) >= len(S_FIELDS) + 1:
                fixed = p[1:len(S_FIELDS) - 1]
                row = dict(zip(S_FIELDS[:-2], fixed))
                row["path"], row["sections"] = p[len(S_FIELDS) - 1], ",".join(p[len(S_FIELDS):])
                for k in INT_S:
                    row[k] = int(row[k])
                scenes.append(row)
            elif p[0] == "F" and len(p) >= len(F_FIELDS) + 1:
                frames.append({k: int(v) for k, v in zip(F_FIELDS, p[1:len(F_FIELDS) + 1])})
    return scenes, frames


class Bookmark:
    __slots__ = ("t", "fifo", "regno", "master", "word1")
    def __init__(self, t, fifo, regno, master, word1):
        self.t, self.fifo, self.regno, self.master, self.word1 = t, fifo, regno, master, word1


def us_to_ticks(us):
    return int(round(us * TICKS_PER_US))


class Slot:
    """One 16-byte trace slot plus its descriptor (descriptor = type<<8 | low byte)."""
    __slots__ = ("t", "desc", "data")
    def __init__(self, t, desc, data):
        assert len(data) == 16, len(data)
        self.t, self.desc, self.data = t, desc, data


def plan_jobs(scenes, gap_us=1):
    """One vertex (TA) + one fragment (3D) GPU job per CSV scene, in time order:
      - vertex job spans [endcall_us, submit_us]
      - fragment job spans [max(submit_us, previous fragment end + gap), done_us]
    done_us == 0 (unknown) or an empty span skips the whole scene, so TA and 3D scenes stay paired
    (FUN_102044a0 matches them by frame number + index within the frame). Consecutive jobs of the
    same kind are kept `gap_us` apart: the event bar of a job only closes on a zero-count counted
    period, and two touching jobs would merge into one bar (one job)."""
    jobs = []
    last_end = {"v": None, "f": None}
    for s in scenes:
        if s["done_us"] == 0:
            continue
        v0, v1 = s["endcall_us"], s["submit_us"]
        if last_end["v"] is not None:
            v0 = max(v0, last_end["v"] + gap_us)
        f0, f1 = s["submit_us"], s["done_us"]
        if last_end["f"] is not None:
            f0 = max(f0, last_end["f"] + gap_us)
        if v1 <= v0 or f1 <= f0:
            continue
        ix = len(jobs) // 2
        jobs.append({"kind": "v", "t0": v0, "t1": v1, "frame": s["frame"], "scene": ix,
                     "draws": s["draws"]})
        jobs.append({"kind": "f", "t0": f0, "t1": f1, "frame": s["frame"], "scene": ix,
                     "draws": s["draws"]})
        last_end["v"], last_end["f"] = v1, f1
    return jobs


def build_job_intervals(jobs, cores=N_GPU_CORES, firmware_us=20):
    """(core, kind, t0_us, t1_us) activity intervals; kind 'v' = vertex/TA, 'f' = fragment/3D,
    'w' = firmware.

    The CSV has no per-core data. Every job is shown active on all `cores` GPU cores for its whole
    span: FUN_10204da0 / FUN_10202000 only accept a job whose combined bar contains a per-core bar on
    each of the four cores (job+0x58 & 0x1f == 0x1f, else "Job has missing Timestamps").
    "Firmware Active" (UKERNEL_RUNNING) is modelled as a short pulse on core 0 at each job start."""
    out = []
    for j in jobs:
        for core in range(cores):
            out.append((core, j["kind"], j["t0"], j["t1"]))
        if firmware_us:
            out.append((0, "w", j["t0"], min(j["t1"], j["t0"] + firmware_us)))
    return out


def build_counted_packet(t_us, values):
    """One type-0x61 counted packet carrying all N_COUNTED (256) channel values.

    FUN_101bcc30 (PmonPacketParserGpuCounted::AddWord), record = u16 descriptor + 16-byte slot:
      first slot (descriptor low byte 0): [0:4] time_low32, [4:6] time_high16, [6:16] values 0-4
      continuation slots (low byte != 0): [0:16] 8 more values each, until popcount values are in
    -> 256 values = 1 + 32 slots. FUN_101ce170 counts only low-byte-0 slots, so the counted sample
    count (the metric result timeline) is one per packet. FUN_101bce70 stores value n in counted
    column n; FUN_101c7540 reads column = sampled position (e + core*8)*8 + bit (map at metric set
    +0x28), so channel n here is exactly sampled position n.
    Each value is the number of sample-period cycles the register bit was set in the period that
    ends at this packet's time (FUN_101c7540 opens an event bar on the first non-zero count)."""
    assert len(values) == N_COUNTED
    tk = us_to_ticks(t_us)
    lo, hi = tk & 0xFFFFFFFF, (tk >> 32) & 0xFFFF
    vals = [v & 0xFFFF for v in values]
    base = SLOT_TYPE_COUNTED << 8
    slots = [Slot(tk, base | 0, struct.pack("<IH5H", lo, hi, *vals[0:5]))]
    k, i = 1, 5
    while i < N_COUNTED:
        chunk = vals[i:i + 8]
        chunk += [0] * (8 - len(chunk))
        slots.append(Slot(tk, base | k, struct.pack("<8H", *chunk)))
        k += 1
        i += 8
    return slots


def counted_values(intervals, positions, times, period):
    """Per sample time t_i: 256 counted values; channel p = cycles (out of `period`) that position p
    was active in (t_{i-1}, t_i]. Sample 0 covers nothing and is all-zero."""
    out = [[0] * N_COUNTED for _ in times]
    for core, kind, a, b in intervals:
        p = positions[KIND_REG[kind]][core]
        i = max(1, bisect.bisect_right(times, a))   # first period (t_{i-1}, t_i] with t_i > a
        while i < len(times) and times[i - 1] < b:
            lo, hi = max(a, times[i - 1]), min(b, times[i])
            span = times[i] - times[i - 1]
            if hi > lo and span > 0:
                v = out[i][p] + max(1, int(round(period * (hi - lo) / span)))
                out[i][p] = min(v, period, 0xFFFF)
            i += 1
    return out


def build_sample_groups(intervals, positions, period):
    """Per sample instant, one group of slots (kept contiguous): a type-0x60 sampled packet carrying
    PERF_OVERVIEW_0 TA_PROCESSING / 3D_PROCESSING / UKERNEL_RUNNING as a sample-and-hold bit per GPU
    core, followed by a type-0x61 counted packet with the activity counts of the period ending at
    that instant. The event metrics "Vertex/Fragment Processing Job Active" and "Firmware Active"
    are Sampled="n", i.e. FUN_101c7540 evaluates them from the counted packets (a Sampled="y"
    operand in an event metric is rejected: "Sampled data operand in event metric").

    Sampled packet = 8 u32 delivered over 3 slots (FUN_101bcd90):
      slot0 (desc low byte 0): [0:4] time_low32, [4:6] time_high16, [6:8] pad, [8:16]  dwords 0,1
      slot1 (desc low byte 1): [0:16] dwords 2,3,4,5
      slot2 (desc low byte 2): [0:8]  dwords 6,7 (parser stops at 8 values)
    Samples are emitted at every activity change point plus each interval midpoint, so every job
    spans at least two non-zero counted periods and every gap at least one zero period."""
    times = set()
    for _c, _k, t0, t1 in intervals:
        times.add(t0); times.add(t1); times.add((t0 + t1) // 2)
    if not times:
        return []
    last = max(times)
    times.add(last + 1)                      # trailing all-idle sample closes the last interval
    times = sorted(times)
    counted = counted_values(intervals, positions, times, period)
    # sample-and-hold bit per instant (half-open [t0, t1)), via a sweep over sorted edges
    edges = []
    for core, kind, t0, t1 in intervals:
        bit = positions[KIND_REG[kind]][core]
        edges.append((t0, 1, bit))
        edges.append((t1, -1, bit))
    edges.sort()
    active = [0] * N_COUNTED
    ei = 0
    groups = []
    base = SLOT_TYPE_SAMPLED << 8
    for n, t_us in enumerate(times):
        while ei < len(edges) and edges[ei][0] <= t_us:
            active[edges[ei][2]] += edges[ei][1]
            ei += 1
        words = [0] * N_SAMPLED_DWORDS
        for bit, cnt in enumerate(active):
            if cnt > 0:
                words[bit >> 5] |= 1 << (bit & 31)
        tk = us_to_ticks(t_us)
        lo, hi = tk & 0xFFFFFFFF, (tk >> 32) & 0xFFFF
        s0 = struct.pack("<IHH", lo, hi, 0) + struct.pack("<II", words[0], words[1])
        s1 = struct.pack("<IIII", words[2], words[3], words[4], words[5])
        s2 = struct.pack("<II", words[6], words[7]) + b"\x00" * 8
        group = [Slot(tk, base | 0, s0), Slot(tk, base | 1, s1), Slot(tk, base | 2, s2)]
        # counted packet at the same instant: FUN_101cddf0 truncates the counted and sampled sample
        # counts to the smaller one, and the counted count is the metric result timeline.
        group += build_counted_packet(t_us, counted[n])
        groups.append(group)
    return groups


def build_bookmarks(jobs, scenes, frames, pid):
    """GPU bookmarks, one set per job (FUN_10204da0 / FUN_10202000 consume them in order, one per
    job, each at or before the job's bar end):
      vertex job   @t0: Frame (TA), Process ID (TA) low+high, Scene TAFLAGS (FIRSTKICK|LASTKICK)
                   @t1: Scene MASTER_VDM_BATCH_NUM (must lie in [bar end, next bar start])
      fragment job @t0: MT LLS (1), Frame (3D), Process ID (3D) low+high, Scene RENDERFLAGS (0)
    No GPU Frame (SPM): SPM frames win over 3D ones and keep the 3D scene open (job+0x74)."""
    bms = []
    A, B = FIFO_A, FIFO_B
    for j in jobs:
        t0, t1 = us_to_ticks(j["t0"]), us_to_ticks(j["t1"])
        fr = j["frame"]
        if j["kind"] == "v":
            bms.append(Bookmark(t0, B, B_KERNEL_GPU0, 0, frame_ta(fr)))
            for w in pid_pair(PID_TA_BASE, pid):
                bms.append(Bookmark(t0, B, B_KERNEL_GPU0, 0, w))
            bms.append(Bookmark(t0, B, B_KERNEL_GPU0, 0,
                                scene_taflags(TAFLAGS_FIRSTKICK | TAFLAGS_LASTKICK)))
            bms.append(Bookmark(t1, B, B_KERNEL_GPU0, 0, scene_vdm(j["draws"])))
        else:
            bms.append(Bookmark(t0, B, B_KERNEL_GPU0, 0, mt_lls(1)))
            bms.append(Bookmark(t0, B, B_KERNEL_GPU0, 0, frame_3d(fr)))
            for w in pid_pair(PID_3D_BASE, pid):
                bms.append(Bookmark(t0, B, B_KERNEL_GPU0, 0, w))
            bms.append(Bookmark(t0, B, B_KERNEL_GPU0, 0, scene_render(RENDERFLAGS_DEFAULT)))
    # ---- libgxm scene + kick bookmarks on A8 (feed the Scene Construction event trace) ----
    for s in scenes:
        if s["done_us"] == 0:
            continue
        bms.append(Bookmark(us_to_ticks(s["open_us"]), A, A_GPU_GENERAL, 0, BM_GXM_BEGIN_SCENE))
        bms.append(Bookmark(us_to_ticks(s["endcall_us"]), A, A_GPU_GENERAL, 0, BM_GXM_END_SCENE))
        # firmware submit (kick) = the EndScene -> submit window of the CSV
        if s["submit_us"] > s["endcall_us"]:
            bms.append(Bookmark(us_to_ticks(s["endcall_us"]), A, A_GPU_GENERAL, 0, BM_GXM_KICK_BEGIN))
            bms.append(Bookmark(us_to_ticks(s["submit_us"]), A, A_GPU_GENERAL, 0, BM_GXM_KICK_END))
    # ---- one CPU Frame bookmark per F line, at end_us, on A8 (regno 8) ----
    # plus display-driver bookmarks on B3 so the VSync / Display Flip / Display Service event
    # traces can be built (otherwise Razor reports "...System Software 1.800 or later").
    for fdef in frames:
        t_end = us_to_ticks(fdef["end_us"])
        bms.append(Bookmark(t_end, A, A_GPU_GENERAL, 0, BM_CPU_FRAME))
        bms.append(Bookmark(t_end, B, B_DISPLAY, 0, BM_DISP_SETFRAMEBUF))
        bms.append(Bookmark(t_end, B, B_DISPLAY, 0, BM_DISP_VBSTART_INT))
        bms.append(Bookmark(us_to_ticks(fdef["end_us"] - 1), B, B_DISPLAY, 0, BM_DISP_WAITVB_BEGIN))
        bms.append(Bookmark(t_end, B, B_DISPLAY, 0, BM_DISP_WAITVB_END))
    bms.sort(key=lambda b: b.t)              # stable: a pid's low half stays before its high half
    return bms


def encode_bookmark_slot(bm: Bookmark) -> bytes:
    lo = bm.t & 0xFFFFFFFF
    hi = (bm.t >> 32) & 0xFFFF
    bmdesc = ((bm.fifo & 1) << 12) | ((bm.regno & 0xF) << 8) | (bm.master & 0x3F)
    return struct.pack("<IHHHHI", lo, hi, 0, 0, bmdesc, bm.word1 & 0xFFFFFFFF)


def pack_frames(slots):
    """Pack Slot records 7 per 0x80 frame: u16 pad(0) + 7 descriptors + 7 x 16-byte slots
    (the container FUN_101cec80 reads as 8 x 16-byte records; record 0 holds the descriptors)."""
    out = bytearray()
    for i in range(0, len(slots), 7):
        group = slots[i:i + 7]
        desc = [0] * 7
        body = [b"\x00" * 16] * 7
        for j, sl in enumerate(group):
            desc[j] = sl.desc & 0xFFFF
            body[j] = sl.data
        frame = struct.pack("<H", 0) + struct.pack("<7H", *desc) + b"".join(body)
        assert len(frame) == FRAME_SIZE, len(frame)
        out += frame
    return bytes(out)


def interleave(bm_slots, groups):
    """Merge by time, keeping each sample group's slots adjacent (the 0x60/0x61 parsers key a new
    packet on descriptor low byte 0, so a packet's slots must stay in order)."""
    merged = []
    bi, gi = 0, 0
    while bi < len(bm_slots) or gi < len(groups):
        take_b = bi < len(bm_slots) and (gi >= len(groups) or bm_slots[bi].t <= groups[gi][0].t)
        if take_b:
            merged.append(bm_slots[bi]); bi += 1
        else:
            merged.extend(groups[gi]); gi += 1
    return merged


def build_pmon(scenes, frames, pid, version, period=1000, entry_order="overview",
               cores=N_GPU_CORES, firmware_us=20, gap_us=1):
    jobs = plan_jobs(scenes, gap_us=gap_us)
    bms = build_bookmarks(jobs, scenes, frames, pid)
    bm_slots = [Slot(b.t, (SLOT_TYPE_BOOKMARK << 8) | ((b.fifo << 4 | b.regno) & 0xFF),
                     encode_bookmark_slot(b)) for b in bms]
    entries = ENTRY_ORDERS[entry_order]
    positions = sampled_positions(entries)
    intervals = build_job_intervals(jobs, cores=cores, firmware_us=firmware_us)
    groups = build_sample_groups(intervals, positions, period)
    body = pack_frames(interleave(bm_slots, groups))
    data_start = 0xF0
    data_end = data_start + len(body)

    hdr = bytearray(0xE0)
    struct.pack_into("<I", hdr, 0x00, MAGIC_PMON)
    struct.pack_into("<I", hdr, 0x0C, version)      # obj+0x418 read as u32; minor u16 at +0x0E is
                                                    # its high half (version 0x10002 => +0xe = 0x0001)
    struct.pack_into("<I", hdr, 0x10, 0)            # flags (bit3 -> use +0x24 as length; we use start/end)
    struct.pack_into("<I", hdr, 0x14, data_end)     # obj+0x420 data end offset
    struct.pack_into("<I", hdr, 0x20, data_start)   # obj+0x42c data start offset
    struct.pack_into("<H", hdr, 0x30, period)       # obj+0x43c sampled period (cycles)
    struct.pack_into("<H", hdr, 0x32, period)       # obj+0x43e counted period (equal -> no warning)
    # counted enable masks obj+0x440..0x45f (header +0x34..+0x53): ALL 256 channels. FUN_101ce3e0
    # popcount = values per packet = number of counted columns (FUN_101ce4a0); the evaluator indexes
    # columns by sampled position, so every bit must be on (see build_counted_packet).
    for k in range(8):
        struct.pack_into("<I", hdr, 0x34 + 4 * k, 0xFFFFFFFF)
    # sampled selection: four u32[4] at +0x74/+0x84/+0x94/+0xa4, indexed by GPU core (FUN_101cc330)
    for k in range(4):
        e_lo = entries[2 * k]
        e_hi = entries[2 * k + 1]
        half_lo = (e_lo[0] & 0xFF) | ((e_lo[1] & 0xFF) << 8)
        half_hi = (e_hi[0] & 0xFF) | ((e_hi[1] & 0xFF) << 8)
        val = half_lo | (half_hi << 16)
        for core in range(4):
            struct.pack_into("<I", hdr, 0x74 + 0x10 * k + 4 * core, val)

    pmnq = bytearray(0x10)
    struct.pack_into("<I", pmnq, 0x00, MAGIC_PMNQ)

    blob = bytes(hdr) + bytes(pmnq) + body
    return blob, bms, jobs, len(groups)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("out")
    ap.add_argument("--pid", type=lambda x: int(x, 0), default=0x40010003)
    ap.add_argument("--version", type=lambda x: int(x, 0), default=0x10002)
    ap.add_argument("--entry-order", choices=sorted(ENTRY_ORDERS), default="overview")
    ap.add_argument("--cores", type=int, default=N_GPU_CORES,
                    help="GPU cores each job is active on (Razor needs all 4 for job rows)")
    ap.add_argument("--firmware-us", type=int, default=20,
                    help="Firmware Active pulse at the start of each job (0 = none)")
    ap.add_argument("--first-frame", type=int, default=0,
                    help="leave out CSV frames before this one (the plugin keeps the last N frames)")
    a = ap.parse_args(argv)
    scenes, frames = parse_csv(a.csv)
    scenes = [s for s in scenes if s["frame"] >= a.first_frame]
    frames = [f for f in frames if f["frame"] >= a.first_frame]
    blob, bms, jobs, nsamp = build_pmon(scenes, frames, a.pid, a.version,
                                       entry_order=a.entry_order, cores=a.cores,
                                       firmware_us=a.firmware_us)
    with open(a.out, "wb") as f:
        f.write(blob)
    nv = sum(1 for j in jobs if j["kind"] == "v")
    nf = sum(1 for j in jobs if j["kind"] == "f")
    print("scenes=%d frames=%d bookmarks=%d jobs=%d(v=%d f=%d) samples=%d bytes=%d version=0x%x "
          "pid=0x%x order=%s -> %s" % (len(scenes), len(frames), len(bms), len(jobs), nv, nf,
                              nsamp, len(blob), a.version, a.pid, a.entry_order, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
