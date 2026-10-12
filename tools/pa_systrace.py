"""Synthesize the kernel "system trace" bookmarks PSP2Razor.dll turns into thread scheduling
(context switch), thread priority change and syscall events.

Format: RAZOR_SYSTRACE_FORMAT.md (decoded from PSP2Razor.dll 3.60.0.5, image base 0x10000000).

  channel   FIFO B, regno 6 (SYS_0), master = CPU + 1 (1..4)      CPMonParser ctor FUN_1020fe20(buf, 1, 6)
  packet    words carried in the data word of consecutive bookmarks of the same master;
            header = type << 24 | total_length_bytes << 16 | b1 << 8 | b0   FUN_102298b0
            packet time = time of the header bookmark
  type 1    [hdr(b1=new prio, b0=old prio), pid, tid]            priority change   FUN_10229420
  type 2    [hdr(b1=priority, b0=start code), pid, tid]          switch in         FUN_10229420
  type 3    [hdr(b0=outgoing thread status), pid, tid]           switch out        FUN_10229420
  type 4    [hdr, ~(nid - 0xE9D4F638), call id, a0, a1, a2, a3]  syscall enter     FUN_10229570
  type 5    [hdr, call id, ret, aux]                              syscall exit      FUN_10229570

Output of every emitter: a list of (fifo, regno, master, time48, data) tuples. Frame packing
(0x7c/0x7d/0x7e slots, the 21-bit time window) is someone else's job, see pa_frames.py.

Ordering contract for the frame packer: keep each master's bookmarks in list order. The
SysTraceWriter makes per-CPU times strictly increasing, so any sort by time (stable or not)
preserves that order.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

Bookmark = Tuple[int, int, int, int, int]      # (fifo, regno, master, time48, data)

FIFO_A, FIFO_B = 0, 1
REGNO_SYS0 = 6                                  # ePABookmarkBChannels SYS_0
TIMEBASE_HZ = 333_000_000                       # CPSP2Target::ConfigurePerfmon insists on 333 MHz
TICKS_PER_MS = TIMEBASE_HZ // 1000
MASK32 = 0xFFFFFFFF
MASK48 = 0xFFFFFFFFFFFF

PKT_PRIORITY_CHANGE = 1
PKT_SWITCH_IN = 2
PKT_SWITCH_OUT = 3
PKT_SYSCALL_ENTER = 4
PKT_SYSCALL_EXIT = 5
PKT_WORDS = {PKT_PRIORITY_CHANGE: 3, PKT_SWITCH_IN: 3, PKT_SWITCH_OUT: 3,
             PKT_SYSCALL_ENTER: 7, PKT_SYSCALL_EXIT: 4}

# Switch-out status byte (b0 of a type 3 header) -> StopThreadIncidentId (FUN_10229420).
# Values are SceThreadStatus bits of the outgoing thread (interpretation, not proven).
SCE_THREAD_READY = 0x02                         # -> incident 1 (preempted / still runnable)
SCE_THREAD_STANDBY = 0x04                       # -> incident 4
SCE_THREAD_WAITING = 0x08                       # -> incident 0xff (any other value too)
STOP_INCIDENT = {SCE_THREAD_READY: 1, SCE_THREAD_STANDBY: 4}

KERNEL_PID = 0x10005                            # CPSP2Target::GetProcessNameInfo names it "Kernel"
NID_KEY = 0xE9D4F638                            # GetSyscallTracePacket: NID = ~w1 + NID_KEY

# NIDs present in PSP2Razor.dll's embedded syscall table (0x10678208.., 0x40-byte entries whose
# first dword is the encoded NID and whose name is "syscall_0x%08x"); an unknown NID makes
# GetSyscallTracePacket fail and ends the syscall pass.
KNOWN_SYSCALL_NIDS = (0xED180B4A, 0xE6306EC6, 0xD90FC9A2, 0xD5993161)
# Syscalls Razor drops on purpose (table 0x1065baf0 copied to CPSP2SysTraceParser in FUN_10229230).
FILTERED_SYSCALL_NIDS = {0x2682E6ED: "_sceKernelExitCallback",
                         0xE53E41F6: "sceKernelCheckCallback",
                         0xA4683592: "sceKernelNotifyCallback"}


# ----------------------------------------------------------------------------------------------
# word level

def encode_nid(nid: int) -> int:
    """Syscall NID -> packet word 1 of a type 4 packet."""
    return (~((nid - NID_KEY) & MASK32)) & MASK32


def decode_nid(word: int) -> int:
    return ((~word & MASK32) + NID_KEY) & MASK32


def header_word(ptype: int, b1: int = 0, b0: int = 0) -> int:
    return (ptype << 24) | ((PKT_WORDS[ptype] * 4) << 16) | ((b1 & 0xFF) << 8) | (b0 & 0xFF)


def switch_in_words(pid: int, tid: int, priority: int, start_code: int = 0) -> List[int]:
    return [header_word(PKT_SWITCH_IN, priority, start_code), pid & MASK32, tid & MASK32]


def switch_out_words(pid: int, tid: int, status: int = SCE_THREAD_READY) -> List[int]:
    return [header_word(PKT_SWITCH_OUT, 0, status), pid & MASK32, tid & MASK32]


def priority_change_words(pid: int, tid: int, new_priority: int, old_priority: int) -> List[int]:
    return [header_word(PKT_PRIORITY_CHANGE, new_priority, old_priority), pid & MASK32, tid & MASK32]


def syscall_enter_words(nid: int, call_id: int, args: Sequence[int] = ()) -> List[int]:
    a = [x & MASK32 for x in args][:4]
    a += [0] * (4 - len(a))
    return [header_word(PKT_SYSCALL_ENTER), encode_nid(nid), call_id & MASK32] + a


def syscall_exit_words(call_id: int, ret: int, aux: int = 0) -> List[int]:
    return [header_word(PKT_SYSCALL_EXIT), call_id & MASK32, ret & MASK32, aux & MASK32]


def packet_bookmarks(cpu: int, time48: int, words: Sequence[int]) -> List[Bookmark]:
    """One packet -> bookmarks on FIFO B / SYS_0, one tick apart (only the header time is used)."""
    if not 0 <= cpu <= 3:
        raise ValueError("cpu must be 0..3 (master 1..4); other masters on SYS_0 end Razor's parse")
    return [(FIFO_B, REGNO_SYS0, cpu + 1, (time48 + i) & MASK48, w & MASK32) for i, w in enumerate(words)]


def bookmark_u32_pair(bm: Bookmark) -> Tuple[int, int]:
    """(word0, data) as stored in a 0x7c/0x7d slot; the upper 27 time bits come from a 0x7e slot."""
    fifo, regno, master, t, data = bm
    return ((fifo & 1) << 31) | ((regno & 0xF) << 27) | ((master & 0x3F) << 21) | (t & 0x1FFFFF), data


# ----------------------------------------------------------------------------------------------
# stream level

class SysTraceWriter:
    """Accumulates SYS_0 bookmarks. Keeps per-CPU times strictly increasing (a packet asked for at
    an already used time is shifted by a few ticks) and remembers who runs where."""

    def __init__(self) -> None:
        self.bookmarks: List[Bookmark] = []
        self._last: Dict[int, int] = {}
        self.running: Dict[int, Tuple[int, int]] = {}         # cpu -> (pid, tid)
        self._call_ids: Dict[Tuple[int, int], List[int]] = {}   # (pid, tid) -> open call ids
        self._next_call_id = 1

    def _emit(self, cpu: int, t: int, words: Sequence[int]) -> int:
        t0 = max(int(t), self._last.get(cpu, -1) + 1)
        bms = packet_bookmarks(cpu, t0, words)
        self.bookmarks.extend(bms)
        self._last[cpu] = bms[-1][3]
        return t0

    def switch_in(self, cpu: int, t: int, pid: int, tid: int, priority: int = 160, start_code: int = 0) -> int:
        if cpu in self.running:
            raise ValueError("cpu %d already runs %r; switch it out first" % (cpu, self.running[cpu]))
        self.running[cpu] = (pid, tid)
        return self._emit(cpu, t, switch_in_words(pid, tid, priority, start_code))

    def switch_out(self, cpu: int, t: int, status: int = SCE_THREAD_READY) -> int:
        pid, tid = self.running.pop(cpu)
        return self._emit(cpu, t, switch_out_words(pid, tid, status))

    def context_switch(self, cpu: int, t: int, pid: int, tid: int, priority: int = 160,
                       out_status: int = SCE_THREAD_READY) -> int:
        """Switch out whoever runs on `cpu` (if anyone), then switch in (pid, tid)."""
        if cpu in self.running:
            self.switch_out(cpu, t, out_status)
        return self.switch_in(cpu, t, pid, tid, priority)

    def priority_change(self, cpu: int, t: int, pid: int, tid: int, new_priority: int, old_priority: int) -> int:
        return self._emit(cpu, t, priority_change_words(pid, tid, new_priority, old_priority))

    def syscall_enter(self, cpu: int, t: int, nid: int, args: Sequence[int] = (), call_id: Optional[int] = None) -> int:
        """Must lie inside the on-CPU interval of the calling thread (Razor looks the thread up by
        cpu/time). Returns the call id to pass to syscall_exit."""
        if cpu not in self.running:
            raise ValueError("no thread running on cpu %d" % cpu)
        if call_id is None:
            call_id, self._next_call_id = self._next_call_id, self._next_call_id + 1
        self._call_ids.setdefault(self.running[cpu], []).append(call_id)
        self._emit(cpu, t, syscall_enter_words(nid, call_id, args))
        return call_id

    def syscall_exit(self, cpu: int, t: int, ret: int = 0, aux: int = 0, call_id: Optional[int] = None) -> int:
        ids = self._call_ids.get(self.running.get(cpu), [])
        if call_id is None:
            call_id = ids.pop() if ids else 0
        elif call_id in ids:
            ids.remove(call_id)
        return self._emit(cpu, t, syscall_exit_words(call_id, ret, aux))

    def close_all(self, t_end: int, status: int = SCE_THREAD_READY) -> None:
        """Switch out every running thread at the end of the capture. Razor's capture end
        (CPSP2ProcessRawTraceData+0x210) is the latest switch-out; user markers after it are dropped."""
        for cpu in sorted(self.running):
            self.switch_out(cpu, t_end, status)

    def sorted_bookmarks(self) -> List[Bookmark]:
        return sorted(self.bookmarks, key=lambda b: b[3])


def schedule_bookmarks(slices: Iterable[Tuple[int, int, int, int, int, int]]) -> List[Bookmark]:
    """slices: (cpu, pid, tid, priority, t_start, t_end). Non-overlapping per CPU."""
    w = SysTraceWriter()
    events = []
    for cpu, pid, tid, prio, t0, t1 in slices:
        events.append((t0, 1, cpu, pid, tid, prio))
        events.append((t1, 0, cpu, pid, tid, prio))            # out before in at equal times
    for t, is_in, cpu, pid, tid, prio in sorted(events):
        if is_in:
            w.switch_in(cpu, t, pid, tid, prio)
        else:
            w.switch_out(cpu, t)
    return w.bookmarks


# ----------------------------------------------------------------------------------------------
# reference decoder (mirror of Razor, for self-checks)

def razor_packets(bookmarks: Iterable[Bookmark]):
    """FUN_10210070 + FUN_102298b0: yields (time48, cpu, [words]) in completion order."""
    state = {}                                             # cpu -> [remaining, time, words]
    for fifo, regno, master, t, data in bookmarks:
        if fifo != FIFO_B or regno != REGNO_SYS0:
            continue
        cpu = ((master & 0x3F) - 1) & 0xFF
        if cpu > 3:
            raise ValueError("SYS_0 bookmark with master %d: Razor stops the whole system trace here" % master)
        st = state.setdefault(cpu, [0, 0, []])
        if st[0] == 0:
            typ, ln = data >> 24, (data >> 16) & 0xFF
            if typ in (1, 2, 3, 4, 5) and ln & 3 == 0 and (typ not in (2, 3) or ln == 0x0C) and ln > 4:
                st[:] = [ln - 4, t, [data]]
            continue                                       # invalid header words are dropped
        st[2].append(data)
        st[0] -= 4
        if st[0] == 0:
            yield st[1], cpu, list(st[2])


def razor_decode(bookmarks: Iterable[Bookmark], t_origin: Optional[int] = None) -> dict:
    """FUN_10229420 + FUN_1021a080 (scheduler) and FUN_10229570 + FUN_1021ad20 (syscalls).
    Times are relative to t_origin (Razor: the first 0x7e slot's timestamp)."""
    bms = list(bookmarks)
    if t_origin is None:
        t_origin = min((b[3] for b in bms), default=0)
    pkts = [((t - t_origin) & 0xFFFFFFFFFFFFFFFF, cpu, ws) for t, cpu, ws in razor_packets(bms)]
    nodes, intervals, prio, warn = {}, [], [], []
    missing = missing_start = 0
    max_end = 0
    for t, cpu, ws in pkts:
        typ, ln = ws[0] >> 24, (ws[0] >> 16) & 0xFF
        if typ not in (1, 2, 3) or ln != 0x0C:
            continue
        b0, b1, pid, tid = ws[0] & 0xFF, (ws[0] >> 8) & 0xFF, ws[1], ws[2]
        key = (pid, tid)
        if typ == 2:
            if key in nodes and nodes[key]["start"] is not None:
                missing += 1
            nodes[key] = dict(start=t, cpu=cpu, priority=b1, start_code=b0)
        elif typ == 3:
            n = nodes.get(key)
            if n is None:
                continue
            if n["start"] is None:
                missing_start += 1
                continue
            intervals.append(dict(cpu=cpu, pid=pid, tid=tid, start=n["start"], end=t,
                                  stop_incident=STOP_INCIDENT.get(b0, 0xFF),
                                  priority=n["priority"], start_code=n["start_code"]))
            max_end = max(max_end, t)
            n["start"] = None
        else:
            prio.append(dict(time=t, pid=pid, tid=tid, new_priority=b1, old_priority=b0))
    for key, n in nodes.items():
        if n["start"] is not None and n["start"] < max_end:
            intervals.append(dict(cpu=n["cpu"], pid=key[0], tid=key[1], start=n["start"], end=max_end,
                                  stop_incident=0xFF, priority=n["priority"], start_code=n["start_code"]))
    if missing:
        warn.append("Scheduler trace missing %u events!" % missing)
    if missing_start:
        warn.append("Scheduler trace missing %u start events!" % missing_start)
    if not intervals:
        warn.append("ProcessSchedulerTrace: no intervals -> Razor aborts CPU trace processing")

    per_cpu = {}
    for iv in intervals:
        per_cpu.setdefault(iv["cpu"], []).append(iv)

    def thread_at(cpu, t):
        for iv in per_cpu.get(cpu, []):
            if iv["start"] <= t <= iv["end"]:
                return iv["pid"], iv["tid"]
        return None

    calls, open_calls = [], {}
    for t, cpu, ws in pkts:
        typ, ln = ws[0] >> 24, (ws[0] >> 16) & 0xFF
        if not ((typ == 4 and ln == 0x1C) or (typ == 5 and ln == 0x10)):
            continue
        who = thread_at(cpu, t)
        if who is None:
            continue
        if typ == 4:
            nid = decode_nid(ws[1])
            if nid in FILTERED_SYSCALL_NIDS:
                continue
            if who in open_calls:
                warn.append("Syscall trace missing event (nested enter) on %r" % (who,))
            open_calls[who] = dict(nid=nid, call_id=ws[2], args=ws[3:7], enter=t, enter_cpu=cpu)
        else:
            c = open_calls.pop(who, None)
            if c is not None:
                calls.append(dict(c, exit=t, exit_cpu=cpu, ret=ws[2], aux=ws[3], pid=who[0], tid=who[1]))
    return dict(intervals=intervals, priority_changes=prio, syscalls=calls, max_end=max_end, warnings=warn)


# ----------------------------------------------------------------------------------------------
# example

EXAMPLE_PID = 0x40010003
EXAMPLE_TID_A = 0x40010005
EXAMPLE_TID_B = 0x40010007
EXAMPLE_T0 = 0x00000C1F0000                     # arbitrary 48-bit start; crosses a 21-bit window


def example_two_threads(t0: int = EXAMPLE_T0) -> SysTraceWriter:
    """Threads A (prio 160) and B (prio 128) of one process alternate on CPU 0 in 2 ms slices
    for 10 ms: A, B, A, B, A; everything switched out at t0 + 10 ms."""
    w = SysTraceWriter()
    ms = TICKS_PER_MS
    for i in range(5):
        tid, prio = (EXAMPLE_TID_A, 160) if i % 2 == 0 else (EXAMPLE_TID_B, 128)
        w.context_switch(0, t0 + i * 2 * ms, EXAMPLE_PID, tid, prio)
    w.close_all(t0 + 10 * ms)
    return w


def _dump(bms: Sequence[Bookmark]) -> None:
    print("  #  fifo regno master      time48       data      | word0      word1")
    for i, b in enumerate(bms):
        w0, w1 = bookmark_u32_pair(b)
        print("%3d  %4s %5d %6d  0x%012X  0x%08X | 0x%08X 0x%08X" %
              (i, "AB"[b[0]], b[1], b[2], b[3], b[4], w0, w1))


if __name__ == "__main__":
    ex = example_two_threads()
    bms = ex.sorted_bookmarks()
    _dump(bms)
    res = razor_decode(bms)
    for iv in res["intervals"]:
        print("interval cpu%d tid=0x%08X  %8.3f ms .. %8.3f ms  prio=%d stop=%d" %
              (iv["cpu"], iv["tid"], iv["start"] / TICKS_PER_MS, iv["end"] / TICKS_PER_MS,
               iv["priority"], iv["stop_incident"]))
    assert len(res["intervals"]) == 5 and not res["warnings"], res

    # syscalls: enter/exit inside thread A's first slice
    w = SysTraceWriter()
    w.switch_in(1, 1000, EXAMPLE_PID, EXAMPLE_TID_A, 160)
    cid = w.syscall_enter(1, 2000, KNOWN_SYSCALL_NIDS[0], (1, 2, 3, 4))
    w.syscall_exit(1, 3000, ret=0x80020001, call_id=cid)
    w.priority_change(1, 3500, EXAMPLE_PID, EXAMPLE_TID_A, 100, 160)
    w.close_all(5000)
    r2 = razor_decode(w.sorted_bookmarks(), t_origin=0)
    assert len(r2["syscalls"]) == 1 and r2["syscalls"][0]["nid"] == KNOWN_SYSCALL_NIDS[0], r2
    assert r2["priority_changes"][0]["new_priority"] == 100, r2
    assert encode_nid(0xE6306EC6) == 0x03A48771 and encode_nid(0xED180B4A) == 0xFCBCEAED

    try:                                                   # optional round trip through the packer
        import pa_frames
        raw = pa_frames.pack([pa_frames.Bookmark(*b) for b in bms])
        back = list(pa_frames.iter_bookmarks(raw))
        assert razor_decode(back)["intervals"] == res["intervals"]
        print("round trip through pa_frames ok (%d frames)" % (len(raw) // pa_frames.FRAME_SIZE))
    except ImportError:
        pass
    print("pa_systrace self-test ok")
