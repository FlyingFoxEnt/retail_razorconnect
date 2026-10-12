# Razor CPU trace: the kernel system trace (scheduler, priority, syscall packets)

How PSP2Razor.dll (3.60.0.5, image base 0x10000000) turns PA bookmarks into thread on-CPU
intervals, priority changes and syscall bars. This builds on `RAZOR_PA_TRACE_FORMAT.md` (frames,
slots, 64-bit bookmark layout). Generator and reference decoder: `tools/pa_systrace.py`.

Every claim cites the function it comes from. "Interpretation" marks the few things that are
names or meanings rather than decoded behaviour.

## 0. Summary

- **Channel:** FIFO B, regno 6 (`SYS_0`). The master is the CPU + 1 (1..4). No other SYS channel
  is read by this DLL.
- **Packets:** a packet is a run of data words from consecutive SYS_0 bookmarks with the same
  master. The header word is `type << 24 | length_in_bytes << 16 | b1 << 8 | b0`. The packet time
  is the time of the header bookmark.
- **Packet types:**

  | type | words | meaning | layout |
  |---|---|---|---|
  | 1 | 3 | priority change | `hdr(b1=new, b0=old), pid, tid` |
  | 2 | 3 | switch in (thread starts running on this CPU) | `hdr(b1=priority, b0=start code), pid, tid` |
  | 3 | 3 | switch out | `hdr(b0=outgoing thread status), pid, tid` |
  | 4 | 7 | syscall enter | `hdr, ~(NID - 0xE9D4F638), call id, arg0, arg1, arg2, arg3` |
  | 5 | 4 | syscall exit | `hdr, call id, return value, aux` |

- **Scheduler trace is mandatory.** If it yields no complete switch-in/switch-out interval,
  `ProcessSchedulerTrace` fails and Razor aborts all CPU-trace processing.
- **Capture end.** The latest switch-out time becomes the capture end. User markers after it are
  dropped. Other bookmarks are attributed to a thread only if they fall inside an interval that a
  switch-out closed on the same CPU.
- **Names are not in the trace.** Thread and process names come from Target Manager
  (`CPSP2Target::GetProcessNameInfo`), keyed by the same pid and tid. The kernel is pid 0x10005.

## 1. Call graph

`FUN_10228e10` (snapshot import) builds `CPSP2ProcessRawTraceData` (ctor `FUN_102144a0`). It
copies the snapshot's process/thread maps into it (`FUN_10219d30`), sets `+0x1f8` = target pid,
then runs these steps in order. All of them must return true:

```
FUN_102190c0(0, buf)   ProcessMainTraceBuffer mode 0: scheduler      -> FUN_1021a080
FUN_102190c0(1, buf)   ProcessMainTraceBuffer mode 1: syscalls       -> FUN_1021ad20
FUN_102190c0(5, buf)   PFT PC samples                                -> FUN_10219450
FUN_10219300(1, buf)   ProcessMainTraceBufferUser (markers)
FUN_10219300(2, buf)
FUN_10218fa0(buf)      ProcessFiberTrace (FIFO A regno 15)
```

Modes 0 and 1 build the same reader stack on the stack of `FUN_102190c0` (disassembly
0x10219261..0x102192a8):

```
CPSP2SysTracePMonParser pmon  = FUN_10229850(buf)       vftable 0x1057bf50
    -> base CPMonParser ctor FUN_1020fe20(buf, fifo=1, regno=6)
CPSP2SysTraceParser     sys   = FUN_10229230(&pmon, &raw->syscallFilter /*raw+0x218*/)
                                                         vftable 0x1057bf10
FUN_1021a080(raw, &sys, &count)  or  FUN_1021ad20(raw, &sys, &count)
~sys FUN_10229300, ~pmon FUN_10229870
```

| vtable | +0 | +4 | +8 | +0xc |
|---|---|---|---|---|
| CPSP2SysTracePMonParser 0x1057bf50 | dtor 10229880 | `NextPacket` FUN_10210070 (CPMonParser) | `AddWord` FUN_102298b0 | `GetPacket` FUN_10229960 |
| CPSP2SysTraceParser 0x1057bf10 | dtor 10229360 | `GetSchedulerPacket` FUN_10229420 | `GetSyscallTracePacket` FUN_10229570 | FUN_10401b10 (returns 1) |

Other bookmark users in the DLL (call sites of FUN_10217d50/FUN_102180c0/FUN_10217ee0/FUN_1020fe20)
read FIFO A regno 9, FIFO A regno 15 and the GPU channels. SYS_1..SYS_9 (B regno 7..15) are not read.

## 2. Bookmark stream: CPMonParser::NextPacket (FUN_10210070)

The object fields are given as dword index `[n]` (byte offset n*4).

- `[0x23]` is the buffer reader. It is walked chunk by chunk (reader vt+4 returns the chunk size,
  `[0x2e]` is the chunk pointer). `[0x25]` is the current frame, `[0x26]` the slot index 0..6,
  and `[0x27]` the 0x7d half toggle.
- **Slot type** = `byte[frame + 3 + 2*slot] & 0x7f`. Bit 15 of the descriptor is *not* checked here.
  - **0x7c:** the bookmark is at `frame + 0x10 + slot*16`; go to the next slot.
  - **0x7d:** first the bookmark at `+0`, then the one at `+8` (the toggle), then go to the next slot.
  - **0x7e:** `base_lo = u32[slot+0] & 0xffe00000`, `base_hi = u16[slot+4]`. The bookmark at
    `slot+8` is then delivered like any other. The bookmark embedded in a 0x7e slot is real data.
- **Filter:**
  - `byte[obj+0x88]` = FIFO (1 means bit 31 must be set).
  - `byte[obj+0x89]` = regno, compared against `(w0 >> 27) & 0xf`.
- **CPU:** `cpu = ((w0 >> 21) & 0x3f) - 1` (as a byte). **If cpu > 3 the function returns false:
  the whole system-trace pass ends at that bookmark**, not just that bookmark. Never put master 0
  or 5..63 on B/SYS_0.
- **Time:** `time64 = (base_hi:base_lo) + (w0 & 0x1fffff) - (origin_hi:origin_lo)`.
  - The origin (`[0x2c]`, `[0x2d]`) is the full u32 and u16 of the **first 0x7e slot in the buffer**
    (FUN_10210240 -> FUN_1020ffb0). `CPSP2ProcessRawTraceData` uses the same origin (FUN_102185a0,
    `raw+0x200/0x208`), so all streams share t = 0.
  - There is no wrap handling. A 0x7e slot must come before any bookmark whose `time >> 21`
    differs from the running base.
  - Bookmarks earlier than the first 0x7e come out as huge unsigned values, so start the buffer
    with a 0x7e slot.
- **Packet assembly:** each accepted bookmark calls vt+8 `AddWord(cpu, time, data)`. When that
  returns true, vt+0xc `GetPacket(cpu, &pkt)` is called and NextPacket returns true.

## 3. Reassembly: CPSP2SysTracePMonParser::AddWord (FUN_102298b0)

Per-CPU state `S = obj + 8 + cpu*0x20`. This is an eh-vector of 4 x 0x20 bytes, built in
FUN_1020fe20:

```
S+0x00 u32 remaining bytes
S+0x08 u64 packet time         <- GetPacket (FUN_10229960) returns &S+0x08
S+0x10 u32 cpu
S+0x14 std::vector<u32> words  (begin, end, cap)
```

**When `remaining == 0`, the word must be a header**, else it is silently dropped. With
`type = w >> 24` and `len = (w >> 16) & 0xff`, the header is accepted only if all of these hold:

- `type` is one of 1, 2, 3, 4, 5.
- `(len & 3) == 0`.
- `len > 4`.
- `len == 0x0c` if `type` is 2 or 3.

On acceptance: `cpu` is stored, `remaining = len - 4`, time = this bookmark's time, the vector is
cleared and the header is pushed. The function returns false.

**Otherwise** the word is pushed and `remaining -= 4`. When it reaches 0 the function returns true
and the packet is complete.

Rules that follow:

- Words of one packet must be the next bookmarks **of the same master on B/SYS_0**. Bookmarks of
  other masters or channels may be interleaved.
- There is no sequence number or checksum. A lost word shifts every later packet of that CPU until
  a word happens to look like a header.
- The packet timestamp is the header's. Later words' times are ignored.
- Packets are handed to the consumers in **completion order** (buffer position of their last word).
- The low 16 bits of type 4/5 headers and b1 of type 3 are not read. Write 0.

## 4. Scheduler packets

### 4.1 Record: CPSP2SysTraceParser::GetSchedulerPacket (FUN_10229420)

The function loops over packets and skips everything except the three types below. It fills a
0x28-byte record `R` (zeroed first):

| type (len) | R+0x0c kind | fields |
|---|---|---|
| 2 (0x0c) | 0 | R+0x10 = 0, R+0x18 = b1, R+0x1c = b0 |
| 3 (0x0c) | 1 | R+0x10 = 1 if b0 == 2, 4 if b0 == 4, else 0xff |
| 1 (0x0c) | 2 | R+0x14 = b0, R+0x18 = b1 |

These fields are common to all three kinds: `R+0x00` u64 packet time, `R+0x08` cpu,
`R+0x20` = w1, `R+0x24` = w2. Type 1 packets with any length other than 0x0c are skipped.

### 4.2 ProcessSchedulerTrace (FUN_1021a080)

Stack layout from the disassembly: R = EBP-0x38, kind = EBP-0x2c, w1 = EBP-0x18, w2 = EBP-0x14.
A std::map is keyed by `{w2, w1}`, and each node holds a copy of the last kind-0 record
(`node+0x18` = start time).

- **kind 0 (switch in):**
  - Unknown thread: insert a node.
  - Known thread whose start != -1: count "Scheduler trace missing %u events!" and overwrite
    (the earlier interval is lost).
  - Known thread whose start == -1: store the record.
- **kind 1 (switch out):** unknown thread is ignored. A known thread whose start == -1 counts
  "missing %u start events". Otherwise:
  1. `FUN_102188a0(&thr, pid = w1, tid = w2)` looks up the process in map `raw+0x30` by w1 and
     the thread in `proc[6]` by w2. Both are created if absent. For an unknown thread in the
     target process (`raw+0x1f8`) it also logs message 0x51f. So **w1 = process id, w2 = thread id**.
  2. `FUN_10216d20` builds `RZR_EVENT_THREAD_SCHEDULER(_V2)` (pool `raw+0xb8`, 0x20 bytes) and
     pushes it onto `thr+0x1c`:

     ```
     +0x00 u32 0x0011001c   (type 0x11, payload 0x1c)
     +0x04 u64 start (switch-in time)
     +0x0c u64 end   (switch-out time)
     +0x14 u16 cpu of the switch-out packet          export CpuCoreId      (FUN_102c0bd0)
     +0x16 u8  0                                     export StartThreadIncidentId (FUN_102c1560)
     +0x17 u8  R.+0x10 of the switch-out (1/4/0xff)  export StopThreadIncidentId  (FUN_102c15f0)
     +0x18 u32 b1 of the switch-in header            export StartThreadIncidentPriority (short, FUN_102c1580)
     +0x1c u32 b0 of the switch-in header            (not exported)
     ```

  3. `raw+0x18` (count) is incremented.
  4. `EVENT_THREAD_SCHED {u64 start, u64 end, u32 pid, u32 tid}` (pool `raw+0x120`) is pushed onto
     the per-CPU vector `raw + 0x44 + cpu*0xc`.
  5. `raw+0x210` = max(end) (the capture end).
  6. The node's start is set to -1.
- **kind 2 (priority change):** after `FUN_102188a0`, `RZR_EVENT_THREAD_PRIORITY_CHANGE` (pool
  `raw+0x84`) is pushed onto `thr+0x64`:

  ```
  +0x00 u32 0x00050010   +0x04 u64 time   +0x0c u32 b1 (NewPriority, FUN_102c1120)   +0x10 u32 b0 (OldPriority, FUN_102c1220)
  ```

- **End of stream:** every node with start != -1 and `start < raw+0x210` gets a scheduler event
  `[start, raw+0x210]` with the node's cpu and stop incident 0xff, and the count is incremented.
  These closures are **not** added to the per-CPU vectors.
- **Return value:** `count != 0`, else `FUN_100304d0("...ProcessSchedulerTrace", 0x408, false)`,
  which returns its third argument (false). `FUN_102190c0` returns it and `FUN_10228e10` gives up.

Consequences for a synthetic trace:

- Emit at least one switch-in/switch-out pair.
- Close each interval on the CPU it started on. The per-CPU vector is searched with a lower_bound
  (`FUN_102186d0` LookupThreadId -> `FUN_10213670`) and must stay sorted and non-overlapping.
- Switch every running thread out at the capture end. That both sets the capture end and puts the
  last slices into the per-CPU lists. `FUN_1021b150` and `FUN_1021bea0` stop at events later than
  `raw+0x210`. `FUN_10219300` fails when it finds no CPU-user markers and `raw+0x210` is 0.
- A bookmark on another channel is attributed to a thread only if its time lies inside a per-CPU
  interval of CPU `master-1` (`FUN_102180c0` GetTraceBufferPerThread -> `FUN_102186d0`).
  Otherwise it is dropped.

**Stop incident (interpretation).** b0 of the switch-out header looks like the outgoing thread's
`SceThreadStatus`:

- READY (2) is incident 1, a preemption.
- STANDBY (4) is incident 4.
- WAITING (8) and every other value are incident 0xff.

Razor only uses the mapping 2 -> 1, 4 -> 4, else -> 0xff. **Start code** (b0 of type 2) is kept at
event+0x1c but never shown; write 0.

## 5. Syscall packets

### 5.1 GetSyscallTracePacket (FUN_10229570)

The function fills a 0x50-byte record `P` (zeroed). It skips packets that are not type 4 with
len 0x1c or type 5 with len 0x10. `P[0..2]` = time lo, time hi, cpu. `P[n]` means dword n.

**Type 4 (enter), `P[3] = 1`:**

- `NID = ~w1 + 0xE9D4F638`, so `w1 = ~(NID - 0xE9D4F638)`.
- The NID is looked up in the syscall DB (`FUN_10124cf0` singleton, `FUN_10124e90`). **If it is
  unknown, the function logs and returns false, which ends the whole syscall pass.**
- `P[4]` = syscall info handle, `P[5]` = w2 (call id).
- `P[6..13]` = w3, w4, w5, w6 as zero-extended u64s (args 0..3).

**Type 5 (exit), `P[3] = 2`:**

- `P[5]` = w1 (call id).
- `P[0xe..0xf]` = w2 (return value, u64).
- `P[0x10..0x11]` = w3 (aux, not used later).

**Filter flag `byte P[0x48]`.** The parser copies the table `raw+0x218` (filled in `FUN_102144a0`
from 0x1065baf0) into 12-byte entries `{name, nid, learned id}`:

| NID | name |
|---|---|
| 0x2682E6ED | `_sceKernelExitCallback` |
| 0xE53E41F6 | `sceKernelCheckCallback` |
| 0xA4683592 | `sceKernelNotifyCallback` |

A type-4 packet with one of these NIDs stores its w2 in the entry and is flagged. A type-5 packet
whose w1 equals a learned id is flagged too. Flagged packets are skipped (FUN_1021ad20
`cmp byte [ebp-0x28], 1`). Do not reuse such a call id for other syscalls, and avoid call id 0.

**NID DB.** PSP2Razor.dll has an embedded table of 0x40-byte entries (seen at 0x10678148..,
0x10678208 ..). Each entry starts with the **encoded** NID and names the call
`"syscall_0x%08x"` (1853 such strings). Example: entry 0x10678208 holds 0xFCBCEAED and the name
`syscall_0xed180b4a`, and `~0xFCBCEAED + 0xE9D4F638 = 0xED180B4A`. Real names come from the
optional `%SCE_PSP2_SDK_DIR%\..\internal\tool\razor\PSP2RazorCpuDoNotDistribute.dll` (FUN_1021e850),
which is absent here. The code path that loads the embedded table into the DB map was not traced.
Use NIDs present in the table; `KNOWN_SYSCALL_NIDS` in the tool lists a few.

### 5.2 Syscall pass (FUN_1021ad20)

This pass always returns true.

1. The per-CPU cursors `raw+0x74..0x83` are zeroed.
2. For every non-flagged packet, `FUN_10218020(cpu, time)` walks the per-CPU interval vector
   forward from the cursor to find the running `(pid, tid)`. **The syscall time must lie inside a
   closed interval on that CPU, and packets must be time-ordered per CPU** (the cursor never goes
   back). Otherwise the packet is ignored.
3. A map keyed by `(pid, tid)` pairs the packets:
   - An enter stores the record. An enter while another is open counts
     "Syscall trace missing %u events!".
   - An exit with an open enter calls `FUN_10216bd0`. That function requires the process and
     thread to exist already, since it does not create them. It builds `RZR_EVENT_SYSCALL`:

     ```
     +0x00 u32 0x00020060   +0x04 u64 enter time   +0x0c u64 exit time
     +0x14 u16 enter cpu    +0x16 u16 exit cpu     +0x18 u32 syscall info (from NID)
     +0x1c u64 return value (type5 w2)
     +0x24 u64 arg0  +0x2c u64 arg1  +0x34 u64 arg2  +0x3c u64 arg3   (type4 w3..w6)
     +0x44 .. +0x63 zero
     ```

Pairing is per thread. The call id is only used by the filter, so nested syscalls on one thread
are not supported.

## 6. Thread and process identity, names, IsKernelIdle

- **Identity.** pid = w1 and tid = w2 of every scheduler and syscall packet (`FUN_102188a0`).
  Both are the Vita UIDs Target Manager reports. Kernel threads use pid **0x10005**, which
  `CPSP2Target::GetProcessNameInfo` (`FUN_101af640`) hard-codes as process "Kernel".
- **Names are not in the trace.** `FUN_101af640` asks Target Manager, through the COM target
  interface at `CPSP2Target+0x140`:
  - Kernel thread names: `target->vt[0x1bc](VARIANT ids, VARIANT names)`.
  - The process collection: `target->vt[0x20]`. For each process: `vt[0x1c]` id, `vt[0x20]` name
    BSTR, and `vt[0x38]` a sub-object whose `vt[0xbc](ids, names)` returns that process's threads.
  - `CPSP2Target::ParseThreadNames` (`FUN_101b4e20`) accepts `ids` as `VT_ARRAY|VT_UI4` (0x2013)
    and `names` as `VT_ARRAY|VT_BSTR` (0x2008) of equal length. The first name for a tid wins.
  - The resulting map seeds processes and threads in `FUN_10219d30`. Ids that appear only in the
    trace are created without names (`FUN_102188a0`).
  - So a retail target must return thread lists whose ids equal the tids written into the packets.
- **IsKernelIdle.** An export property of `CThreadTraceData`: bit 0 of `+0x14` (`FUN_101536f0`).
  `CSnapShotCaptureModel::TotalProcessIdleTimes` (`FUN_100ffe60`) sums the interval durations of
  threads with that bit, split by bit 1 (`FUN_10153700`) into two totals. The ctor
  (`FUN_10152ea0`) zeroes the flags. No system-trace packet sets them, and the setter was not
  located. Nothing in the packet format marks idle threads.

## 7. Minimal valid example

Two threads of process 0x40010003 alternate on CPU 0 in 2 ms slices over 10 ms:

- A = 0x40010005, priority 160
- B = 0x40010007, priority 128

The order is A, B, A, B, A, and everything is switched out at +10 ms. The start is
t0 = 0x0C1F0000 (1 ms = 333000 ticks). The switch-in after a switch-out on the same CPU is placed
3 ticks later, so per-CPU times stay strictly increasing.

Generated by `python tools/pa_systrace.py` (`example_two_threads()`). `word0` is the 0x7c/0x7d
slot form, whose upper 27 time bits must come from a preceding 0x7e slot. The time windows used
are 0x0C000000, 0x0C200000 and 0x0C400000.

```
 #  fifo regno master  time48          data        | word0      word1
 0  B     6    1       0x00000C1F0000  0x020CA000  | 0xB03F0000 0x020CA000   switch in  prio 0xA0
 1  B     6    1       0x00000C1F0001  0x40010003  | 0xB03F0001 0x40010003     pid
 2  B     6    1       0x00000C1F0002  0x40010005  | 0xB03F0002 0x40010005     tid A
 3  B     6    1       0x00000C292990  0x030C0002  | 0xB0292990 0x030C0002   switch out status READY  (+2 ms)
 4  B     6    1       0x00000C292991  0x40010003  | 0xB0292991 0x40010003
 5  B     6    1       0x00000C292992  0x40010005  | 0xB0292992 0x40010005
 6  B     6    1       0x00000C292993  0x020C8000  | 0xB0292993 0x020C8000   switch in  prio 0x80
 7  B     6    1       0x00000C292994  0x40010003  | 0xB0292994 0x40010003
 8  B     6    1       0x00000C292995  0x40010007  | 0xB0292995 0x40010007     tid B
 9  B     6    1       0x00000C335320  0x030C0002  | 0xB0335320 0x030C0002   switch out (+4 ms)
10  B     6    1       0x00000C335321  0x40010003  | 0xB0335321 0x40010003
11  B     6    1       0x00000C335322  0x40010007  | 0xB0335322 0x40010007
12  B     6    1       0x00000C335323  0x020CA000  | 0xB0335323 0x020CA000   switch in A
13  B     6    1       0x00000C335324  0x40010003  | 0xB0335324 0x40010003
14  B     6    1       0x00000C335325  0x40010005  | 0xB0335325 0x40010005
15  B     6    1       0x00000C3D7CB0  0x030C0002  | 0xB03D7CB0 0x030C0002   switch out (+6 ms)
16  B     6    1       0x00000C3D7CB1  0x40010003  | 0xB03D7CB1 0x40010003
17  B     6    1       0x00000C3D7CB2  0x40010005  | 0xB03D7CB2 0x40010005
18  B     6    1       0x00000C3D7CB3  0x020C8000  | 0xB03D7CB3 0x020C8000   switch in B
19  B     6    1       0x00000C3D7CB4  0x40010003  | 0xB03D7CB4 0x40010003
20  B     6    1       0x00000C3D7CB5  0x40010007  | 0xB03D7CB5 0x40010007
21  B     6    1       0x00000C47A640  0x030C0002  | 0xB027A640 0x030C0002   switch out (+8 ms)
22  B     6    1       0x00000C47A641  0x40010003  | 0xB027A641 0x40010003
23  B     6    1       0x00000C47A642  0x40010007  | 0xB027A642 0x40010007
24  B     6    1       0x00000C47A643  0x020CA000  | 0xB027A643 0x020CA000   switch in A
25  B     6    1       0x00000C47A644  0x40010003  | 0xB027A644 0x40010003
26  B     6    1       0x00000C47A645  0x40010005  | 0xB027A645 0x40010005
27  B     6    1       0x00000C51CFD0  0x030C0002  | 0xB031CFD0 0x030C0002   switch out (+10 ms, capture end)
28  B     6    1       0x00000C51CFD1  0x40010003  | 0xB031CFD1 0x40010003
29  B     6    1       0x00000C51CFD2  0x40010005  | 0xB031CFD2 0x40010005
```

Razor's view (reference decoder `razor_decode`, times relative to the first bookmark): five
`RZR_EVENT_THREAD_SCHEDULER` intervals on CPU 0, namely A 0-2 ms, B 2-4, A 4-6, B 6-8, A 8-10,
all with stop incident 1. The capture end is 10 ms and no warnings are logged. Packing these with
`pa_frames.pack` gives 3 frames (descriptors `7e00 7d00 7e00 7d00 7d00 7d00 7d00 | 7d00 7d00 7d00
7d00 7c00 7e00 7d00 | 7d00 7d00 7d00 0 0 0 0`). The 0x7e slots carry bookmarks 0, 3 and 21, the
first bookmark of each 21-bit window. `iter_bookmarks` on that buffer decodes to the same
intervals.

A syscall inside a slice on CPU 1 (see the self-test in the tool) looks like this:

```
enter: 0x041C0000, 0xFCBCEAED (NID 0xED180B4A), call_id=1, a0, a1, a2, a3
exit : 0x05100000, call_id=1, 0x80020001 (ret), 0
```

## 8. Open points

- **Meaning of the incident ids and of the start code.** Razor only stores them (section 4.2);
  the ThreadIncident name table was not decoded.
- **Loader for the embedded syscall table.** How it reaches the `FUN_10124cf0` DB was not traced.
  The value encoding is verified; presence in the DB at run time is inferred.
- **Setter for the CThreadTraceData idle flags** was not found.
