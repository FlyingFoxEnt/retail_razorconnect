# Razor CPU trace: the PA raw trace buffer (work in progress)

What PS Vita Razor (PSP2Razor.dll 3.60.0.5, 32-bit) expects to read back from a target's
Performance Analysis (PA) trace buffer. On a DevKit this buffer is filled by the PA hardware
(CoreSight PFT from the Cortex-A9 cores plus "bookmarks" written by the kernel/libperf into two
16-channel FIFOs). A retail Vita has to synthesize it.

Addresses are PSP2Razor.dll (image base 0x10000000). Ghidra project: `RAZOR` (see tools notes).

## 1. Host call sequence (CPSP2Target, verified from decompile)

`StartCaptureCallback` FUN_101b6d50 -> `ConfigurePerfmon(pid)` FUN_101ac0b0, on the TMAPI
`IPerformanceAnalysis` object:

1. `Open()`. If it fails with 0x80040255, `Close()` then `Open()` again.
2. `TimebaseFrequency` **must be 333** (`f * 1000000 == 333000000`), else capture aborts
   (error resource 0x771). So timestamps are ticks of a 333 MHz timebase.
3. `TraceBufferAvailableSize` (capped to 0x4000000), halved in one mode.
4. `ConfigNormalTraceBuffer(0, stopWhenFull, size, 0x1f)`.
5. `GetBookmarkConfig`; set A-enabled `0xfe0f`, A-destination 0, B-enabled `0xffc3`,
   B-destination 0, then props `0xf`, `100`, `100`; `SetBookmarkConfig`.
6. `CreateArmTrace(traceMode, sampleMode, tsPeriod, samplePeriod, pid)`.
7. `StartCapture()`.

Before that: process must be in run state 2, Razor looks for `sceRazorCpuSync` in the main
module's ELF, and `ConnectToLibPerf` FUN_101ac960 scans modules (flag bit 0) in process memory for
the marker `DE BE AD BE  BE BE EF BE` (u32 0xBEADBEDE, 0xBEEFBEBE) followed by the address of
libperf's Razor info struct (version >= 5; v5 size 0x28). Missing libperf is tolerated.

Bookmark channel names (TMAPI `ePABookmarkAChannels` / `ePABookmarkBChannels`):

| FIFO A regno | channel | FIFO B regno | channel |
|---|---|---|---|
| 0-3 | USER_0..3 | 0-1 | DTRACE_0..1 |
| 4-7 | RAZOR_GPU_0..3 | 2-5 | RAZOR_KERNEL_GPU_0..3 |
| 8 | RAZOR_GPU_GENERAL | 6-15 | SYS_0..9 |
| 9 | RAZOR_CPU_USER | | |
| 10 | RAZOR_CPU_CALLPROF | | |
| 11 | RAZOR_CPU_HUD | | |
| 12-14 | LIB_0..2 | | |
| 15 | FIBER_TRACE | | |

## 2. Buffer container (verified)

Iteration: FUN_10219450 (`ProcessPftPcSample`), FUN_10217d50 (bookmark iterator),
FUN_102185a0 (find first timestamp).

The buffer is a sequence of **0x80-byte frames**:

```
+0x00  u16  (unknown, not read by the iterators seen so far)
+0x02  u16  desc[0]   one descriptor per slot, 7 slots
...
+0x0e  u16  desc[6]
+0x10  16 bytes slot[0]
...
+0x70  16 bytes slot[6]
```

Slot type: if `desc & 0x8000` the slot is handled by FUN_103efc50 (not yet decoded); otherwise
`type = (desc >> 8) & 0x7f` and `desc & 0xff` is printed as a channel/source number:

| type | meaning | handler | slot contents |
|---|---|---|---|
| 0x10 | ARM trace (CoreSight PFT byte stream, 16 bytes) | FUN_103edc00 | raw PFT bytes; `FF FF FF 7F` = full sync |
| 0x7c | Bookmark 64 x 1 | FUN_103ef460 | one 64-bit bookmark in bytes 0..7 |
| 0x7d | Bookmark 64 x 2 | FUN_103ef5e0 | two 64-bit bookmarks |
| 0x7e | Bookmark + timestamp | FUN_103ef880 | `u32 tbLow, u16 tbHigh, u16 ?, u16 ?, u16 bmDesc, u32 data` |
| 0x7f | Bookmark 128 | FUN_103ef320 | `u32 tbLow, u16 tbHigh, u16 ?, u16 ?, u16 bmDesc2, u32 data` |

The iterator in FUN_10217d50 reads a 64x1 bookmark at `frame + 0x10 + (slot*2 + k)*8` where `k`
alternates 0/1 for 64x2 (`+0x1d4` toggles). For 0x7e it sets the running timebase high part:
`base = slotword0 & 0xffe00000`, `baseHigh = u16 at slot+4`, and yields the bookmark at slot+8.

### 64-bit bookmark

```
word0: bit31 FIFO (0=A, 1=B) | bits27-30 regno | bits21-26 master | bits0-20 time low 21 bits
word1: data
```

Time = `(word0 & 0x1fffff) | (base & 0xffe00000)`, high 16 bits from the last 0x7e slot:
a 48-bit timebase. For 0x7e / 0x7f the desc word is `bmDesc`: bit15 FIFO, bits11-14 regno,
bits5-10 master (0x7f: bit12 FIFO, bits8-11 regno, bits0-5 master).

`master` indexes a name table `PTR_s_reserved_1068a010`; for CPU bookmarks `master - 1` is the
CPU core (0..3) (FUN_102180c0 `GetTraceBufferPerThread`).

## 3. Consumers (partially decoded)

- FUN_102180c0 `GetTraceBufferPerThread`: iterates bookmarks of one FIFO/regno, maps
  (cpu = master-1, time) to (process, thread) with FUN_102186d0 `LookupThreadId` over per-CPU
  on-CPU intervals built from the scheduler trace, and buckets `{time64, word0, word1}` per thread.
- FUN_1021c740: probes FIFO A regno 9 (RAZOR_CPU_USER) records through FUN_10216820.
- FUN_1021a080 `ProcessSchedulerTrace`: consumes records from an iterator object with a record
  kind 0/1/2 at record+0x0c, (time) at +0x00/+0x04, fields at +0x10.. ; builds on-CPU intervals.
- FUN_10229570 `CPSP2SysTraceParser::GetSyscallTracePacket`: packets assembled from bookmark data
  words; first word top byte = packet type: 4 -> 7 words (syscall; NID = `~w1 + 0xE9D4F638`),
  5 -> 4 words.
- ProcessMainTraceBuffer FUN_102190c0 modes: 0 -> FUN_1021a080 path, 1 -> FUN_1021ad20 path,
  5 -> FUN_10219450 (PFT PC sample).
