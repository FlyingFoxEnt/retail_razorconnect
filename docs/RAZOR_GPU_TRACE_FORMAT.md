# Razor GPU trace: bookmark channels, the .pmon container, and CPU-timeline correlation

How PS Vita Razor (`PSP2Razor.dll` 3.60.0.5, image base `0x10000000`, 32-bit) produces the "GPU
activity" rows shown against a CPU trace, and what a target must deliver for them to appear.
Builds on `RAZOR_PA_TRACE_FORMAT.md` (frames, slots, 64-bit bookmark, timebase) and
`RAZOR_SYSTRACE_FORMAT.md` (CPMonParser). psp2tm.exe PAMP framing is in `PAMP.md`.

Every claim cites the function/data it comes from. "**Interpretation**" marks names/meanings that
are inferred rather than decoded behaviour. Addresses are PSP2Razor.dll unless prefixed:
`tm!` = psp2tm.exe 3.60.0.2 (Ghidra project TMRE), `api!` = psp2tmapix86.dll (project TMAPI).

Raw decompiles are not committed: they include dumps of Sony resources.

---

## 0. Summary

**The GPU-activity timeline is NOT built from GPU bookmarks in the CPU (ARM PA) trace buffer.**
The four bookmark readers -
`FUN_1020fe20` (CPMonParser ctor), `FUN_10217d50` (bookmark iterator), `FUN_102180c0`
(`GetTraceBufferPerThread`), `FUN_10217ee0` (CPU-user packet reader), plus the fifth sibling
`FUN_1021c590` (skip-N iterator) - are only ever invoked on three channels:

| reader | call site | fifo/regno used | source |
|---|---|---|---|
| `FUN_1020fe20(buf,1,6)` | `FUN_10229850` (`CPSP2SysTracePMonParser` ctor) | **B / 6** = SYS_0 | callargs, vtable `0x1057bf50` |
| `FUN_10217d50(0,9,..)` | inside `FUN_10217ee0`,`FUN_10216820`,`FUN_1021c740`,`FUN_1021c590` | **A / 9** = RAZOR_CPU_USER | disasm |
| `FUN_102180c0(..,0,0xf,..)` | `FUN_10218fa0` `ProcessFiberTrace` | **A / 0xf** = FIBER_TRACE | FUN_10218fa0 |
| `FUN_1021c590(0,9,..)` | inside `FUN_10217ee0` | **A / 9** | |

No call passes regno 4..8 (A) or 2..5 (B). `GetTraceBufferPerThread` (`FUN_102180c0`) takes fifo/
regno as parameters, but its single caller passes A/15. **So `RAZOR_GPU_0..3`, `RAZOR_GPU_GENERAL`
and `RAZOR_KERNEL_GPU_0..3` are never read out of the CPU PA trace buffer by this DLL.** Those
bookmark channels are captured on the target into a **separate GPU trace = a `.pmon` file**, fetched
over PAMP `CreateGpuTrace`/`FetchTraceData`, and merged into the CPU view by *timestamp* using CPU
Frame bookmarks. This is confirmed by the correlation errors in §4 ("The GPU Trace could not be
correlated...") and by the `.pmon` parser owning its own bookmark channel table (§3).

Consequence for the retail-target project: to make GPU rows appear you do **not** inject GPU
bookmarks into the CPU PA buffer. You must (a) answer PAMP `CreateGpuTrace` and hand back a valid
`.pmon` file via `FetchTraceData`, and (b) emit the `[ARM] CPU Frame (sceGxmPadHeartbeat)` bookmark
on the CPU side so the two clocks line up. (a) is the large task; its format is §3.

---

## 1. Bookmark channel numbers (verified against TMAPI)

`PSP2TMAPILib.ePABookmarkAChannels` / `ePABookmarkBChannels`, read from
`Interop.PSP2TMAPILib.dll` by reflection (matches `RAZOR_PA_TRACE_FORMAT.md` §1 and the embedded
`Bookmarks.xml`, RCDATA resource id 1402, dumped to `ghidra/bookmarks_embedded.xml`):

```
FIFO A: 0-3 USER_0..3 | 4-7 RAZOR_GPU_0..3 | 8 RAZOR_GPU_GENERAL | 9 RAZOR_CPU_USER
        10 CPU_CALLPROF | 11 CPU_HUD | 12-14 LIB_0..2 | 15 FIBER_TRACE
FIFO B: 0-1 DTRACE_0..1 | 2-5 RAZOR_KERNEL_GPU_0..3 | 6-15 SYS_0..9
```

The embedded `Bookmarks.xml` declares the GPU bookmark **type masks** the target's GPU uKernel/
libgxm emit (these are the packets that end up in the `.pmon`, matched by caption in §4):

| Channel | TypeMask | TypeValue | Caption |
|---|---|---|---|
| B2 | ff000000 | 10000000 | `GPU Frame (TA)`  (vertex frame) |
| B2 | ff000000 | 11000000 | `GPU Frame (3D)`  (fragment frame) |
| B2 | ff000000 | 12000000 | `GPU Frame (SPM)` |
| B2 | ff000000 | 13000000 | `GPU Frame (2D)` |
| B2 | ff000000 | 14000000 | `GPU MT LLS (Num Valid MTs)` |
| B2 | f0000000 | 20000000 | `GPU Scene (SGXMKIF_TAFLAGS_*)` |
| B2 | ff000000 | 40000000 | `GPU Scene (MASTER_VDM_BATCH_NUM)` |
| B2 | f0000000 | 50000000 | `GPU Scene (SGXMKIF_RENDERFLAGS_*)` |
| B2 | fc000000 | 30000000 | `GPU Process ID (TA)` |
| B2 | fc000000 | 34000000 | `GPU Process ID (3D)` |
| B2 | fc000000 | 38000000 | `GPU Process ID (2D)` |
| A8 | ffffffff | b0bafe77 | `[ARM] CPU Frame (sceGxmPadHeartbeat)` (**CPU side, in the CPU trace**) |
| A8 | ff000000 | 10..1e000000 | libgxm `sceGxmBeginScene/EndScene/Kick/...` |
| B2 | ff000000 | ad000000 | EDM Trace (MKTC_*) |
| B3 | ff000000 | 10..13000000 | display driver `sceDisplaySetFrameBuf` / vblank |

Each is `bookmark.word1 & TypeMask == TypeValue`; the low bits carry the payload (frame number,
scene index, pid). This is the *definition* table; the actual matcher is caption-based (§4).

---

## 2. PAMP `CreateGpuTrace` (cmd 0x04 sub 2) and `GetGpuSampledData` (cmd 0x10)

### 2.1 The TMAPI method (authoritative signatures, from the interop typelib)

`IPerformanceAnalysis` (IID `4B774C15-82F7-4EFB-AA9F-791F0A28884F`) - reflected:

```
CreateGpuTrace(uint nControl, ushort nSampleRate, ushort nCountedRate,
               uint[] arrDBusAEnabled, uint[] arrDBusBEnabled,
               uint[] arrConditionMask, uint[] arrValidityMask)
GetGpuSampledData(uint[] arrData)          // arrData length 4  -> 16 bytes
```

### 2.2 Wire format (psp2tm.exe, verified)

psp2tm sends PAMP command **4** with a **0x48-byte body** for the GPU sub-case. The generic
`Create*Trace` dispatcher is `tm!FUN_1400db5d0(buf, requestId, sub)`; it writes
`u32 command=4, u32 requestId, u32 length=0, u32 sub`. `CreateGpuTrace` is
`tm!FUN_1400dcbe0` (sub `2`) which then appends exactly **0x48** bytes:
`tm!FUN_140242bd0(buf+8, body, 0x48)`. Its caller `tm!FUN_140088560`
increments requestId, appends, checks the frame stays < 0x10fed bytes, then
`FUN_140090e80(buf, 4, requestId, resp)` (send-and-wait, command 4). Cross-check: sub-0 ARM is
`FUN_1400dcb00` (0x10 body), sub-1 counter is `FUN_1400dcb70` (0x18 body), sub-2 GPU is 0x48 -
matches `PAMP.md` cmd 4 (sub 0=16, sub 1=0x18, sub 2=0x48).

**The 0x48 body layout** is proven by the psp2tmapi *response/print* serializer
`api!FUN_1008a410` ("Control:/SampleRate:/CountedRate:/DBusAEnabled:/DBusBEnabled:/ConditionMask:/
ConditionValidityMask:"). Reading its field offsets on the packed request struct:

```
+0x00  u32   nControl              (labelled "Control")
+0x04  u16   nSampleRate
+0x06  u16   nCountedRate
+0x08  u32[4] arrDBusAEnabled      (16 bytes)   D-bus A probe-enable mask, per USSE/core slot
+0x18  u32[4] arrDBusBEnabled      (16 bytes)
+0x28  u32[4] arrConditionMask     (16 bytes)
+0x38  u32[4] arrValidityMask      (16 bytes)   "ConditionValidityMask"
= 0x48 bytes total
```
(`*param_2`=Control, `param_2[1]` low/high u16 = SampleRate/CountedRate, then four
4-dword arrays at word indices 2, 6, 10, 0xe.) The serializer that *marshals* it into the DECI
payload is `api!FUN_100e9730` -> `FUN_10086600(dst,&0x48)` (writes the whole 0x48 struct);
`api!FUN_100e9bc0`/`FUN_10086760(src,0x48)` reads it back. **Interpretation:** these are the SGX
uKernel PMON hardware-trace programming fields (D-bus event selects + counted/sampled rates); the
GPU firmware fills a PMON trace ring which becomes the `.pmon` (§3). The names come straight from
the interop typelib, so they are reliable; the bit meanings of `nControl`/the masks are not decoded.

When does Razor send it? The DLL's snapshot GPU-trace session `CPSP2SnapShotSessionRunGpuTrace`
(`FUN_10258c30` `DoCaptureInternal`, `FUN_10259530` `RequestCapture`, `FUN_102595a0` `RunCapture`) is a *distinct* capture from the CPU trace. It is driven by the `EnableGpuActivityTrace`
capture option (`CCaptureOptions` field, default **1**; `FUN_1008c140` sets
`EnableGpuActivityTraceOption` = 1, data `0x10659b10`/`0x105030f8`). So a normal
"CPU trace with GPU activity enabled" runs both the ARM PA capture *and* a GPU trace; the GPU rows
come from the latter.

### 2.3 `GetGpuSampledData` (cmd 0x10, 16-byte response)

psp2tm `tm!FUN_140088910` sends command **0x10** and reads a 16-byte response body
(`api!` response class `CGetGpuSampledDataResponse`: printer `FUN_100bf700` labels it
"Data:", (de)serialize `FUN_100c39b0`/`FUN_100dbe80` move **0x10** bytes). Backing SDK export is
`_sceKernelPaGetGpuSampledData(SceKernelPaGpuSampledData *data)` (NID 0xB0CB88A8, syscall table
entry 539, `ghidra/syscall_table.txt`).

The 16 bytes are the live "GPU status" sample, **not** the timeline. From the HUD/attribute strings
(string resource ids 11271-11312): `Status of GPU at a given point in time`,
`The time at which the GPU status sample was taken in clock ticks`, `Sampled GPU GRBM Status
Register` and `Sampled GPU GRBM2 Status Register`. **Interpretation of the 16 bytes** (two 32-bit
status regs + a 64-bit timestamp; bit meanings from the two GRBM strings):
```
+0x00  u32  GRBM  status register   (bit14 TA_BUSY, 15 GDS_BUSY, 17 VGT_BUSY, 18 IA_BUSY_NO_DMA,
                                      19 IA_BUSY, 20 SX_BUSY, 22 SPI_BUSY, 24 SC_BUSY, 25 PA_BUSY,
                                      26 DB_BUSY, 29 CP_BUSY, 30 CB_BUSY, 31 GUI_ACTIVE; 0-13 undisc.)
+0x04  u32  GRBM2 status register   (bit25 TC_BUSY, 28 CPF_BUSY, 29 CPC_BUSY, 30 CPG_BUSY; else undisc.)
+0x08  u64  timestamp (clock ticks) [inferred from "taken in clock ticks"]
```
This feeds the HUD, not the CPU timeline, and is out of scope for GPU-job rows.

---

## 3. The GPU trace file (`.pmon`) container

`FetchTraceData`/`ReadTraceData` returns the raw GPU trace, which Razor loads exactly like a saved
`.pmon` (loader `FUN_101d71a0`, model `FUN_101d5630` `CPSP2...psp2datasetpatrace.cpp`). Loading fails cleanly with `Failed to load GPU Trace, unsupported v%d.%d .pmon
file` (rt_strings 1461/2121).

### 3.1 File header (verified, `FUN_101cee80`, `FUN_101ce280`)

```
+0x00  0xE0 bytes  primary header, first dword MAGIC = 0x4E4F4D50  ("PMON", little-endian)
       +0x18 u32   version   (offset 0x418 in the object = header+0x0c ... field read at obj+0x418)
                    version < 0x10002            -> error 0x6d  ("unsupported old .pmon")
                    0x10002 <= version <= 0x10003 -> OK
                    version >= 0x10004           -> error 0x7c  ("unsupported .pmon")
       +0x1a u16   (minor, printed in the version message)
if version >= 0x10002: a 0x10-byte secondary header follows,
       first dword MAGIC = 0x4E4F4D51  ("PMNQ")           (FUN_101cee80 @ 0x101cef..)
```
`FUN_101ce280` throws `Header invalid` (`psp2pmontrace.cpp:0x8a`) unless the leading dword is
`0x4E4F4D50`. So the minimum valid GPU file starts `50 4D 4F 4E` ("PMON").

### 3.2 Body = the SAME PA frame/slot container as the CPU trace

The `.pmon` data section is read through the identical container as `RAZOR_PA_TRACE_FORMAT.md` §2:
0x80-byte frames, 8x16-byte slots, `0x7e` timestamp slots, `desc = (type<<8)|chan`. The record
counter `FUN_101ce170` walks 16-byte units; unit 0 of each frame is header/timestamp, units 1..7
are slots whose `type = (u16desc >> 8) & 0x7f`. Per-slot-type parser objects are
registered in a 0x100-entry table `obj+0x50c + type*8` (`FUN_101cd800`/`FUN_101cee60`), and dispatched by `FUN_101cec80` per 16-byte packet. Three parser subclasses
are installed (`FUN_101cd800`):

| slot type | parser subclass (vftable) | ctor | role |
|---|---|---|---|
| **0x7f** | `PmonPacketParserBookmark` (`0x105221e4`) | `FUN_101bcb40`? see note | 64-bit **bookmarks** (GPU Frame/Scene/PID) |
| **0x61** | `PmonPacketParserGpuCounted` (`0x105221f4`) | `FUN_101bcaa0` | counted PMON data (0x218-byte state) |
| **0x60** | `PmonPacketParserGpuSampled` (`0x10522204`) | `FUN_101bcb40` | sampled PMON data (0x38-byte state) |

(`FUN_101cda10` sizes the working buffer as `bm*0x10 + counted*0x208 + sampled*0x28 + 0x52c`,
confirming counts of each type via `FUN_101ce3b0(0x7f/0x61/0x60)`.) The GPU bookmark
channels of §1 arrive as type-0x7f slots here; the fields `RAZOR_GPU_0..3`/`RAZOR_KERNEL_GPU_0..3`
are just the `chan` low byte of those slots.

### 3.3 Bookmark reassembly - `PmonPacketParserBookmark::AddWord` `FUN_101bc930`

Per 16-byte type-0x7f slot record `R`, with the parser's accumulator at `obj[3] (=0xc)`:

- If `R[1] & 0x80 == 0` it is a **timestamped bookmark head**: store
  `acc[0]=u32 R+2` (bookmark word0/low), `acc[1]=u16 R+6` (time-hi), `acc.byte0xc=R[0xc]&0x3f`,
  `acc.byte0xd=R[0xd]&0xf`, `acc.byte0xe=(R[0xd]>>4)&1`, `acc[0x10]=u32 R+0xe` (the data word), then
  `FUN_101bc9d0` appends the assembled 0x10-byte bookmark record to the channel vector.
- Else (`R[1]&0x80`) it is a *continuation* count (`acc[2]++`).
- `obj+0x10/+0x14` track first, `obj+0x18/+0x1c` track last bookmark word0 (time bounds).

This is the GPU-file analogue of `CPMonParser::AddWord`. The header-byte-validation analogue to
`RAZOR_SYSTRACE_FORMAT.md §3` here is only the `bit7` continuation test - there is no per-packet
type/length header check; the GPU bookmark's *meaning* comes entirely from the caption match in §4.
`PmonPacketParserGpuCounted::AddWord` (`FUN_101bcc30`) and `...Sampled` (`FUN_101bcd90`) accumulate
16-bit counter samples into 0x218/0x38 state blocks and flush on a slot-index wrap.

### 3.4 IFF metadata chunks (`FUN_101cddf0`)

After the frame body, if `version >= 0x10003`, Razor parses length-prefixed IFF chunks
(`FUN_101cec50` reads an 8-byte header: `tag = w0 & 0xFFFFFF`, `chunkVersion = (w0>>24)&0x3f`,
`size = w1`). Tags (base `0x1c2b00`):

| tag | handler | body | stores |
|---|---|---|---|
| 0x1c2b00 | (skip) | - | padding/no-op |
| 0x1c2b01 | (end) | - | terminates the chunk loop |
| 0x1c2b02 | `FUN_101ce9d0` | 4 | +0x60=1, +0x64 = u32 |
| 0x1c2b03 | `FUN_101ce930` | 0x20 | +0x68=1, +0x6c.. (8xu32) |
| 0x1c2b04 | `FUN_101cea20` | 0xc | +0x8c=1, +0x90 u32, +0x94/0x96/0x98 u16 |
| 0x1c2b05 | `FUN_101ceb60` | 0xc | +0x9c=1, six u16 at +0x9e.. |
| 0x1c2b06 | `FUN_101cec00` | 4 | +0xaa=1, +0xac u16 |
| 0x1c2b07 | `FUN_101ceab0` | 0x34 | +0xb0=1, +0xb4 u32, a 0x20-wchar name at +0xb8, +0xf8..+0x104 |
| 0x1c2b08 | `FUN_101ce850` | 0x120 | +0x108=1, 8x {u32 + 0x20-wchar name} |
| other | (skip `size-8`) | var | "Skipping unrecognised GPU Trace IFF chunk (tag 0x%08x, version %d, size %d)" |

**Interpretation:** these carry capture metadata (clock/GPU-model/metric-group names - the 0x1c2b07
/0x1c2b08 name blocks look like the metric group + per-core USSE names). They are optional for the
container to parse but the metric group they name gates correlation (§4). Failure paths:
`Failed to parse GPU Trace IFF header/chunk`, `GPU Trace IFF parsing aborted`.

---

## 4. What must be present for the GPU rows to appear
After the `.pmon` is parsed, `FUN_10201820` validates correlation and
`FUN_10202000`/`FUN_10204da0` build the per-job intervals. The row builders are `PmonQueries::
CreateFrameJobActivityIntervals` (`FUN_1020c490`). Required, in order:

1. **CPU Frame bookmarks.** `FUN_101d5630` looks up `[ARM] CPU Frame (sceGxmPadHeartbeat)`
   (caption search `FUN_101bfa30`, `FUN_101c1540`) and if the GPU trace yields none,
   `FUN_101d4fd0` logs **"No CPU Frame Bookmarks found in GPU Trace!"** and the frames come out empty.
   These A8/`b0bafe77` bookmarks live on the **CPU** side; they are the shared
   clock. Emit one per `sceGxmPadHeartBeat()`/frame.

2. **Nine GPU bookmark captions must resolve** (`FUN_10201820`). Each is searched by
   caption via `FUN_101bfa30`; if any returns -1 -> error resource **0x718**
   ("...Bookmarks.xml is missing some essential GPU Bookmark definitions", rt 1816):
   `GPU Frame (TA)`, `GPU Process ID (TA)`, `GPU Scene (SGXMKIF_TAFLAGS_*)`,
   `GPU Scene (MASTER_VDM_BATCH_NUM)`, `GPU Frame (3D)`, `GPU Frame (SPM)`, `GPU Process ID (3D)`,
   `GPU Scene (SGXMKIF_RENDERFLAGS_*)`, `GPU MT LLS (Num Valid MTs)`. Then each channel's bookmark
   vector must be **non-empty** (`(end-begin)&~3 != 0`), else error **0x719**.

3. **Metric group must contain the two job-active events for all 4 GPU cores.**
   `FUN_101d3b00("Vertex Processing Job Active",1,0)` and `"Fragment Processing Job Active"` must
   exist, and per-core `FUN_101d3b00(...,0,core)` for core 0..3 must all resolve, else error
   **0x71a** = "...the GPU Trace Metrics Group must include Vertex and Fragment Processing Job Active"
   (rt 1818). These events are the `Overview Jobs` metrics `PERF_OVERVIEW_n_PERF_TA_PROCESSING` /
   `PERF_3D_PROCESSING` (embedded `metrics_embedded.xml`, RCDATA 1400/1401). They come from the
   PMON counted/sampled data (D-bus masks in the 0x48 CreateGpuTrace body).

4. **Enough data.** `FUN_10201740` requires each job list stride 0xf8 to divide evenly / be
   non-empty, else error **0x71b** -> "...the GPU Trace is too small. Try triggering a new GPU Trace
   with a greater size" (rt 1819).

**Per-job build & the fields that must match (`FUN_1020c490`).** For every job record
(0xf8-byte vertex/fragment job), a job is emitted onto the timeline only if it survives these gates,
each of which logs "PmonQueries::CreateFrameJobActivityIntervals ... skipping Vertex/Fragment Job of
Frame %d" when it fails:
- **Process ID present**: `job+0x58 bit6` set (else "missing Process Id"); and when the pid filter
  bit (`param&0x40`/`0x10`) is on, `job+0x60` (the job's process id) must equal / differ from the
  traced process `raw+4 -> +8`. **So GPU jobs are filtered to the traced pid.**
- **Frame number present**: `job+0x58 bit5` set (else "missing Frame Number").
- **Timestamps present**: `job+0x58 & 0x1f == 0x1f` (all five sub-fields valid) else "missing
  Timestamps". The interval is `[job+0x30.. , job+0x34..]` (u64 start) and `[job+0x08, job+0x0c]`
  (u64 end), clamped to the query window.
`FUN_10202000`/`FUN_10204da0` assemble the 0x78-byte `PmonVertexJob`/`PmonFragmentJob` (vtables
`0x10555e80`/`0x10555e98`) from the four scene/pid/frame bookmark streams, packing per job:
`frame# (bookmark payload &0xffffff)`, `TAFLAGS/RENDERFLAGS (&0xffffff)`, `MASTER_VDM_BATCH_NUM
(&0xfffffff)`, `pid`, and the vertex/fragment timestamps. Frame numbers are matched
between TA/3D bookmarks and the CPU Frame bookmark timeline by *time order* (monotonic), not by an
embedded equality check.

**What aborts the whole GPU pass** (analogous to `cpu>3` aborting the systrace): a missing/parse-
failed `.pmon` header (`FUN_101ce280` throws), IFF parse failure, any of the four correlation errors
0x718-0x71b above, or "No CPU Frame Bookmarks". None of these abort the *CPU* trace - the GPU trace
is independent - they just leave the GPU rows empty with the logged reason.

**UI row resource names** (string resources): timeline group `GPU Trace Timeline`
(rt 256), rows `GPU All Activity` (35088), `GPU Pipeline Activity` (35089/35091),
`GPU Activity (Event)` (35092), `GPU Activity (Ranged)` (35093), `GPU Flip`/`GPU Flip Request`
(1742/34262), plus data sources `GPUSummary::FramesDataSource`, `GPUTraceDataSource`,
`FrameOverviewVp/FpPie/BarDataSource` (vertex/fragment split), `GPU Frame (TA)` / `GPU Frame (3D)`
bookmark rows.

---

## 5. `master` interpretation on the GPU channels

For CPU channels (`RAZOR_PA_TRACE_FORMAT.md`) `master-1` is the CPU core. For the GPU bookmark
channels the `master` field of the 64-bit bookmark is **not** interpreted as a CPU core by this DLL,
because these bookmarks are never read from the PA buffer (§0). Inside the `.pmon`, the GPU job's
core identity comes from **which metric-group slot** (`Vertex/Fragment Processing Job Active` per
core 0..3, `FUN_101d3b00(...,0,core)`) and from the D-bus enable arrays in the 0x48 CreateGpuTrace
body - i.e. from the counted PMON data, not from a bookmark master field. **Interpretation:** the
GPU has four USSE pipes (`USSE 0..3`) that map to the four `RAZOR_GPU_0..3` / `RAZOR_KERNEL_GPU_0..3`
channels; a job's "core" is its pipe index. Vertex work = TA/`GPU Frame (TA)`; fragment work =
3D/`GPU Frame (3D)`. This split is explicit in `metricgroups_embedded.xml`
(`SceRazorGpuLiveEntryJobVertexValues*` vs `...FragmentValues*`, and SDK `razor_hud.h`
`SCE_RAZOR_LIVE_TRACE_METRIC_JOB_TYPE_VERTEX0..3` = 7,1,3,5 / `FRAGMENT0..3` = 8,2,4,6).

---

## 6. User markers on RAZOR_CPU_USER (FIFO A regno 9)
`ProcessMainTraceBufferUser` `FUN_10219300(mode, buf)` runs for mode 1 (`FUN_1021a640`
then `FUN_1021bea0`) and mode 2 (`FUN_1021b150`), after the mandatory scheduler pass. The record
reader is `FUN_10216820` driven from `FUN_1021c740`; the packet-collector is
`FUN_10217ee0`/`FUN_1021c850`. Everything reads **FIFO A regno 9** (`FUN_10217d50(0,9,..)`).

**Record header (verified, `FUN_10216820`).** The *first* CPU_USER bookmark of a record carries the
header in its data word (word1): `type = (word1 >> 16) & 0xf` must be **1, 2 or 3**
(`uVar7-1 < 3`); `len = word1 & 0xffff` must be `<= 0x200` (512). Word-count read after the header
is `((len & 0xffff) + 3 >> 2) + 1`; each subsequent CPU_USER bookmark contributes its word1.

- **type 1** - thread-scoped marker: after collecting words, `FUN_1019d140`/`FUN_10077250` look the
  value up in the process/thread map (`raw+0x30`, `proc[6]`); `local_10` is compared to a thread id.
  **Interpretation:** push/marker bound to a thread id.
- **type 2** - **named** marker: the payload bytes are validated as a printable/So string - the big
  byte-range test at `0x10216940` accepts bytes `0x08..0x7,0x9..0xd,0x0f..0x12,0x40..0x42,0x50..0x51,
  0x60..0x68,0x6e,0x70..0x74,0x80..0x86,0x8a..0x8b,0x90..0x93` and a wrap range - i.e. the name is
  stored **inline as characters in the data words**, not as a string-table id. A byte outside the
  set makes the record invalid.
- **type 3** - pop/close: validates `field < 0x10000` and `field < 7` (a stack-level / small index).

`FUN_1021c850(2,3,...)` collects records of nibble-type 2 or 3 (name + pop) and `FUN_1021bea0(1,4,
...)` collects the mode-1 set. The assembled marker record is allocated by `FUN_10216740` (same pool
allocator as GPU jobs) and pushed with header word `0x00110001` family into per-thread vectors.

**So a game can emit named CPU scopes** by writing CPU_USER (FIFO A regno 9) bookmarks: a type-2
record whose data words spell the name in-line, opened at push and matched by a type-3 pop, all
attributed to the running (pid,tid) via the scheduler intervals. This mirrors the SDK
`sceRazorCpuPushMarkerWithHud(label,color,flags)` / `sceRazorCpuPopMarker()` API
(`libperf.h`; the separate `sceRazorCpuStartUserMarkerTrace` ring uses a different 24-byte
`SceRazorCpuUserMarkerTracePacket {u32 header; u32 threadId; u32 stackLevel; u32 color; u64
timestamp}` which is NOT the bookmark path). The exact byte packing of the name across word1 of
successive bookmarks was not fully reversed (see open questions).

---

## 7. Encoder recipe

### 7.1 To make GPU-activity rows appear against a CPU trace

Because the GPU timeline is a separate `.pmon` merged by timestamp, the minimum is:

1. **On the CPU side**, in the ARM PA trace buffer, additionally emit the CPU-frame bookmark once
   per frame on **FIFO A regno 8** (RAZOR_GPU_GENERAL): `word1 = 0xB0BAFE77` exactly (TypeMask
   ffffffff). Without it: "No CPU Frame Bookmarks found in GPU Trace!" and no frames.
2. **Answer PAMP `CreateGpuTrace`** (cmd 4 sub 2, 0x48 body) with OK, and on `FetchTraceData` return
   a `.pmon` blob:
   - header `50 4D 4F 4E` ("PMON") + 0xE0-byte header, version field = `0x00010003`
     (0x10002 or 0x10003 accepted; **not** >= 0x10004);
   - `51 4D 4F 4E` ("PMNQ") + 0x10-byte secondary header;
   - a PA-frame body (0x80 frames; start with a `0x7e` timestamp slot) carrying, per GPU job on
     **FIFO B regno 2** (RAZOR_KERNEL_GPU_0), type-0x7f bookmark slots for each required caption:
     `GPU Frame (TA)` word1=`0x10000000|frame`, `GPU Process ID (TA)` word1=`0x30000000|pid`,
     `GPU Scene (SGXMKIF_TAFLAGS_*)` word1=`0x20000000|flags`, `GPU Scene (MASTER_VDM_BATCH_NUM)`
     word1=`0x40000000|batch`, and the fragment counterparts (`0x11000000`, `0x34000000`,
     `0x50000000`), `GPU Frame (SPM)` `0x12000000`, `GPU MT LLS` `0x14000000`; each job needs
     start+end timestamps (two bookmarks bracketing the job) so `job+0x58 & 0x1f == 0x1f`;
   - counted/sampled PMON slots (type 0x61/0x60) providing the `Vertex/Fragment Processing Job
     Active` metric per core 0..3;
   - IFF chunks (tag base 0x1c2b00, `0x1c2b01` to end) naming a metric group that includes those
     two job-active events for all four cores.
   - pid in every `GPU Process ID` bookmark = the traced process id (jobs of other pids are dropped).

This is a large synthesis; the CPU-frame bookmark (step 1) alone is cheap and is what unblocks
correlation once a `.pmon` exists.

### 7.2 To emit a named CPU scope (user marker, works today via the CPU PA path)

On **FIFO A regno 9** (RAZOR_CPU_USER), inside an on-CPU interval of the calling thread:
- push/named: first bookmark `word1 = (2 << 16) | len`, then `ceil(len/4)` bookmarks whose word1
  bytes spell the ASCII name (bytes must be in the printable set of `FUN_10216820`);
- pop: a bookmark `word1 = (3 << 16) | level` with `level < 7`.
Attribution uses the same (pid,tid) scheduler intervals as `RAZOR_SYSTRACE_FORMAT.md`.

---

## 8. Open questions

- The exact byte packing of a user-marker **name** across successive CPU_USER word1s
  (`FUN_10217ee0`/`FUN_10216820` collect words but the char-to-word mapping and the color/flags
  fields were not fully reversed; the printable-char validation is proven, the layout is not).
- The `nControl` bitfield and the D-bus/condition mask semantics in the 0x48 `CreateGpuTrace` body
  (names are from the typelib; bit meanings are SGX-uKernel internal and not decoded).
- The precise 0xE0-byte PMON header fields beyond MAGIC+version, and the 0x10 PMNQ header fields.
- Whether the GPU-job start/end come from paired bookmarks or from the counted PMON job-active
  edges - `FUN_1020c490` reads `job+0x08/0x30` timestamps; how those job records are populated from
  the raw slots (`FUN_10202000`) was traced structurally but the per-field source in the raw stream
  is only partially mapped.
- The 16-byte `GetGpuSampledData` layout is interpreted (GRBM+GRBM2+timestamp) from strings, not
  from a decoded writer.
- On a retail target, whether `_sceKernelPaAddGpuTrace`/`AddGpuTraceByKey` (NIDs 0x935181AD /
  0xD285D137, syscall entries 543/530) are reachable at all - these are the kernel side that would
  actually produce a `.pmon`; not investigated on-device.

## 9. Function / data index

| addr | role |
|---|---|
| `FUN_1020fe20` | CPMonParser ctor; only call `(buf,1,6)` = SYS_0 |
| `FUN_10217d50` / `FUN_1021c590` | PA bookmark iterators; only A/9, A/15, B/6 |
| `FUN_102180c0` | GetTraceBufferPerThread; sole caller `FUN_10218fa0` uses A/15 |
| `FUN_10217ee0` / `FUN_10216820` | CPU_USER (A/9) packet reader + record validator |
| `tm!FUN_1400dcbe0` | psp2tm CreateGpuTrace encoder (cmd 4 sub 2, 0x48 body) |
| `tm!FUN_140088560` / `tm!FUN_140088910` | send CreateGpuTrace (4) / GetGpuSampledData (0x10) |
| `api!FUN_1008a410` | GPU-trace request field printer (Control/SampleRate/...masks) |
| `api!CCreateGpuTraceRequest` `0x1015f5d0` / `api!CGetGpuSampledDataResponse` `0x1015fef4` | request/response classes |
| `FUN_101d71a0` / `FUN_101d5630` | .pmon loader / dataset builder |
| `FUN_101ce280` / `FUN_101cee80` | .pmon "PMON"/"PMNQ" header validate |
| `FUN_101ce170` / `FUN_101cec80` | frame/slot walker + per-packet dispatch |
| `FUN_101cddf0` | IFF chunk parser (tags 0x1c2b00..08) |
| `PmonPacketParserBookmark/GpuCounted/GpuSampled` `0x105221e4/f4/0x10522204` | type 0x7f/0x61/0x60 slot parsers |
| `FUN_101bc930` | bookmark AddWord (assemble 0x10-byte bookmark) |
| `FUN_10201820` | correlation validation (errors 0x718/0x719/0x71a) |
| `FUN_10201740` | "too small" check (error 0x71b) |
| `FUN_1020c490` | `PmonQueries::CreateFrameJobActivityIntervals` (pid/frame/timestamp gates) |
| `FUN_10202000`/`FUN_10204da0` | build PmonVertexJob / PmonFragmentJob (0x78) |
| `FUN_101d4fd0` | "No CPU Frame Bookmarks found in GPU Trace!" |
| `0x1065bb08` | embedded syscall-name table (0xad1 x 0x40 entries; `ghidra/syscall_table.txt`) |
| RCDATA 1400/1401/1402 | RazorMetrics / MetricGroups / Bookmarks XML (`ghidra/*_embedded.xml`) |
