# PMON_SYNTH - synthesising a Razor GPU trace (.pmon) from the GXM GPU CSV

Companion to `RAZOR_GPU_TRACE_FORMAT.md`. Tool: `tools/pmon_synth.py`. Verified against
PSP2Razor.dll 3.60.0.5 by decompile and by loading the output in `PSP2Razor.exe` offline.

## Round 4: 0x71a solved, Razor logs no GPU-trace error

Rounds 1-3 below are kept for the history; where they disagree, this section wins.

| Razor run (log only) | file | ERROR lines |
|---|---|---|
| baseline | round-3 `synth.pmon` | "System Software 2.500" + **0x71a** |
| 1 | + all 256 counted channels | 2.500 + **0x71b "GPU Trace is too small"** |
| 2 | + job/bookmark rules below | 2.500 only |
| 3 | + `sceGxmKick()` bookmarks | **none** |

The synthetic CSV now gives 179 vertex + 179 fragment jobs, all complete, frames 501-559 without gaps
(`tools/check_pmon.py`, an offline model of the checks below; the rows were not yet looked at in the UI).

**Root cause.** `Vertex="y"` was a red herring: the XML loader `FUN_101ca2d0` stores it as flag 0x10 and
nothing tests it. The three Overview event metrics are `Sampled="n"`, so the evaluator `FUN_101c7540`
reads them from the **counted** (0x61) stream, at column = the metric's *sampled position*
(`(e + core*8)*8 + bit`, map at metric set +0x28, lookups 0x101c87eb/0x101c832e/0x101c8470/0x101c8a19).
The counted loader (`FUN_101bcc30` / `FUN_101bce70` / `FUN_101ce4a0`) stores values by their order among
the *enabled* counted bits (header +0x34..+0x53), so the two numberings only agree when **all 256 counted
bits are enabled**. Rounds 1-3 enabled one bit and sent 0, i.e. core-0 "Vertex Processing Job Active" had
no activity (no entry -> 0x71a); Fragment and Firmware were read past the one-column buffer (the ~50 %
garbage bars of round 3).

Metric flag word (`FUN_101ca2d0`, metric[7]): 1 Core0, 2 Sampled, 4 !Verified, 8 Percentage,
0x10/0x20/0x40 Vertex/Fragment/Firmware, 0x80 Hidden, 0x100 TileYX, 0x200 EventCondition "c",
0x400 pulse, 0x800 EventAggregation (combined entry), 0x1000/0x2000/0x4000 event type generic/draw/tile.

**Bar rule** (`FUN_101c7540`): for sample i >= 1 a non-zero counted value opens a bar at `ts[i-1]`, zero
closes it at `ts[i-1]`, an open bar closes at `ts[n-1]`; the combined entry (0x800) is the union of the
per-core bars (touching bars are not merged). So a counted value = active cycles in `(t[i-1], t[i]]`.

**Next gates, decoded:**

- 0x71b (`FUN_10201740`): some process must own at least one 0xf8 frame.
- `FUN_10204da0` / `FUN_10202000` build one job per *combined* bar; `FUN_101ff8e0` sets bit 4 plus one bit
  per core whose bar lies inside it, and `FUN_1020c490` needs `job+0x58 & 0x1f == 0x1f`: **every job must
  be active on all four GPU cores.**
- Bookmarks are consumed in order, one per job, at or before the bar's end: Frame (TA) or, for 3D, the
  earlier of Frame (3D) / Frame (SPM) (payload `& 0xffffff`, flag 0x20; SPM also sets `job+0x74`, which
  keeps the scene open, so do not emit it); **Process ID is a pair** (flag 0x40):
  `pid = second << 16 | (u16)first`, the second with payload bit 25 set; TAFLAGS/RENDERFLAGS
  (`& 0xfffffff`, flag 0x80, `+0x68`); VDM (flag 0x100, `& 0x1fff`) must lie in [this bar's end, next
  bar's start]; MT LLS sets 0x300 (`+0x6c` count, `+0x70` index).
- Scenes (`FUN_102044a0`): a TA job needs flags 0x1f|0x20|0x40|0x80 and closes its scene on TAFLAGS bit 1
  (bits 22-26 clear); a 3D job additionally needs RENDERFLAGS bit 13 or flag 0x100 and closes when bits
  13-15 are clear and `+0x74 == 0`. Each pid's **first frame is dropped**. TA and 3D scenes pair by
  (frame, pid, index). `FUN_10202990` numbers frames `first + i`, so frame numbers must be consecutive.
- The "System Software 2.500" note (`FUN_101be9b0` -> `FUN_101bf780`) wants at least one
  `sceGxmKick() Begin/End` pair on A8 (0x1d000000 / 0x1e000000).

**What `pmon_synth.py` now writes:** counted masks all ones; one sampled + one counted packet (256 u16 in
1 + 32 slots) per instant; per scene one TA job `[endcall, submit]` and one 3D job
`[max(submit, prev done), done]`, same-kind jobs at least 1 us apart, each active on all 4 cores
(`--cores`), plus a 20 us Firmware Active pulse on core 0 per job (`--firmware-us`); TA job: Frame (TA),
PID pair, TAFLAGS 0x3 at start, VDM at end; 3D job: MT LLS(1), Frame (3D), PID pair, RENDERFLAGS 0;
A8 kick Begin/End at endcall/submit. The file is ~10x larger (115 KB -> 1.19 MB for 60 frames), almost
all counted packets.

Approximations: all four cores busy per job, synthetic firmware pulse, fixed flag values, kick window.

## Result (evidence)

`python tools/pmon_synth.py gxm_gpu_synthetic.csv synth.pmon`
(180 scenes, 60 frames, 2029 bookmarks, 37360 bytes, version 0x10002, pid 0x40010003).

(Round 1 figures; round 2 adds display/libgxm bookmarks and sampled+counted metric data:
180 scenes, 60 frames, 2627 bookmarks, 364 jobs, 909 samples, 114800 bytes.)

Loaded offline via the registry-declared invocation
`"C:\Program Files (x86)\SCE\PSP2\Tools\Razor\bin\PSP2Razor.exe" "<file>"`
(HKLM\SOFTWARE\WOW6432Node\SCE\Common\Razor Launcher\x86\Vita: Handler=PSP2Razor.dll,
Invoke=PSP2Razor.exe "%1"). Log lines (`%LOCALAPPDATA%\SCE\Razor\Razor-<pid>.log`, runs 19292 & 204):

```
ERROR  VSync/Display Flip/Display Service/Scene Construction Event Trace could not be created.
       The GPU Trace must be triggered using System Software 1.800 or later.
ERROR  The GPU Trace could not be correlated, the GPU Trace Metrics Group must include
       Vertex and Fragment Processing Job Active.
```

**The file parses fully**: no "Failed to load GPU Trace", no "Header invalid", no
"Failed to parse GPU Trace IFF", **no "No CPU Frame Bookmarks found in GPU Trace!"**, and
**no "Bookmarks.xml is missing some essential GPU Bookmark definitions" (0x718)**. That means the
PMON/PMNQ header, the PA-frame body, every GPU bookmark (all 9 required captions) and the CPU-frame
bookmark were accepted and correlated by caption. (Round 1 wording said the blocker was missing
metric data; rounds 2-3 showed the sampled/counted streams do parse and evaluate - the real blocker
is narrower, see "Remaining blocker after round 3".)

The round-1 screenshot caught only the desktop; round 3 captures Razor's own window properly -
see "Round 3: what Razor displays" below.

## Header layout used (verified `FUN_101cee80` @ 0x101ceec0, disasm)

```
off    size  field
0x00   u32   MAGIC 'PMON' = 0x4E4F4D50                 (must match; else "Header invalid")
0x0C   u32   version   (read at obj+0x418). 0x10002 or 0x10003 accepted; <=0x10001 or >=0x10004 fail.
0x0E   u16   minor = high half of the version dword (version 0x10002 -> +0x0E = 0x0001)
0x10   u32   flags     (obj+0x41c; bit3 -> data length taken from +0x24 instead of +0x14/-0x20)
0x14   u32   dataEndOffset   (obj+0x420)   -- data byte length = end - start
0x20   u32   dataStartOffset (obj+0x42c)   -- we use 0xF0 (right after PMON+PMNQ)
0x30   u16   counted sample period (obj+0x43c)
0x32   u16   sampled sample period (obj+0x43e)  -- set equal to avoid the "period !=" warning
= 0xE0 bytes; remaining fields (condition/DBus masks at +0x74/+0x84/+0x94/+0xa4, clocks) left 0.
then 0x10 bytes PMNQ: dword0 MAGIC 'PMNQ' = 0x4E4F4D51 (required when version>=0x10002); rest 0.
```
Chose **version 0x10002**: `FUN_101cddf0` skips the separate IFF-chunk buffer path when
`version < 0x10003`, so the frame/bookmark body alone drives correlation (no second buffer needed).

## Body / slot encoding (verified)

The data section is a PS Vita PA trace buffer - 0x80-byte frames, read as 8x 16-byte records per
frame by `FUN_101cec80`: record 0 = `u16 pad(0) + 7 descriptors`; records 1..7 = the 7 slots.
`descriptor = (slotType<<8) | chanByte`. Slot type **0x7f** = timestamped bookmark. Slot bytes
(consumed by `PmonPacketParserBookmark::AddWord` `FUN_101bc930`):

```
[0:4]   u32  time_low32   (48-bit tick, low 32)
[4:6]   u16  time_high16  (bits 32..47)          time = (high16<<32)|low32, in 333 MHz ticks
[6:10]  0
[10:12] u16  bmDesc = (fifo<<12) | (regno<<8) | (master & 0x3f)
[12:16] u32  word1 = the bookmark data (matched by TypeMask/TypeValue, FUN_101c2630)
```
`FUN_101c2630`/`FUN_101c2210` derive channel from bmDesc: byte[9]=regno (A: 4..8 valid, B: 2..5),
byte[10]=fifo. The `[ARM] CPU Frame` bookmark is special-cased: fifo A, regno 8, word1 == 0xB0BAFE77.
Times: `ticks = round(us * 333)` (export ClockRate = 333000000; times are absolute ticks, the loader
subtracts the min bookmark time as origin, `FUN_101d5630`).

Bookmarks emitted (word1 = TypeValue | payload; masks from the embedded Bookmarks.xml):
`GPU Frame (TA)=0x10000000|frame`, `(3D)=0x11000000|frame`, `(SPM)=0x12000000|frame`,
`GPU MT LLS=0x14000000|n`, `GPU Process ID (TA)=0x30000000|pid`, `(3D)=0x34000000|pid`,
`GPU Scene TAFLAGS=0x20000000|v`, `RENDERFLAGS=0x50000000|v`, `MASTER_VDM_BATCH_NUM=0x40000000|draws`,
all on FIFO B regno 2 (RAZOR_KERNEL_GPU_0); `[ARM] CPU Frame=0xB0BAFE77` on FIFO A regno 8.

## Mapping choices (the CSV has no hardware GPU data - these are documented approximations)

- **Vertex (TA) job**, GPU core 0, span `[endcall_us, submit_us]`: per scene emit Frame(TA),
  ProcessID(TA), Scene(TAFLAGS=scene index), MASTER_VDM_BATCH_NUM=draws, MT LLS at the start, and a
  closing Frame(TA) at submit_us.
- **Fragment (3D) job**, GPU core 0, span `[max(submit_us, previous-scene done_us), done_us]`
  (the max keeps the 3D window from overlapping the previous scene's completion): emit Frame(3D),
  ProcessID(3D), Scene(RENDERFLAGS=scene index), Frame(SPM) at start, closing Frame(3D) at done_us.
- `done_us == 0` (unknown) -> scene skipped.
- **frame number** = CSV `frame` field (masked into the bookmark payload).
- **pid** constant, default 0x40010003 (any value that is the "traced process"; the job builder
  filters GPU jobs to it - since offline there is no traced pid, the value is cosmetic here).
- One **CPU Frame bookmark** (0xB0BAFE77) per `F` line at `end_us` - placed **inside the .pmon** on
  A8, which is where the loader looks ("No CPU Frame Bookmarks found in GPU Trace!" is gone),
  confirming this is the correct location for the offline path.

## Round 2: metric pipeline + event traces

### Event traces - FIXED (3 of 4 errors gone, 4th downgraded)

The "...Event Trace could not be created. The GPU Trace must be triggered using System Software
1.800 or later." messages are **not** a firmware-version field. `FUN_101bdfb0` looks up the
bookmark captions `sceDisplaySetFrameBuf()` / `_sceDisplayVbStartInterrupt()` (Channels="B3") and
prints that text as the fallback when the definitions resolve but the trace holds no instances.
Emitting them fixed it. `pmon_synth.py` now also emits, per F line on **B3**:
`sceDisplaySetFrameBuf() 0x10000000`, `_sceDisplayVbStartInterrupt() 0x11000000`,
`_sceDisplayWaitVblankStartMulti() Begin 0x12000000 / End 0x13000000`; and per scene on **A8**
`sceGxmBeginScene() 0x10000000` / `sceGxmEndScene() 0x11000000`.

Result: VSync / Display Flip / Display Service errors are **gone**, and Scene Construction is now
built (remaining note: "Created Scene Construction Event Trace without GPU Firmware Submit Events.
The GPU Trace must be triggered using System Software 2.500 or later." - it needs additional
GPU-firmware submit bookmarks, informational only).

### Metric pipeline - decoded, still not committing (error 0x71a persists)

Decoded and implemented this round:

- **Register/bit table** `DAT_1053d988`, 0x10-byte entries `{u32 group, wchar* name, u32 mask, u32 firstBit}`,
  1639 entries, dumped from the DLL:
  `PERF_OVERVIEW_0_PERF_TA_PROCESSING` = **group 0, bit 0**;
  `PERF_OVERVIEW_0_PERF_3D_PROCESSING` = **group 0, bit 1**
  (`PERF_OVERVIEW_1_*` variants = group 1 bits 12/13).
- **Sampled selection** (`FUN_101cc330`): header **+0x74/+0x84/+0x94/+0xa4**, each a `u32[4]`
  indexed by GPU core. Entry `e` (0..7) = low/high u16 of field `e>>1`, u16 = `{byte0 = register
  group, byte1 = first bit}`; it maps 8 consecutive register bits to sampled-stream bit positions
  **`(e + core*8)*8 + bit`**, keyed in the enabled map as `(core<<16)|(group<<8)|(firstBit+bit)`.
  The metric operand address is `(core<<16)|(group<<8)|bit` (`FUN_101cba90` + `FUN_101cf150`), so
  the two match.
- **Metric-group signature** (`FUN_101cb150`): walks the same 8 entries of **core 0**, accumulating
  byte0s into one u64 and byte1s into another, first entry in the most-significant byte. Programming
  the "Overview" group from `metricgroups_embedded.xml`
  (`TraceGroups=0000000002020202`, `TraceCounters=0008101800081018`) therefore needs
  entries `(g0,s0x00)(g0,s0x08)(g0,s0x10)(g0,s0x18)(g2,s0x00)(g2,s0x08)(g2,s0x10)(g2,s0x18)`
  -> field values `0x08000000, 0x18001000, 0x08020002, 0x18021002` replicated for all 4 cores.
  This is what `pmon_synth.py` writes, and it reproduces the XML signature exactly.
- **Sampled slot packets** (type 0x60, `FUN_101bcd90` / flush `FUN_101bcf50`): 8 u32 = 256 bits =
  4 cores x 64 bits, delivered over 3 slots - slot0 (desc low byte 0) `[0:4] time_low32,
  [4:6] time_high16, [6:8] pad, [8:16] dwords 0-1`; slot1 (low byte 1) `dwords 2-5`;
  slot2 (low byte 2) `dwords 6-7`. Flush stores 16 u16 column-major (channel k, sample i).
  So core c TA_PROCESSING = bit `c*64`, 3D_PROCESSING = bit `c*64+1` (dword0 bits 0/1 for core 0).
- **Counted slot packets** (type 0x61, `FUN_101bcc30` / flush `FUN_101bce70`) and the counted enable
  masks at header **+0x34..+0x53** (8 u32; `FUN_101ce3e0` popcount = values per packet). First slot
  = `[0:4] time_low32, [4:6] time_high16, [6:16] five u16 values`, continuation slots 8 u16 each.
  These matter because `FUN_101cd9e0` sizes the metric-result buffer as
  `(metricCount+1) * FUN_101ce260() * 8`, and `FUN_101ce260` returns the **counted** sample count -
  with zero counted samples there is nowhere to write results. We now enable one counted counter and
  emit one counted packet per sampled instant.
- **Evaluator commit rule** (`FUN_101c7540`): a metric entry (0x10 bytes `{result, metric, coreFlag}`)
  is only counted (`param_2[5]++`, the count read back at `model+0x108+0x14`) when its result
  pointer is non-zero, i.e. the metric actually produced data; the combined (`coreFlag=1`) entry is
  appended only if per-core entries exist and the metric has attribute bit `0x800`.
  `FUN_10201820` demands a per-core entry for **all four** cores plus a combined one - so we give
  cores 1-3 a short pulse (`core_blip_us`, default 10 us) since a permanently idle core produces no
  events. The evaluator gate `DAT_106e7391` is set unconditionally by `FUN_101cb630`, and the metric
  XML is loaded from **embedded RCDATA 0x578 (1400) and 0x579 (1401)** first, with optional
  `Metrics\*.xml` overrides - so metric definitions are always present (this install has no
  `Metrics` directory, which is fine).

### Remaining blocker (precise)

With all of the above in the file, Razor still logs
`The GPU Trace could not be correlated, the GPU Trace Metrics Group must include Vertex and Fragment
Processing Job Active.` (error resource 0x71a, emitted by `FUN_10201820` @ 0x10201dab when
`FUN_101d3b00(L"Vertex Processing Job Active",1,0)` or any per-core lookup returns -1).

Everything feeding that lookup checks out statically: the operand-address / enabled-map key formulas
agree, the group signature matches the XML, the sampled and counted streams parse with the exact
slot layouts above. So the failure is inside **`FUN_101c7540`** (~1500 instructions) - it is not
committing a result for these metrics. To finish, the next round needs:

1. `FUN_101c7540` decoded end-to-end: how it walks the counted-sample timeline, how it fetches a
   sampled bit for a given metric operand (the `local_50`/`ppiVar12` result-array indexing at
   0x101c7600-0x101c7700), and exactly what it stores in entry+0 so the entry commits.
2. The metric-object layout from the XML loader `FUN_101ca2d0` / `FUN_101c9200`: fields `[5]`
   (category 0/1/2 -> which of the three vectors at metric-set +4/+0x10/+0x1c), `[6]` (core),
   `[7]`/`+0x1c` flag bits (0x2 = Sampled, 0x400 = EventCondition, 0x800 = combined-entry), and
   the operand flag encoding (`0xa000000` = skip check, `0xe000000` = metric reference).
3. Whether the per-core expansion of a `Core0="n"` metric happens at XML load or in the evaluator
   (this decides whether cores 1-3 can ever produce entries from a synthetic trace).

Measured against the alternative, this is the only part of the GPU-trace path still unknown; the
container, bookmark, correlation-gate and event-trace layers are all verified working.

## Round 3: what Razor displays (screenshots)

`synth.pmon` with View = **GPU Trace Timeline**, captured from
Razor's own window (foregrounded via `MainWindowHandle`+`SetForegroundWindow`, window rect only).
Getting there: the file opens as a document tab **`synth.rzr`**; `View:` has exactly two entries,
`Summary` and `GPU Trace Timeline`.

**Rendered and correct:**

- **Time ruler 0 -> 1.800 s** matching the CSV span, and a red **frame band with frame numbers**
  (1,2,3,4,5,6,7,8,9 ... 20 ... 24 ... 34 ...) - one per `F` line, i.e. the `[ARM] CPU Frame`
  (0xB0BAFE77) bookmarks are parsed, timestamped and numbered correctly.
- **CPU Events Group** with four populated rows: **VSync**, **Display Flip**, **Display Service**,
  **Scene Construction** - from the B3 display bookmarks and A8 `sceGxmBeginScene/EndScene`
  (Scene Construction is visibly denser, 3 scenes per frame, as in the CSV).
- **Events Group**: **Fragment Processing Job Active - Utilization 50.886%, Event Time 957.092 ms**
  and **Firmware Active - 50.276%, 945.636 ms**, both drawn as event bars across the timeline.
  So the sampled (0x60) stream *is* parsed and evaluated into event metrics.
- **Metrics Group**: the full counted-metric row set ([0..3] VDM Active, PDS Active, USSE [...],
  DCU Pipe ...) listed at 0.000% - expected, we only enable one dummy counted counter.
- `Summary` view shows **GPU Trace Info**: `File synth.rzr`,
  **`Metrics Group: M0: Overview`**, `Trace Size/Rate: Custom`, correct date and
  `Captured By <user> (from computer <PC name>)`. The `M0: Overview` line is hard proof
  that the metric-group signature built from header +0x74/+0x84/+0x94/+0xa4 is byte-exact.
- `Frames` tab shows the schema (Utilization / Frame Time / Idle Time /
  Active Time / Vertex Processing Time / Fragment Processing Time x Average/Longest/Shortest) but
  **empty cells** - those are gated on the correlation.

So the file is already useful as a GPU-side timeline: real frame boundaries/numbers, per-scene
begin/end and flip/vsync events, and a fragment-activity track derived from the CSV.

## Remaining blocker after round 3

Verbatim, still:
```
ERROR Created Scene Construction Event Trace without GPU Firmware Submit Events. The GPU Trace must be triggered using System Software 2.500 or later.
ERROR The GPU Trace could not be correlated, the GPU Trace Metrics Group must include Vertex and Fragment Processing Job Active.
```
The Overview group declares three event metrics - Vertex Processing Job Active, Fragment Processing
Job Active, Firmware Active. Razor resolves **two**; **"Vertex Processing Job Active" is never
selected**, and `FUN_10201820` needs it, so 0x71a stands.

Experiments that narrow it down (each a real Razor run):

1. **Not a data problem.** A debug build with **all 256 sampled bits set in every sample** still
   showed only Fragment + Firmware. So the metric is rejected at
   *selection* time, not for lack of samples.
2. **Not the position-0 theory.** All three metrics' operands live in the same entry (group 0 bits
   0/1/2 -> stream positions 0/1/2), and I suspected position 0 was unusable. Reordering the entries
   so group 0 starts at entry 4 (TA -> position 32, `--entry-order shifted`) **lost the
   `M0: Overview` match and with it *both* event metrics**. Reverted;
   `--entry-order overview` is the default and is strictly better. Also `FUN_101cba90` compares the
   map *iterator* against end (`*found == *end`), not the value, so a 0 value is legitimately fine.
3. The only XML attribute that distinguishes the missing metric from the two that work is
   **`Vertex="y"`** (Fragment has `Fragment="y"`, Firmware Active has all three `"n"`). Both
   surviving metrics differ from Vertex in exactly that field, which points at a
   vertex/fragment/firmware capability filter applied during selection
   (`FUN_101cb910` / the `local_44` group-filter branch of `FUN_101cba90`), rather than at the
   sampled-bit plumbing - which is demonstrably working for the adjacent bits.

### What a next session would need

- Decode **`FUN_101cba90`**'s group-filter branch (`local_44 != 0` -> `FUN_101cb910`) and the metric
  object's Vertex/Fragment/Firmware attribute bits (set by the XML loader `FUN_101ca2d0`, fields
  `[7]`/`+0x1c`), to find what makes a `Vertex="y"` metric admissible. That is now the single
  unknown standing between this file and job rows.
- Then `FUN_101c7540`'s per-metric result write (what lands at entry+0) only matters if selection
  still yields nothing after that.
- Unknown-but-cosmetic: the "GPU Firmware Submit Events" bookmarks behind the 2.500 message.

## Gaps / remaining work to reach actual job rows

Getting past 0x71a needs the **PMON counted/sampled metric pipeline**, which this CSV cannot feed
and which was not reversed far enough to synthesise reliably:

1. **Counted (type 0x61) / sampled (0x60) slots** carrying the raw SGX PMON counter samples for
   `PERF_OVERVIEW_n_PERF_TA_PROCESSING` and `PERF_3D_PROCESSING` (the "Vertex/Fragment Processing
   Job Active" events, per core 0..3). Parsers `FUN_101bcc30`/`FUN_101bcd90`; the counter-id and
   16-bit sample packing were only structurally mapped.
2. **Metric-group signature** in the header condition/DBus mask fields (`FUN_101cb150` reads
   header+0x74/+0x84/+0x94/+0xa4; `FUN_101cba90`/`FUN_101ccb20` recognise a known group, e.g. the
   "Overview" group `TraceGroups=0000000002020202 TraceCounters=0008101800081018` from the embedded
   MetricGroups XML) so the two job-active metrics are declared available.
3. The metric **expression evaluator** `FUN_101c7540` (~1500 insns) that binds counter data to
   named metrics that `FUN_101d3b00` then finds - not reversed.
4. The "System Software 1.800" event-trace warnings are secondary (VSync/Flip/Scene Construction
   built from A8/B3 libgxm/display bookmarks + a version gate); they do not block job rows, only the
   extra event-trace rows. Adding those bookmarks + bumping to a higher version field would clear
   them but is orthogonal to 0x71a.

So this proves the **container + bookmark + CPU-frame-correlation layer is correct and
accepted by Razor**; the outstanding piece is the hardware-counter metric layer.

## Files
- `tools/pmon_synth.py` - the synthesiser (`<csv> <out.pmon> [--pid N] [--version 0x10002|0x10003]`)
- `tools/check_pmon.py` - offline model of Razor's GPU-trace checks, to test a `.pmon` without Razor
- `plugin/pmon_trace.c` - the same conversion on the console

The Razor screenshots and the scripts that loaded each `.pmon` into PSP2Razor.exe are not committed.
