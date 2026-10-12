# Razor CPU PC-sample / ARM program-flow-trace (PFT) format

How PS Vita Razor (`PSP2Razor.dll` 3.60.0.5, 32-bit, image base `0x10000000`) decodes the
CoreSight PFT (PTM) byte stream inside the PA trace buffer, and the **minimal** byte sequence that
makes its decoder emit exactly one PC sample per record. Companion to
`RAZOR_PA_TRACE_FORMAT.md` (frame container, bookmarks, timebase). Encoder: `tools/pa_pft.py`.

All facts below are from the decompiled/disassembled functions cited (Ghidra project `RAZOR`).
Where the encoding matches ARM IHI 0035 (CoreSight PFT), the ARM name is given, but the field
widths and dispatch are taken from the decompile.

---

## 0. Where the PFT path is entered

`CPSP2SnapShotCaptureData::ProcessTraceData` **FUN_10228e10** runs three buffer passes in order
(disasm at `0x10228fee`, `0x10229010`, ...):

```
FUN_102190c0(0, raw)   // ProcessMainTraceBuffer variant 0  -> scheduler trace  (FUN_1021a080)
FUN_102190c0(1, raw)   // variant 1                         -> user/libperf     (FUN_1021ad20)
FUN_102190c0(5, raw)   // variant 5                         -> PFT PC sample    (FUN_10219450)
```

`ProcessMainTraceBuffer` **FUN_102190c0** first calls `FUN_1021cdb0(raw, variant != 5)`. The 2nd
arg forces "must contain a 0x7e bookmark-timestamp slot" (`FUN_102185a0`). Variant 5 does **not**
require it, but variants 0/1 run first and **do**, so a usable buffer still needs at least one
`0x7e` slot and the scheduler bookmarks that map (cpu,time)->(pid,tid) (see `RAZOR_PA_TRACE_FORMAT.md`
§3 and `FUN_102186d0 LookupThreadId`). PC samples themselves carry no thread id in sample-mode 6.

`ProcessPftPcSample` **FUN_10219450** (`"CPSP2ProcessRawTraceData::ProcessPftPcSample"`) walks the
0x80-byte frames and, per slot descriptor, routes bytes to the ARM-trace de-formatter. After the
whole buffer is de-formatted into four per-CPU PFT streams, it decodes each stream according to the
capture's **sample mode**.

---

## 1. Frame + slot recap, and the slot dispatch (FUN_10219450)

Container is unchanged from `RAZOR_PA_TRACE_FORMAT.md` §2: 0x80-byte frames, `+0x00` u16 header,
`+0x02..+0x0e` seven u16 descriptors, `+0x10..+0x7f` seven 16-byte slots. The dispatch, at
`0x10219597` / decompile lines in `FUN_10219450`:

```
uVar2 = desc[slot]
if (uVar2 & 0x8000)               -> FUN_103efc50   (overflow / wrap marker, §5)
else switch ((uVar2 >> 8) & 0x7f):
    0x10 -> FUN_103edc00          ARM trace, 16 PFT bytes           (this doc)
    0x7c -> FUN_103ef460          bookmark 64x1
    0x7d -> FUN_103ef5e0          bookmark 64x2
    0x7e -> FUN_103ef880          bookmark + timestamp
    0x7f -> FUN_103ef320          bookmark 128
    else -> ignored
```

For a **type 0x10** slot, `desc & 0xff` is the low byte and is only used as a printf channel id
(`"ARM Trace (%d)"`, `FUN_103edc00 @ 0x103edc4d`). It does **not** select the CPU - the CPU is the
CoreSight formatter trace-ID carried *inside* the bytes (§2). Set it to the CPU for readability;
the decoder ignores it.

`desc` for an ARM-trace slot is therefore `(0x10 << 8) | channel` = `0x1000 | cpu`.

---

## 2. The CoreSight formatter de-multiplex (FUN_103edc00 + FUN_103edd70)

The 16 bytes of every type-0x10 slot are **one CoreSight trace-formatter frame** (IHI 0029). The
de-formatter accumulates them into a 0x70-byte buffer (`this+0x10` = write count, reset to 0 at
0x10, `+0x14`/`+0x18` hold source ids) and processes each complete 16-byte frame.

### FUN_103edc00 (per slot)
- For each of the 16 slot bytes: if the running 4-byte window is `FF FF FF 7F` it is a **full-sync
  (FSYNC)** marker (`"Full Synchronaization packet was found!"`, `0x103edcb1`): the accumulator and
  all four source states are reset. **Do not** let this sequence occur inside your data (it would
  desynchronise the formatter). Real user PCs never encode to it after the even-byte bit-strip
  below; `pa_pft.py`'s reference de-formatter raises if it sees one.
- Otherwise the byte is appended; every time 16 bytes accumulate, `FUN_103edd70` is called and the
  count resets (`0x103edd2a`).

### FUN_103edd70 (one 16-byte formatter frame -> source streams)
Standard CoreSight formatter. `frame[15]` is the **aux/flag byte**; `frame[0]` is the first ID/data
slot. For byte index `i` (0..15):

- **Even `i`** (`i & 1 == 0`):
  - if `frame[i] & 1 == 0`: it is a **data** byte for the current source. Its real bit0 is taken
    from `aux >> (i>>1)`, i.e. `data = frame[i] ^ ((aux>>(i>>1))^frame[i]) & 1` (`0x103ede0e`).
    Appended to the current source via `FUN_103eefa0` **only if** the current source id is 1..4.
  - if `frame[i] & 1 == 1`: it is an **ID change**. New id = `frame[i] >> 1`. If `i == 0x0e` or the
    aux bit for this half is 0, the change is immediate (`this+0x14`); else it is *pending* until
    after the following odd byte (`this+0x18`).
- **Odd `i`**: a data byte for the current source, appended verbatim (except `i == 0x0f`, the aux
  byte). A pending id change is applied here.

**Source id = CoreSight trace ID.** IDs 1..4 map to **CPU 0..3** respectively (`FUN_103eb660`/
`FUN_103eb8c0` iterate `uVar2 = 0..3` and read source slot `piVar5[uVar2*3]`; and only ids `1..4`
are captured, `0x103edd8d`/`FUN_103eefa0` guard `1 <= id <= 4`). Encoder: **CPU n -> trace ID n+1.**

**Practical single-source framing** (what `pa_pft.py` emits): put one CPU's bytes in a frame as
`frame[0] = (id<<1)|1` (immediate ID set), `frame[1..14]` = up to 14 payload bytes, `frame[15]` =
aux (bit0 corresponds to data at position 1's bit-strip, etc.), padding payload with `0x66`
(Ignore). This yields exactly 14 PFT bytes/frame for one CPU. Interleaving CPUs in one frame is
legal but unnecessary.

---

## 3. The PFT packet decoder (FUN_103ec9b0 = `decompress_pft_packet`)

Per CPU stream. First `FUN_103ede40` (`"A-sync packet was found"`) scans for the alignment
synchronisation packet: **>= 5 bytes of `0x00` followed by `0x80`** (`0x103ede40`). Decoding
starts right after it; if none is found the stream is skipped (`"[Warning] Cannot find A-sync
packet."`). After any gap/overflow a fresh A-sync is required.

Header-byte dispatch (`FUN_103ec9b0`, mirrored in `pa_pft.razor_decode_pc_samples`):

| header byte | packet | handler | notes |
|---|---|---|---|
| `0x00` | **A-sync** | re-scan `FUN_103ede40` | 6 bytes `00 00 00 00 00 80` |
| `0x08` | **I-sync** (address+context) | `FUN_103ee8f0` -> `FUN_103ebd30` | **the PC record** |
| `0x0C` | Trigger | skip 1 | `"[Trigger]"` |
| `0x66` | Ignore | skip 1 | padding |
| `0x6E` | Context ID | `FUN_103ee890` -> `FUN_103ee3d0` | `"[Context ID]"` |
| `0x72` | Waypoint update | `FUN_103eee10` | `"[Waypoint]"` |
| `0x42`,`0x46` (`b & 0xFB == 0x42`) | Timestamp | `FUN_103eeaa0` -> `FUN_103ec740` | `"[Timestamp]"`, §4 |
| `0x76` | Exception return | skip 1 | `"[Exception return]"` |
| `b & 0x81 == 0x80` (else) | **Atom** (branch history) | `FUN_103ee540` -> `FUN_103ed020` | `"[Atom]"` |
| `b & 1 == 1` (odd) | **Branch address** | `FUN_103ee6e0` -> `FUN_103ed310` | `"[Branch]"` |
| any other even byte | **Unknown** | prints `"Unknown Packet was found at"` and **aborts the whole stream** |

The abort on unknown bytes is the reason a synthetic stream must contain *only* packet types the
decoder knows. Note `0x08` (I-sync), not `0x80`, is the I-sync header; `0x80..0xFE` even are Atoms.

### I-sync parse - FUN_103ebd30
`this` is the small decoder state; `off` is the read offset.

```
addr  = (u24 at off+2) << 8 | (byte[off+1] & 0xFE)   // == LE u32 from off+1, bit0 cleared
+0x10 thumb    = byte[off+1] & 1
+0x11 (ThumbEE)= byte[off+5] >> 3 & 1      // printed "ThumbEE"
+0x12 (NonSec) = byte[off+5] >> 2 & 1      // printed "Non-secure"
reason (out)   = byte[off+5] >> 5 & 3      // 0 Periodic,1 Trace On,2 Overflow,3 Debug
off += 5
if reason != 0 && (traceMode & 0x1000): off += 1; FUN_103ee460  // cycle-count field
if (traceMode & 0xC000):                  off += 1; FUN_103ee3d0 // context id: 1/2/4 bytes
off += 1
```

So a **minimal I-sync is 6 bytes**: `08 | addr[0..3] (LE, bit0=Thumb) | info`, where
`info = 0x80 | (reason<<5) | (nonsecure<<3) | (thumbee<<2)`. Bit7 is set on real hardware; the
decoder does not test it.

- **Cycle-count field** (`FUN_103ee460`, only when `reason != 0 && traceMode & 0x1000`): variable
  length, ARM continuation encoding - byte0 bits `5:2` = cycles[3:0], bit6 = more; then up to 3
  more bytes of 7 bits (bit7 = more); final byte = cycles[31:25]. Encoded by
  `pa_pft.encode_cycle_count`.
- **Context-ID field** (`FUN_103ee3d0`, only when `traceMode & 0xC000`): 1 byte for `0x4000`, 2 for
  `0x8000`, 4 for `0xC000`, little-endian into a 32-bit value.

### What becomes a sample - FUN_103ee8f0
```
if parse ok:
  if (param_5 == 0):                       // CPU-basis path (sample mode 6, from FUN_103eb660)
      if (reason == 1):                    // "Trace On"
          FUN_103f4870(address, sampleMap) //  ++ map<address,count>[address]
  else if (traceMode & 0x1000):            // gprof path (sample mode 5, from FUN_103eb8c0)
      FUN_103ef0e0(...); FUN_103eaee0(...)  // attach a time via per-thread on-CPU intervals
  this+0x13 = 1                            // "I-sync seen": enables branch/atom PC tracking
```
`FUN_103f4870` (`"[%d: Call]"` neighbourhood, actually the histogram inserter) walks a red-black
`map<uint address, {..,count}>` and increments the count, inserting the address if absent. **One
I-sync with reason==Trace On == one PC sample.** cpu/time/thread are dropped in this path.

---

## 4. Sample modes, and where samples land (FUN_10219450 tail)

The capture's decode mode is `*(*(model+8)+4)`, set to **5 or 6** by `FUN_10199430` (§6). In the
tail of `FUN_10219450` (`0x102197df`):

```
iVar6 = *(*(this+8)+4)
if (iVar6 == 6):  FUN_103eb660(streams, ..., &sampleMap, ...)     // decode_arm_trace       (histogram)
if (iVar6 == 5):  FUN_103eb8c0(streams, ..., &sampleVec, ...)     // decode_arm_trace_gprof (time-attributed)
```

### Mode 6 - plain "PC sampling" (FUN_103eb660, `"decode_arm_trace"`)
Loops CPU `0..3`, calls `FUN_103ec9b0(stream, .., cpu, /*param_5*/0, .., &perCpuMap, ..)`. Builds a
per-CPU `map<address,count>` (freed by `FUN_103e9990` after use). Output is a **histogram of PC
addresses**; there is no per-sample time or thread. This is the smallest, self-contained path and
the target of `pa_pft.py` (trace_mode = 0). The addresses are later symbolised against the module
list / ELF by `CPcSampleDataMiniModel::Rebuild` (`FUN_100b3f50`) and
`CPSP2SnapShotCaptureModel::BuildPcSampleSummary` (`FUN_1019dd90`), read as `map` at
`this+0x88`/`+0x4c`.

### Mode 5 - gprof / program flow (FUN_103eb8c0, `"decode_arm_trace_gprof"`)
Calls `FUN_103ec9b0(.., /*param_5*/1, ..)`, so I-syncs, branches and atoms feed a **time-ordered
vector of `{address,time}`** (0x18-byte records built by `FUN_103ef000`/appended in the 0x40-byte
vectors seen in `FUN_10219450`), with time reconstructed from **Timestamp packets** (§4a) and cycle
counts, and clamped against the per-thread on-CPU intervals (`FUN_103eaee0`, globals
`DAT_106ec760..`). Thread basis is a separate pass, `decode_thread_arm_trace` **FUN_103ebe10**
(`"Timestamp at OnCPU (CPU"`), which calls `FUN_103ecd40` per thread and correlates the ARM
timestamp with the bookmark timestamp for the on-CPU interval. This path is heavier and is **not**
what a retail-Vita PC sampler needs.

### 4a. Timestamp packet (FUN_103eeaa0 / FUN_103ec740)
Header `0x42`/`0x46`. Payload = ARM continuation-encoded up-to-7-byte 48/56-bit value
(`FUN_103ec740`: 7 bits/byte, bit7 = more), optional trailing cycle field when `traceMode & 0x1000`.
It sets the running decode time (`"[Timestamp] Timestamp = 0x%012llx"`) and drives the
CPU-frequency drift check `FUN_103eb450`/`FUN_103eebc0` (333 vs 444 MHz). Only used in mode 5 /
thread basis. For sample-mode-6 PC sampling you need **no** Timestamp packets; interleave `0x7e`
bookmark-timestamp *slots* at the frame level instead (needed for the mode-0/1 passes).

---

## 5. `desc & 0x8000` slots - overflow / wrap marker (FUN_103efc50)

Not a PC record. Printed as `"Overflow packet (%d)"` (`desc & 0xff`), `"Type = 0x%02x"`
(`(desc>>8) & 0x7f`), and a `"Timebase = 0x%012llx"` read from the slot payload
(`u32 tbLow, u16 tbHigh`). The per-slot **Type** is `slotDesc_high & 0x7f`:
- `0x50`: a "Master" record - if payload word `& 0x400`, prints `Master : ID = 0x%02x Number = %d`
  (id = `word >> 0xb`).
- `0x10`: an **embedded ARM-trace burst** - resets a private 0x70 accumulator (`FUN_103eac00`),
  builds a 0x10-entry array (`FUN_10490f04(.., 0x10, 4, FUN_10214e90, FUN_10215980)`) and
  de-formats 0x40 bytes via `FUN_103efdf0`. This is how the hardware re-seeds trace after a FIFO
  wrap; it feeds a *separate* accumulator, not the main per-CPU streams.
- else: prints `Number = %d`.

**For synthesis: never set `desc & 0x8000`.** It forces a new trace segment; each CPU stream would
then need a fresh A-sync. `pa_pft.PftSlotEncoder.resync()` exists only for that case.

---

## 6. Capture options: what `CreateArmTrace(traceMode, sampleMode, tsPeriod, samplePeriod, pid)` carries

`FUN_10199430` maps the CPU-capture option (`CCaptureOptions` field, the arg at
`*(opts+0x3a0)`, disasm `0x101b6e68`) to the three ARM-trace fields (`+0x18`,`+0x1c`,`+0x20`), which
`ConfigurePerfmon` **FUN_101ac0b0** copies to `this+0x300..+0x30c` and passes to the TMAPI
`IPerformanceAnalysis::CreateArmTrace` (vtable +0x30, `0x101ac32d`) as
`(nTraceMode = +0x300, nSampleMode = +0x304, nTimestampPeriod = +0x308 & 0xFFFF,
nSamplePeriod = +0x308 >> 16, nProcessId = pid)`:

| option | sampleMode (`+0x1c`/`+0x304`) | traceMode (`+0x18`/`+0x300`) | ts / sample period (`+0x20`/`+0x308`) | decoder |
|---|---|---|---|---|
| `1` (**PC sampling**) | **6** | `0x00000000` | ts=0, sample=`0x3e8`=1000 | `FUN_103eb660` histogram |
| `0` (program flow) | **5** | `0x10001000` (timestamp+cycle) | ts=`0xFFFF`, sample=0 | `FUN_103eb8c0` gprof |
| other | 0 | 0 | 0 | (disabled) |

So **PC sampling uses traceMode 0**: no cycle-accurate bit (`0x1000`), no context-ID bits
(`0xC000`), no timestamp bit. The I-sync stream is therefore the 6-byte minimal form, and Razor's
histogram counts one address per I-sync. Program-flow mode sets `0x10001000` so I-syncs carry a
cycle field and the stream also carries Timestamp packets for time attribution.

`traceMode` is the ARM PTM main-control-register layout; the bits the **decoder** actually reads:
`0x1000` = cycle-accurate (cycle field present on I-sync reason!=0 / branch / atom / timestamp),
`0xC000` = context-ID size (`0x4000`=1B, `0x8000`=2B, `0xC000`=4B). `0x10000000` (timestamp enable)
is set by hardware but not re-read by the decoder.

---

## 7. Minimal encoding of "CPU n executing user PC X at time T in thread Y" (sample mode 6)

Because sample mode 6 produces only a PC histogram, "time T" and "thread Y" are **not** encoded in
the PFT stream at all - they come from the frame-level bookmark timeline and the scheduler passes.
Per PC sample you emit exactly **one 6-byte I-sync** into CPU n's formatter stream:

```
08  a0 a1 a2 a3  info          (a0..a3 = X little-endian, a0 bit0 = Thumb; info = 0x80|(1<<5)|(ns<<3))
```

- At the **start of each CPU stream** (and after any gap/overflow) prepend the 6-byte A-sync
  `00 00 00 00 00 80`.
- Pack the resulting byte stream into 14-byte formatter frames tagged with trace ID `n+1` (§2),
  each frame becoming the 16 bytes of one type-0x10 slot with `desc = 0x1000 | n`.
- No Timestamp / Context-ID / cycle bytes are needed (traceMode = 0).
- The buffer as a whole still needs the `0x7e` bookmark-timestamp slot and scheduler bookmarks for
  the mode-0/1 passes (thread attribution); those are independent of the PFT slots and may be
  interleaved freely between ARM-trace slots.

### Worked example - 3 samples on CPU 0

Samples `(cpu, time48, pc, thumb, ctxid)`:
```
(0, 0x000100000000, 0x81000100, 0, 0)
(0, 0x000100002000, 0x81000235, 1, 0)   # Thumb -> decoded address masks to 0x81000234
(0, 0x000100004000, 0x8100A000, 0, 0)
```

CPU-0 PFT byte stream (A-sync + three 6-byte I-syncs), 24 bytes:
```
00 00 00 00 00 80        A-sync
08 00 01 00 81 a8        I-sync  addr=0x81000100 thumb=0 info=0xa8 (reason=Trace On, NS=1)
08 35 02 00 81 a8        I-sync  addr=0x81000234 thumb=1
08 00 a0 00 81 a8        I-sync  addr=0x8100A000 thumb=0
```

These 24 bytes de-formatted into two 14-byte formatter frames (trace ID 1 = CPU 0), padded with
`0x66` Ignore, become two type-0x10 slots (`desc = 0x1000`):
```
desc=0x1000  03 00 00 00 00 00 80 08 00 01 00 81 a8 08 34 80
desc=0x1000  03 02 00 81 a8 08 00 a0 00 81 a8 66 66 66 66 00
```
(`frame[0]=0x03`=(ID 1<<1)|1; `frame[15]` is the aux byte carrying the stripped bit0 of even-
position data bytes; e.g. first frame aux `0x80` restores bit0 of the byte at position 14.)

Packed into a single 0x80-byte frame (header 0, remaining descriptors 0 = type 0, skipped):
```
00: 00 00 00 10 00 10 00 00 00 00 00 00 00 00 00 00   header + desc[0]=0x1000 desc[1]=0x1000 desc[2..6]=0
10: 03 00 00 00 00 00 80 08 00 01 00 81 a8 08 34 80   slot[0]
20: 03 02 00 81 a8 08 00 a0 00 81 a8 66 66 66 66 00   slot[1]
30: 00 .. 00                                          slot[2..6] unused
```

Razor de-formats slot[0]/slot[1] back to the 24-byte CPU-0 stream, finds the A-sync, and increments
`map[0x81000100]`, `map[0x81000234]`, `map[0x8100A000]` by one each - three PC samples. This is
verified by the reference de-formatter + decoder in `tools/pa_pft.py` (`_selftest`, which also
round-trips 3000 random samples for traceMode 0/0x1000/0x4000/0x8000/0xC000/0x10001000).

---

## 8. Function index

| addr | name / role |
|---|---|
| `FUN_10228e10` | `ProcessTraceData`: runs ProcessMainTraceBuffer variants 0,1,5 |
| `FUN_102190c0` | `ProcessMainTraceBuffer(variant)`; variant 5 -> FUN_10219450 |
| `FUN_1021cdb0` | buffer setup; 2nd arg requires a 0x7e timestamp (variants 0/1) |
| `FUN_10219450` | `ProcessPftPcSample`: slot walk + per-CPU decode dispatch |
| `FUN_103efc50` | overflow / wrap slot (`desc & 0x8000`) |
| `FUN_103edc00` | ARM-trace slot: 16 bytes -> formatter accumulator; FSYNC reset |
| `FUN_103edd70` | CoreSight formatter de-mux; trace ID 1..4 -> CPU 0..3 |
| `FUN_103eb660` | `decode_arm_trace` (sample mode 6, histogram) |
| `FUN_103eb8c0` | `decode_arm_trace_gprof` (sample mode 5, time-attributed) |
| `FUN_103ebe10` | `decode_thread_arm_trace` (thread basis) |
| `FUN_103ec9b0` | `decompress_pft_packet`: packet-header dispatch |
| `FUN_103ecd40` | packet dispatch, thread-basis variant |
| `FUN_103ede40` | A-sync scan (>=5 zeros + 0x80) |
| `FUN_103ee8f0` | I-sync handler; records the PC sample |
| `FUN_103ebd30` | I-sync field parse (address/thumb/reason/cycle/ctxid) |
| `FUN_103ee460` | cycle-count field parse |
| `FUN_103ee3d0` | context-ID field parse (1/2/4 bytes) |
| `FUN_103ee540`/`FUN_103ed020` | Atom packet |
| `FUN_103ee6e0`/`FUN_103ed310` | Branch-address packet |
| `FUN_103eeaa0`/`FUN_103ec740` | Timestamp packet |
| `FUN_103ee890`/`FUN_103ed5a0` | Context-ID packet |
| `FUN_103eee10`/`FUN_103ed9c0` | Waypoint packet |
| `FUN_103f4870` | histogram inserter (`++map[address]`) |
| `FUN_10199430` | option -> (traceMode,sampleMode,ts/sample period) |
| `FUN_101ac0b0` | `ConfigurePerfmon`: CreateArmTrace(traceMode,sampleMode,ts,sample,pid) |
| `FUN_100b3f50`/`FUN_1019dd90` | PC-sample histogram consumers (symbolisation) |
