# PS Vita Razor "GPU Trace" - what the retail DLL actually does over the wire

Reverse of `PSP2Razor.dll` 3.60.0.5 (32-bit, image base `0x10000000`), the live GPU-activity
timeline trace that becomes a `.pmon`. Every claim is tagged with the function/data it comes from.
"**Interpretation**" marks inference. `tm!` = psp2tm.exe 3.60.0.2 (Ghidra TMRE), `api!` =
psp2tmapix86.dll (TMAPI), unprefixed = PSP2Razor.dll. TMAPI vtable offsets are from reflecting
`Interop.PSP2TMAPILib.dll` (Target Manager Server\bin).

---

## 0. Summary

**The retail DLL's "Perform GPU Trace" path sends NO PAMP `IPerformanceAnalysis` commands at all.
It aborts inside `CPSP2SnapShotSessionRunGpuTrace::DoCaptureInternal` while looking for the on-target
Razor HUD library, before any capture is programmed.** This matches a live
`Razor-16608.log` (DoCaptureInternal -> two `CPSP2Target::GetModule` -> "Did not find usable Razor HUD
library" -> abort) and is proven statically below.

The whole GPU trace is delegated to a **PRX that must be resident on the target**: `SceRazorHud`
or `SceRazorHudEs3`. The host DLL only (a) finds+validates that PRX, (b) writes a `tmp_settings.ini`
into a host temp dir and exposes it as `host0:` via DRFP file serving, (c) writes a command into the
HUD's memory and sets a software breakpoint on a "trace complete" address the HUD advertises,
(d) resumes and waits for that breakpoint, (e) reads back the `.pmon` the HUD wrote to `host0:`
and loads it with `FUN_101d71a0`. The GPU PMON hardware capture happens entirely inside the HUD PRX
(kernel PA `_sceKernelPaAddGpuTrace`), which retail firmware cannot do without that PRX.

### 0.1 The HUD finder `FUN_101b1200`

Called (virtually) from the GPU-trace session via `CPSP2Target` vtable **slot +0xfc =
`FUN_101b17e0`** (vtable `0x1051fdec[63]`; `FUN_101b17e0` logs the literal
"Unable to find Razor HUD library for this executable." then calls `FUN_101b1200`). The steps:

1. `Ordinal_286(L"SceRazorHud")`, `Ordinal_286(L"SceRazorHudEs3")` - the two module names.
2. `FUN_101ade90(...,"SceRazorHud")` then, on failure, `FUN_101ade90(...,"SceRazorHudEs3")` =
   **`CPSP2Target::GetModule`** (the two GetModule calls in the log). GetModule iterates
   `IProcess.get_Modules` (`process` vtable **+0x74**), reads each `IModule.get_Name` (**+0x3c**),
   `VarBstrCmp` against the wanted name; on match returns `IModule.get_Id` (**+0x1c**) and the
   `IModule`.
3. **If neither module is found -> `FUN_1028d690(0x865)`** -> error resource **0x865 = rt 2149 "Did
   not find usable Razor HUD library."** and the session aborts (verified: this is the only site of
   0x865, and 0x865's text matches the log). **This is exactly where retail dies** - the console has
   no `SceRazorHud*` module, so GetModule iterates the real module list and matches nothing.
4. If found: `IModule.get_ModuleSegments` (**+0x48**) -> collection; `get_Count` (**+0x1c**); for each
   segment: `get_Attributes` (**+0x28**), and **only if `attr & 1`** (executable/code segment):
   `get_BaseAddress` (**+0x1c**), `get_Size` (**+0x20**), allocate a buffer of that size, then
   `FUN_101af550(base,size,buf)` = **`CPSP2Target::GetProcessMemory` = `IProcess.GetMemory` (+0x2c) =
   DBGP RDMEM** (`DBGP_MODULE_THREAD_FORMAT.md §9a`).
5. Scan the read bytes for the **8-byte marker** (disasm `0x101b145b`):
   `dword0 == 0xBEBABEB0` and `dword1 == 0xBE77BEFE`, i.e. the little-endian bytes
   **`B0 BE BA BE  FE BE 77 BE`**. The `u32` immediately after (buf+8) is the **HUD info-struct
   address**, stored at `this+0x1d8` (disasm `0x101b14ac`). (Analogous to libperf's
   `DE BE AD BE BE BE EF BE` marker in `RAZOR_PA_TRACE_FORMAT.md §1`, but a distinct signature.)
6. If no segment held the marker -> **0x817c = "Unable to find a matching Razor HUD library."**
7. With the info addr in `this+0x1d8`: check process run-state (`model+0x34 == 2`), then
   `FUN_101af550(this+0x1d8 -> *,0x20,this+0x1e0)` = **RDMEM 0x20 bytes at the info addr** into the
   struct mirror at `this+0x1e0` (disasm `0x101b15..`). Validate:
   - `this+0x1e0 (struct dword0) == 1`   -> **version, must be 1** (else 0x817e).
   - `this+0x1e4 (struct dword1) == 0x20` -> **size, must be 0x20** (else **0x817e = "This version of
     Razor HUD is not compatible with the Host Tool."**).
   - If that RDMEM fails -> **0x817d = "Unable to check Razor HUD version."**
8. `FUN_101b1c50(1, ...)` - writes the "start/arm" command into HUD memory (see §0.3), sets
   `this+0x181 = 1`, then `FUN_101b0d40()` (clears 4 breakpoint slots).
9. Requires `this+0x1ec (struct dword3) != 0` = the **trace-completion breakpoint address**; if 0 ->
   **0x787 = "Cannot get address of trace completion break point."**
10. `FUN_101b1b30(3, this+0x1ec)` - **sets a software breakpoint (slot 3) at that address** (see
    §0.4). On failure -> **0x817f = "Failed to set up GPU trace."**

### 0.2 The HUD info struct (0x20 bytes, read by step 7; field offsets from disasm of `FUN_101b1200`)

```
+0x00 u32 version        MUST == 1                        (this+0x1e0)   -> else 0x817e
+0x04 u32 size           MUST == 0x20                     (this+0x1e4)   -> else 0x817e
+0x08 u32 ?              (this+0x1e8; read, use not decoded)
+0x0c u32 completionBpAddr  MUST != 0                      (this+0x1ec)   -> else 0x787; bp set here
+0x10 u32 commandBufAddr    address the 0x204-byte command is written to (this+0x1f0)
+0x14 u32 ?              (this+0x1f4)
+0x18 u32 ?              (this+0x1f8)
+0x1c u32 ?              (this+0x1fc)
```
**Interpretation:** dword2/4..7 are additional HUD control fields (a command ring / status address);
only version, size, completionBpAddr and commandBufAddr are load-bearing for getting past setup.

### 0.3 Command write `FUN_101b1c50(cmd, strArg)`

```
if ((this+0x1d8 | this+0x1dc) == 0) return;      // info addr must be valid
buf[0]   = cmd (u32)                              // 1=arm/start, 2=stop, 4=cleanup
buf[4..0x203] = 0, optionally a 0x1ff-char string (strArg) via FUN_102e00e0
FUN_101b6a50(this+0x1f0 -> commandBufAddr, 0x204, buf)   // = CPSP2Target::SetProcessMemory
                                                          //   = IProcess.SetMemory(+0x30) = DBGP WRMEM
```
`FUN_101b6a50` = `CPSP2Target::SetProcessMemory` = `IProcess.SetMemory` (**+0x30**) = **DBGP WRMEM**
(`DBGP_MODULE_THREAD_FORMAT.md §9b`). Command codes seen: `FUN_101b1200` sends **1** (arm);
`FUN_101b1e00`(+0x100) sends **2** (stop); `FUN_101b1d00`(+0x108)/`FUN_101b0ba0`(+0x10c) send **4**
(teardown). So the trace is a WRMEM(cmd=1) -> wait bp -> WRMEM(cmd=2/4) exchange with the HUD, 0x204
bytes each.

### 0.4 Breakpoint `FUN_101b1b30(slot, addr)` (disasm `0x101b1b30`)

`slot < 4` required. Slot object = `this + 0x280 + slot*0x18` (slot 3 -> `this+0x2c8`).
`FUN_1018d660(bpSlot, addr, process)` then `FUN_1018d6c0()` which calls process vtable **+0x4c** =
`IProcess.SetSoftwareBreakpoint(nThreadId=0xFFFFFFFF, nAddress=addr, eAttr, nHitCount=0, script,
&origOpcodeSize, &origOpcode)`. Over the wire that is **DBGP group 0x10 SET_SWBRKPT,
request code 0x4a / response 0x4b** (`tm!FUN_1400d9810` builder, `tm!FUN_140085980` transaction; the
psp2tm request body is `pid | threadId | address | attributes | u32 difLen | difBytes`, the response
carries `OriginalOpcode / OriginalOpcodeSize / BreakPtId`, from `api!` request
`sn::CSetSoftwareBreakPointRequest` fields ProcessID/ThreadID/Address/Attributes/DIFByteCode and
response printer `api!FUN_100c2a60`). The breakpoint firing (process STOP_NOTIFICATION at that PC)
is what wakes the wait pump; `FUN_101b5300` (bp-hit handler) treats a slot-3 hit as benign
(returns 1, disasm `0x101b5578` `LEA ECX,[EDI+0x2c8]`). **CLEAR_SWBRKPT is 0x4c / 0x4d**
(`tm!FUN_1400d84f0` / `tm!FUN_140083e60`, request `pid | breakpointId`), used at teardown
(`IProcess.ClearSoftwareBreakpoint` +0x50 via `FUN_1018d780`).

### 0.5 To satisfy Razor by faking the HUD (the actionable recipe)

Getting past **0x865** needs only a fake module; getting a `.pmon` to load needs the full dance.

1. **Module list (DBGP GET_MOD_INFO_RES, group 0x40 code 0; `DBGP_MODULE_THREAD_FORMAT.md §2`).**
   Add one module entry named exactly **`SceRazorHud`** (26-byte name field at `ENTRY+0x24`,
   NUL-padded) with `Status=2 LIVE` (`+0x44`) and **at least one segment whose `Attributes` bit0 is
   set** (`seg+0x04`), a `BaseAddress` (`seg+0x08`) and `Size` (`seg+0x0c`) that cover a region you
   will answer RDMEM for. (`SceRazorHudEs3` also works; Razor tries `SceRazorHud` first.)
2. **Implement DBGP RDMEM (group 0x10 code 0x11) for that region** - currently NOT implemented in the
   bridge (`FEATURES.md`, returns result 8). Return, somewhere in the segment, the 8 bytes
   `B0 BE BA BE FE BE 77 BE` followed by a `u32` = the info-struct address (pick any readable target
   address, e.g. inside the same fake segment).
3. **RDMEM at the info-struct address** must return 0x20 bytes: `version=1`, `size=0x20`,
   `dword2=0`, **`completionBpAddr=<a code address you will "hit">`**, `commandBufAddr=<writable
   addr>`, rest 0.
4. **Accept DBGP SET_SWBRKPT (0x4a)** at `completionBpAddr` - reply 0x4b with `OriginalOpcode`,
   `OriginalOpcodeSize`, a `BreakPtId`. **Accept DBGP WRMEM (0x13)** of the 0x204-byte command at
   `commandBufAddr` - reply with `written_len == len`.
5. **Do the work the HUD would do:** synthesise the `.pmon` (the plugin already has
   `plugin/pmon_trace.c`) and **write it to the `host0:` file** whose path Razor put in
   `tmp_settings.ini` `trace_filename=` (§2). This requires **DRFP host0: file serving** (also NOT
   started in the bridge, `FEATURES.md`).
6. **Fire the breakpoint:** push a **DBGP STOP_NOTIFICATION** (group 0x10 code 0xc0,
   `DBGP_MODULE_THREAD_FORMAT.md §10`) with the thread PC at `completionBpAddr`. That wakes Razor's
   wait pump; it then reads back `host0:<tmp.pmon>` and loads it with `FUN_101d71a0`. Answer the
   subsequent WRMEM(cmd=2/4) and CLEAR_SWBRKPT to finish cleanly.

**Interpretation / caveat:** steps 2-6 are a full HUD impersonation on top of DBGP memory R/W,
software breakpoints and DRFP - three subsystems the bridge lists as not implemented. It is *possible*
in principle (nothing checks that the marker/struct/`.pmon` really came from a HUD), but it is a large
build, and the `.pmon` content still has to be synthesised on-console (which `pmon_trace.c` already
does). The pragmatic alternative is to open a pre-built `.pmon` in Razor directly (offline load path),
which needs none of this.

---

## 1. Where GPU Trace starts, and the abort preconditions
- **UI command:** menu id **0x6f0** ("Create a GPU Trace / GPU Trace", rt 1776) -> dispatcher
  `FUN_1018b630` -> `FUN_1018a600`. `FUN_1018a600` builds a `CCaptureOptions` of **type 2**
  (`FUN_10182a90(2,0)`) and calls `CPSP2RazorDLL::DoSnapshotCapture` `FUN_10184c10`.
  (Type 1 / id 0x689 = GPU *Capture* `FUN_1018a450`; id 0x8009 = CPU snapshot `FUN_1018a310`.)
- `DoSnapshotCapture` `FUN_10184c10` -> `DoLocalSnapshotCapture` `FUN_101846d0`, which
  before anything checks memory head-room (`FUN_1003db90` -> 0x7c9 "insufficient memory",
  `FUN_1003ddd0` -> 0x81eb), then runs the session.
- **Process preconditions (from the live log + `FUN_1018a600`/`FUN_101b1200`):** a process must be
  **selected and process-locked** ("Requesting/Acquired process lock for PID ..."), **attached**
  (`CPSP2Target::AttachProcessCallback` `FUN_101acd30`, DBGP `ATTACH_PROCESS` 0x20/0x10 flags 0),
  its **modules enumerated** (`GetModules`/`GetModuleSegments`), and it must be **stopped/attached**
  for the HUD memory read (`FUN_1012f820` requires attached & not the debugger process;
  run-state `model+0x34 == 2`). No VCP screenshot is needed to *reach* the abort (the screenshot,
  session vtable slot `+0x2c` `FUN_10258f90`, happens later inside DoCaptureInternal). The **hard
  precondition that fails on retail is the HUD PRX** (§0). Razor does *not* need
  `librazorcapture`/`SceRazorCapture` for the GPU **trace** - that (and error "Did not find usable
  Razor GPU capture library", from `FUN_101b0d70` scanning `SceRazorCapture`/`SceRazorCaptureEs3`,
  errors 0x8160/0x815e) is the separate GPU **capture** (`.sgx`, `CPSP2SnapShotSessionRunGpuCapture`,
  id 0x689). Confirmed: `Razor-11316.log` GPU capture -> "...GPU capture library"; `Razor-16608.log`
  GPU trace -> "...HUD library".
- **Trigger dialog / config (`SgxTraceTriggerSettingsDialog` `FUN_1024eb10`, reader `FUN_1024ee70`):**
  the GPU trace's user options are **{ metric group (dropdown, e.g.
  "M0: Overview" rt 1778), size in {Low,Medium,High} (rt 1780-82), rate in {Low,Medium,High} }** -
  stored in the `CCaptureOptions` at `+4` (group id, `int`), `+8` (size), `+0xc` (rate). These become
  the `tmp_settings.ini` fields in §2. There is no bufferId/probe-mask UI - that layer belongs to the
  HUD, not the host.

---

## 2. The session flow and the host0: file transport

Session class **`CPSP2SnapShotSessionRunGpuTrace`** (vtable `0x10581f9c`):
`FUN_10258840` ctor, `FUN_10258c00`->`FUN_10258c30` **DoCaptureInternal**, `FUN_10258f90` (slot +0x2c,
VCP screenshot), `FUN_102594a0` (slot +0x30, returns 1), `FUN_10258880` (slot +0x34). Base
(`CSessionRun`) slots +0x08..+0x2c forward to the *model* (`FUN_100f2610` -> model, vtables at
model+0xa0/0xec..0x10c) and drive the progress bar.

**`DoCaptureInternal` `FUN_10258c30`, ordered:**
1. `FUN_1028c4f0` memory guard (0x7c9 on failure).
2. `FUN_100f2610` get model (0x66 on failure).
3. `(*session[0xb])()` = `FUN_10258f90` - **VCP screenshot** (via `Ordinal_4049`/`FUN_1024ee70`;
   guarded by capture option, not fatal).
4. Progress: `local_54` = `CProgressUpdatePumpOp` (`FUN_1004c250`); title **0x8174 "Stop"** then
   **0x8176 "GPU trace in progress..."** (progress state setter `FUN_101741f0`).
5. `FUN_10259030` - **writes the two host files and sets the file-serving root** (see below).
6. `(*session[0xc])()` = `FUN_102594a0` (ok), then `FUN_100f2720` (model +0xfc).
7. First pump `FUN_1028cd70(0,0)` (wait). If the run needs the HUD (state check), progress becomes
   **0x8175 "Requesting GPU trace..."** and:
   - `FUN_10259530` **RequestCapture** -> model vtable **+0xa0** (this is where `CPSP2Target`'s
     HUD-connect `+0xfc`/`FUN_101b17e0`->`FUN_101b1200` runs - the GetModulex2 + 0x865 abort of §0),
     then `FUN_100f2d80` (base +0x100), then `FUN_102595a0` **RunCapture**.
   - **RunCapture `FUN_102595a0`:** progress **0x8177 "Transferring GPU trace..."**, install the
     `WaitForProcessStopPumpOp` (vtable `0x10511138`) and `FUN_1028cd70(0,...)` - **block
     until the process stops at the completion breakpoint** (the HUD signalling "done").
8. `(*session[9])()` (base progress), then `FUN_102589d0` - progress **0x8179 "GPU trace completed."**,
   loads the file.

**`FUN_10259030` - the settings/file writer:**
- Gets a **host temp dir** (app object vtable +0x18), appends `tmp_settings.ini` and `tmp.pmon`
  (data `0x1058208c`, `0x105820a0`). `CreateFileW(settings, GENERIC_WRITE, share=1, OPEN_ALWAYS,
  FILE_ATTRIBUTE_NORMAL)` on the **host**.
- Writes UTF-8 lines (data at `0x105820ac`+): 
  ```
  trace=1
  trace_metrics_group=%d       <- CCaptureOptions+4  (metric group index)
  trace_size=%s                <- CCaptureOptions+8  via FUN_102594b0 (0->"low",1->"medium",2->"high")
  trace_rate=%s                <- CCaptureOptions+0xc via FUN_102594b0
  trace_filename_count_len=0
  trace_filename=host0:<served path to tmp.pmon, backslashes -> forward slashes>
  ```
- `FUN_102d8850`/`FUN_102d8900` (CP_UTF8 0xFDE9) convert the local temp path to a **`host0:` served
  path** and store it at `session+0x30` (`0x104` wchars); `DeleteFileW` pre-cleans the output.
  So the temp dir is exposed to the target as `host0:` (DRFP / `ITarget.set_FileServingRoot` +0xe0).
- **So the transport is DRFP host0: file serving, not PAMP:** the target reads `host0:tmp_settings.ini`
  and writes its `.pmon` to `host0:<...>/tmp.pmon`, which lands as a real host file.

**`FUN_102589d0` - load:** `FUN_104070a0(host path)` then **`FUN_101d71a0(...,
session+0x2c)`** loads the `.pmon` exactly like an offline file; on success builds the
`GPU Trace` dataset (`FUN_101d5630`). So the file Razor loads is the one the HUD wrote via host0:.

**No IPerformanceAnalysis call is made by the GPU-trace session.** Cross-check: the DLL's PA object
lives at `CPSP2Target+0x14c`; scanning every `CALL [reg+0x14c]`-derived vtable call
shows the DLL only ever invokes PA **Open(+0x84), Close(+0x88), TimebaseFrequency(+0x80),
TraceBufferAvailableSize(+0x1c), ConfigNormalTraceBuffer(+0x20), Get/SetBookmarkConfig(+0x6c/+0x68),
CreateArmTrace(+0x30), StartCapture(+0x40), StopCapture(+0x44), ReadTraceData(+0x4c),
FetchTraceData(+0x8c)** - all in the **CPU (ARM) PA** path (`ConfigurePerfmon` `FUN_101ac0b0`,
`ReadTraceData` `FUN_101b5740`). **`CreateGpuTrace` (+0x38), `CreateCounterTrace` (+0x34) and
`GetGpuSampledData` (+0x78) are never called by PSP2Razor.dll.**

---

## 3. The `.pmon` container Razor loads

Whatever produces it (HUD on a DevKit, or a synthesiser), the bytes Razor loads must be a complete
`.pmon` file starting with `"PMON"`. **Razor does NOT build the header from arguments** - it reads a
target/host-produced file whole (`FUN_101d71a0` -> header check `FUN_101cee80`). Verified header
(`FUN_101cee80` @ `0x101ceec0`):

```
+0x00  u32  MAGIC = 0x4E4F4D50 ("PMON")        else throw "Header invalid" (psp2pmontrace.cpp:0x5e)
+0x0C  u32  version   (read at obj+0x418)
             version <  0x10002            -> error 0x6d "unsupported old .pmon"
             0x10002 <= version <= 0x10003 -> OK
             version >= 0x10004            -> error 0x7c "unsupported .pmon"
+0x0E  u16  minor = high half of the version dword
= 0xE0-byte primary header. First read is exactly 0xE0 bytes (FUN_101cf260(obj+0x40c,0xE0)).
if version >= 0x10002: read 0x10 more bytes, MAGIC dword0 = 0x4E4F4D51 ("PMNQ") else throw @:0x83.
```
Header field semantics used by the loader (from `PMON_SYNTH_NOTES.md`, verified there against
`FUN_101cee80`/`FUN_101cddf0`): `+0x10` flags (bit3 -> data length from `+0x24`), `+0x14` dataEnd,
`+0x20` dataStart, `+0x30/+0x32` counted/sampled periods, `+0x34..+0x53` counted-enable masks,
`+0x74/+0x84/+0x94/+0xa4` sampled selections (the metric-group signature), clock 333 MHz.

**Body = the same PA frame/slot container as the CPU trace**: 0x80-byte frames, 8x16-byte records,
`desc=(type<<8)|chan`; slot types **0x7f bookmark / 0x61 counted PMON / 0x60 sampled PMON**
(`FUN_101cec80` dispatch, `FUN_101bc930` bookmark AddWord). **IFF metadata chunks** are appended only
when `version >= 0x10003` and parsed by `FUN_101cddf0` (tags `0x1c2b00`..`0x1c2b08`, `0x1c2b01` ends
the loop) - **so at version 0x10002 the frame body alone drives correlation and no IFF is needed.**
The body length is read as `dataEnd-dataStart`; the frame walker steps in 0x10-byte units and the
loader tolerates a body that is not a whole number of 0x80 frames (`FUN_101ce460` returns the byte
size; `FUN_101cddf0` loops `uVar7 += 0x10` while `< size`) - **no 0x80-multiple or minimum-size
requirement in the container itself** (the "too small" gate 0x71b is a *correlation* check on job
count, not a file-size check). All of §3 and the encoder recipe in `RAZOR_GPU_TRACE_FORMAT.md §3/§7`
and `PMON_SYNTH_NOTES.md` remain correct and have already been validated by loading synthetic files
in `PSP2Razor.exe` offline. **Correction to the prior docs:** the claim that Razor *fetches* this
`.pmon` over PAMP `FetchTraceData` is wrong for the retail DLL path - it is delivered as a `host0:`
file written by the HUD (§2). PAMP `FetchTraceData`/`ReadTraceData` in the DLL serve the ARM CPU
trace buffer, not the GPU `.pmon`.

---

## 4. Does the GPU trace need a simultaneous CPU (ARM) trace? Does CreateArmTrace with
`EnableGpuActivityTrace=1` issue CreateGpuTrace?
- **The GPU-trace session (`CPSP2SnapShotSessionRunGpuTrace`) runs no ARM PA trace and no PAMP.** It
  is a self-contained HUD + host0: + breakpoint operation (§0/§2). It does need the CPU-frame
  correlation bookmark `[ARM] CPU Frame (sceGxmPadHeartbeat)` **inside the .pmon** (A8/`0xB0BAFE77`,
  `RAZOR_GPU_TRACE_FORMAT.md §4.1` / `FUN_101d4fd0` "No CPU Frame Bookmarks found in GPU Trace!"), but
  that lives in the HUD-produced file, not in a separate live ARM capture.
- **A normal Razor CPU trace does NOT issue `CreateGpuTrace`, even though `EnableGpuActivityTrace`
  defaults to 1** (`FUN_1008c140` sets `EnableGpuActivityTraceOption=1`).
  `ConfigurePerfmon` `FUN_101ac0b0` programs **`CreateArmTrace` only** (PA vtable **+0x30**,
  args `traceMode, sampleMode, tsPeriod, samplePeriod, pid`). Combined with §2's finding that the DLL
  never calls PA +0x34/+0x38/+0x78, the single `cmd 4` in the CPU capture PAMP order
  (0,0x12,2,3,2,0xD,0xC,**4**,6,7,8,7,1) is **`CreateArmTrace` (sub 0), never `CreateGpuTrace` (sub
  2)**. **So a CPU trace against the retail plugin will never ask for GPU data over PAMP** - the
  plugin's habit of answering PAMP cmd 4 with OK and ignoring sub 2 is harmless and, for the GPU
  timeline, irrelevant. GPU activity appears only if a `.pmon` is produced by the (separate) GPU-trace
  path and time-correlated.
- **Interpretation:** the `EnableGpuActivityTrace` option gates whether the DLL *also* kicks the
  HUD-based GPU trace alongside the CPU snapshot in the combined "CPU trace with GPU activity" flow;
  when it does, the GPU rows still come from the HUD `.pmon`, not from the ARM PA buffer or a PAMP
  CreateGpuTrace.

---

## 5. psp2tm.exe / PAMP `CreateGpuTrace`: still real, but not on this path

The PAMP wire format for `CreateGpuTrace` (cmd 4 sub 2, **0x48-byte body**: `u32 nControl, u16
nSampleRate, u16 nCountedRate, u32[4] arrDBusAEnabled, u32[4] arrDBusBEnabled, u32[4]
arrConditionMask, u32[4] arrValidityMask`) is exactly as documented in `PAMP.md`/`RAZOR_GPU_TRACE_
FORMAT.md §2` (`tm!FUN_1400dcbe0` encoder, `api!FUN_1008a410` field printer). Reflecting
`Interop.PSP2TMAPILib.dll` confirms the signature verbatim
(`CreateGpuTrace(uint nContol, ushort nSampleRate, ushort nCountedRate, uint[] arrDBusAEnabled,
uint[] arrDBusBEnabled, uint[] arrConditionMask, uint[] arrValidityMask)`, PA vtable **+0x38**), and
`GetGpuSampledData(uint[] arrData)` at **+0x78** (16-byte, live GPU status, `PAMP.md` cmd 0x10). But
**PSP2Razor.dll never invokes either** (§2/§4). psp2tm forwards them unchanged; nothing in the wire
format changes for GPU. They are reachable only by a different TMAPI client, not by the retail Razor
GPU-trace UI. This does not alter what the plugin must answer for the DLL's GPU trace (which is the
DBGP+DRFP HUD dance, not PAMP).

TMAPI vtable offsets confirmed by reflection (for the DBGP handlers the plugin must add):
`IProcess.GetMemory`=+0x2c (RDMEM), `SetMemory`=+0x30 (WRMEM), `SetSoftwareBreakpoint`=+0x4c (DBGP
0x4a), `ClearSoftwareBreakpoint`=+0x50 (DBGP 0x4c), `get_Modules`=+0x74, `Attach`=+0xac;
`IModule.get_Id`=+0x1c, `get_Name`=+0x3c, `get_ModuleSegments`=+0x48, `get_Status`=+0x40;
`ISegmentInfo.get_BaseAddress`=+0x1c, `get_Size`=+0x20, `get_Attributes`=+0x28.

---

## 6. Unknowns

- The HUD info-struct dwords `+0x08` and `+0x14..+0x1c` (`this+0x1e8/+0x1f4..+0x1fc`): read by
  `FUN_101b1200`, exact meaning not decoded (likely a status/ring address; `+0x10` commandBuf and
  `+0x0c` completionBp are the load-bearing ones).
- The 0x204-byte HUD command body beyond `buf[0]=cmd` (the optional 512-char string arg and any
  fields the HUD reads) - not reversed; would matter only for a byte-exact HUD emulation.
- Whether the completion handshake also uses a *second* breakpoint or a status poll of the info
  struct (only the one slot-3 SW breakpoint at `+0x0c` is proven).
- The exact `tmp_settings.ini` keys the HUD *requires* vs. ignores (host writes 6 keys; target-side
  parsing is in the HUD PRX, not in scope).
- `nControl` / DBus mask bit meanings in the (unused-by-DLL) PAMP `CreateGpuTrace` body - SGX-uKernel
  internal, names only.
- On-device: whether `_sceKernelPaAddGpuTrace`/`AddGpuTraceByKey` (NIDs 0x935181AD/0xD285D137) are
  reachable from a retail plugin to *actually* produce GPU PMON data for the `.pmon` - the HUD is the
  normal producer and retail lacks it; the plugin's `pmon_trace.c` synthesises the file from the
  game's own GXM profiler CSV instead.
```
