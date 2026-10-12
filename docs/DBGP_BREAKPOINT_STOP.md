# DBGP software breakpoints + STOP_NOTIFICATION for the Razor GPU-trace HUD dance

How psp2tm (`tm!`, 3.60.0.2, x64, Ghidra `tmproj`) and PS Vita Razor (`PSP2Razor.dll`, 3.60.0.5,
x86 base `0x10000000`, Ghidra `gproj2`) drive the four DBGP messages the impersonated on-target HUD
must answer around the trace-completion breakpoint: **SET_SWBRKPT (0x4a/0x4b)**, **CLEAR_SWBRKPT
(0x4c/0x4d)**, and the pushed **STOP_NOTIFICATION (group 0x10 code 0xc0)**. Conventions match
`DBGP_MODULE_THREAD_FORMAT.md` / `DBGP_PROCINFO_FORMAT.md`: little-endian, offsets relative to the
**DBGP payload** = DECI4 frame + 0x10, `ENTRY+` = relative to a self-sized entry. `Interpretation`
marks inference. Worked frames are produced and re-decoded by the psp2tm validators in
`tools/gen_bp_frames.py` (self-checks pass).

Reused facts: response header §1, RDMEM/WRMEM §9, ProcessInfo entry (`DBGP_PROCINFO_FORMAT.md`),
basic ThreadInfo entry §4b, notification header/routing §10, all from `DBGP_MODULE_THREAD_FORMAT.md`.

---

## 0. Summary: what the target must send

| Msg | dir | payload |
|---|---|---|
| SET_SWBRKPT_RES `0x4b` | target->host | `00 10 4b 00, seq0, result=0, u32 pid, u32 BreakPtId, u32 OriginalOpcodeSize, u32 OriginalOpcode` |
| CLEAR_SWBRKPT_RES `0x4d` | target->host | `00 10 4d 00, seq0, result=0, u32 pid, u32 BreakPtId` |
| STOP_NOTIFICATION `0xc0` | target->host (unsolicited) | `<any> 10 c0 00, seq0, key=0, ProcessInfo entry, u32 Status, u32 ThreadId, u32 count, countxbasic ThreadInfo, [u64 tick]` |

The load-bearing constraints: **SET_SWBRKPT_RES must echo pid and carry a nonzero-or-any BreakPtId**
(Razor keeps it to clear later); OriginalOpcode/Size are **never read by Razor** - cosmetic.
**STOP_NOTIFICATION must report the stopped thread's PC == `completionBpAddr & ~1`** in the
ThreadInfo entry's `CurrentPC` field (`ENTRY+0x9c`); ProcessInfo.Id must equal the pid and be
nonzero; `Status` is **not inspected by Razor** (only logged/surfaced by psp2tm). No register read
follows the stop.

---

## 1. SET_SWBRKPT - group 0x10, request 0x4a / response 0x4b
### 1a. Request as psp2tm builds it (`tm!FUN_1400d9810`, disasm `0x1400d9853`..`0x1400d9907`)

`tm!FUN_140085980` (transaction; waits RES `0x4b`, 5 s) calls the builder with, in order,
`pid, threadId, address, attributes, DIFvector`. Those come straight off the TMAPI request object
`sn::CSetSoftwareBreakPointRequest` (`api!` vtable printer `FUN_1009c760`: fields at obj+0x10
ProcessID, +0x14 ThreadID, +0x18 Address, +0x1c Attributes, +0x20 DIFByteCode). The builder emits a
**fixed 0x24-byte block** then the DIF bytes (pad4). Exact wire (spec's `pid|threadId|address|
attributes|difLen|difBytes` is a simplification - the real block interleaves two constants and two
zero words):

```
+0x00 u32 0x004a1000     b0=00, group=0x10, code=0x4a
+0x04 u32 ProcessID
+0x08 u32 0x00000020     constant (CONCAT44(0x20,pid) high half)
+0x0c u32 0              (threadId high half of CONCAT; always 0)
+0x10 u32 ThreadID       = 0xFFFFFFFF for the HUD breakpoint (see 1c)
+0x14 u32 Address        = completionBpAddr & 0xFFFFFFFE
+0x18 u32 Attributes     = completionBpAddr & 1  (eSoftwareBreakPtAttr: 0=32BIT/ARM, 1=16BIT/Thumb)
+0x1c u32 0              constant
+0x20 u32 0x00000008     constant
+0x24 u32 DIFLen         = difByteCount & 0xFFFF   (0 for the HUD breakpoint - no script)
+0x28 u8[DIFLen] DIF, zero-padded to 4
```

### 1b. Response body the validator requires (`tm!FUN_1400d2030` + consumer `tm!FUN_14013f080`)

`FUN_1400d2030` (the 0x4b decoder): requires `payload[1]==0x10`, `payload[2]==0x4b`,
`result(payload+8)==0`, then **exactly 0x10 bytes** present at payload+0x0c. `FUN_140085980` then
checks the **echoed pid** (`*p != pid -> 0x100010`). `FUN_14013f080` copies the three trailing dwords
into the TMAPI `ISoftwareBreakpointInfo` object; the printer `tm!FUN_14021b6b0` proves the names:

```
+0x0c u32 pid                 MUST equal request pid          (else SCE 0x8004028b)
+0x10 u32 BreakPtId    -> obj+0x40  "BreakPtId:"
+0x14 u32 OriginalOpcodeSize -> obj+0x3c "OriginalOpcodeSize:"
+0x18 u32 OriginalOpcode     -> obj+0x38 "OriginalOpcode:"
```

So the response body is **`pid | BreakPtId | OriginalOpcodeSize | OriginalOpcode`** (12 data bytes;
payload 0x1c). `result==0` required. Header-only nonzero-result error replies are also tolerated
(§7a of `DBGP_MODULE_THREAD_FORMAT.md`), which would fail the arm.

### 1c. What Razor does with it / what to return for Thumb vs ARM

Razor arms the slot 3 breakpoint via `FUN_101b1b30(3, completionBpAddr)` -> `FUN_1018d660` splits the
advertised address: `slot+8 = addr & 0xFFFFFFFE` (the DBGP `Address`), `slot+0xc = addr & 1` (the
`Attributes`, i.e. Thumb) - disasm `0x1018d660`. Then `FUN_1018d6c0` calls
`IProcess.SetSoftwareBreakpoint(nThreadId=0xFFFFFFFF, nAddress=addr, eAttr, nHitCount=0, script=NULL,
&origOpcodeSize, &origOpcode)` (TMAPI vtable +0x4c). **Return value**: success iff HRESULT >= 0
(`SETNS` at `0x101b1b82`), i.e. the RES must have `result==0` and a valid pid echo. **The two
out-params `origOpcodeSize`/`origOpcode` are written into discarded locals** (`local_1c`/`local_18`
in `FUN_1018d6c0`) - Razor never reads OriginalOpcode/OriginalOpcodeSize anywhere. Only **BreakPtId**
is kept (stored at `slot+4`, later handed to `ClearSoftwareBreakpoint`, disasm `FUN_1018d780`).

Recommended target values (cosmetic but self-consistent with the virtual HUD, which places Thumb NOPs
`BF00 BF00` at the bp): **Thumb** (Attributes bit0=1) -> `OriginalOpcodeSize=2`, `OriginalOpcode=0xBF00`;
**ARM** (Attributes=0) -> `OriginalOpcodeSize=4`, `OriginalOpcode=0xE320F000` (NOP) or the real word.
`BreakPtId` = any nonzero id you can echo back on CLEAR (e.g. 1).

### 1d. Worked frames (from `gen_bp_frames.py`, PID `0x40010045`, advertised bp `0x7E000101` -> Thumb)

Host->target SET_SWBRKPT request (payload 0x28):
```
0000  38 00 00 40 00 00 00 00 00 00 02 00 00 00 00 00   DECI4 hdr, proto=0x20000
0010  00 10 4a 00 45 00 01 40 20 00 00 00 00 00 00 00   .4a. | pid | 0x20 | 0
0020  ff ff ff ff 00 01 00 7e 01 00 00 00 00 00 00 00   tid=FFFFFFFF | addr=7E000100 | attr=1 | 0
0030  08 00 00 00 00 00 00 00                           | 8 | difLen=0
```
Target->host **SET_SWBRKPT_RES** (payload 0x1c, frame 0x2c) - the frame the plugin must send:
```
0000  2c 00 00 40 00 00 00 00 00 00 02 00 00 00 00 00
0010  00 10 4b 00 00 00 00 00 00 00 00 00 45 00 01 40   .4b. seq0 result0 | pid
0020  01 00 00 00 02 00 00 00 00 bf 00 00               BreakPtId=1 | OpSize=2 | Opcode=0xBF00
```

---

## 2. CLEAR_SWBRKPT - group 0x10, request 0x4c / response 0x4d
### 2a. Request (`tm!FUN_1400d84f0`, transaction `tm!FUN_140083e60`)

`FUN_140083e60(model, req, pid, BreakPtId)` -> builder writes `0x4c1000` then `CONCAT44(bpid,pid)`:

```
+0x00 u32 0x004c1000      b0=00 group=0x10 code=0x4c
+0x04 u32 ProcessID
+0x08 u32 BreakPtId       the id the target returned in SET_SWBRKPT_RES
```

Razor issues this from `IProcess.ClearSoftwareBreakpoint(nId)` (TMAPI +0x50) via
`FUN_1018d780(slot)` which passes `*(slot+4)` = the stored BreakPtId.

### 2b. Response validator (`tm!FUN_1400cffe0`, consumer check `tm!FUN_140083e60`; printer `tm!FUN_1401d0500`)

`FUN_1400cffe0`: `group==0x10`, `code==0x4d`, `result==0`, **exactly 8 bytes** at payload+0x0c.
`FUN_140083e60`: echoed **pid must match** (`*p != pid -> 0x100010`). The printer shows only
`ProcessID:` and `BreakPtId:` fields:

```
+0x0c u32 pid          MUST equal request pid
+0x10 u32 BreakPtId    present (not value-checked); echo the request's id
```

Worked **CLEAR_SWBRKPT_RES** (payload 0x14, frame 0x24):
```
0000  24 00 00 40 00 00 00 00 00 00 02 00 00 00 00 00
0010  00 10 4d 00 00 00 00 00 00 00 00 00 45 00 01 40   .4d. seq0 result0 | pid
0020  01 00 00 00                                       BreakPtId=1
```

---

## 3. What Razor waits for, and the stop->handler path
### 3a. The wait pump `WaitForProcessStopPumpOp` (vtable `0x10511138`)

Installed by the GPU-trace session `RunCapture` `FUN_102595a0` (also by `DoCaptureInternal`
`FUN_10258c30`), then `FUN_1028cd70(0,...)` blocks (`0x10258df2` / `0x1025968a`).
The pump is a Windows message loop (`FUN_1028cd70`) whose "done" predicate is vtable **slot +4 =
`FUN_10131d90`**: it reads the *model's* process-run-state via model vtable **+0x98**
(`FUN_10130160` -> returns `iProcess+0x34`), and **returns done when that run-state == 2** (disasm
`0x10131e58`..; `iVar3 == 2` at `0x10131e6e`). So Razor is literally waiting for the model to enter
**ProcessRunState == 2 (stopped)**. Nothing polls DBGP - the state flips only when a
STOP_NOTIFICATION is delivered and processed (below). The pump's slot +8 (`FUN_1003eef0`) / slot +0xc
(`FUN_1028cd20` -> model +0x24) are the cancel/tick hooks.

### 3b. Notification -> TMAPI event -> state machine -> `FUN_101b5300`

1. **psp2tm** receives the 0xc0 frame; the frame doesn't match any pending transaction, so
   `tm!FUN_14012c040` sees `payload[1]==0x10` and calls `tm!FUN_14011b140`; the `case 0xc0` runs the
   validator `tm!FUN_1400d20f0`, builds an `IStopNotification` COM object
   (`sn::CStopNotificationNotification`, ctor `FUN_1400aa4d0`, vtable `0x140314a18`) and fires the
   TMAPI debug event to every client via `tm!FUN_140068190` ("DEBUG_NOTIFY").
2. **Razor** implements `IEventDebug` on `CPSP2Target`. `OnStopNotification` (vtable +0x1c) =
   **`FUN_101b4a50`**. It:
   - reads `ProcessInfo` via `IStopNotification.get_ProcessInfo` (+0x24), then `get_Id` (+0x1c);
     **early-outs unless the model's run-state object `+0x2c == 2`** (`0x101b4a70`) - i.e. the
     process is a debug target - and unless **`ProcessInfo.Id == this target's process id`**
     (compared to `CPSP2Target` model +0x84, `0x101b4aa8`);
   - reads `IStopNotification.get_ThreadId` (+0x20) -> `ThreadId`;
   - reads `IStopNotification.get_Threads` (+0x28) -> `IThreadInfoCollection`, then
     **`GetById(ThreadId)`** (collection +0x28), then **`IThreadInfo.get_PC` (+0x84)** -> PC;
   - posts state-machine **event 9** with a `TargetStateCookie<uint,uint>` = `{ThreadId, PC}`
     (`FUN_101b7aa0(9,...)` -> `FUN_101343e0`).
3. State event 9 -> handler `FUN_10133900`: sets model **ProcessRunState (+0x9c) = 2**
   (this is exactly the value the wait pump §3a is blocked on) and invokes **callback index 10 =
   `FUN_101b5300`** with the cookie args `(ThreadId, PC)`.
4. **`FUN_101b5300`** (bp-hit handler): iterates the breakpoint slots and compares
   the **stopped PC** (the 2nd cookie uint, `ESI` at `0x101b5335`) against each armed slot's address
   (`FUN_1018d650` = `slot+8`, and `slot+0x10` "is-armed" flag via `FUN_100848d0`). Slot layout:
   CPU-capture slots `this+0x208/0x220/0x238`; HUD/GPU slots `this+0x280/0x298/0x2c8`. The GPU
   trace-completion breakpoint is **slot 3 = `this+0x2c8`** (`0x101b5578 LEA ECX,[EDI+0x2c8]`); a PC
   match there jumps to `LAB_101b5666` and **returns 1 (benign - "the HUD trace-completion breakpoint
   was hit")**. If the PC matches no slot, it logs rt `0xafd` "Unexpected stop occurred. Thread Id:...,
   PC:..." and the trace fails.

### 3c. The exact fields Razor requires

| what | requirement | where |
|---|---|---|
| **stop reason / Status** | **not inspected by Razor.** `FUN_101b4a50` never reads `IStopNotification.get_Status`. psp2tm only logs it. Set `Status = STOP_REASON_SOFTWARE_BRKPT = 0x00020004` for correctness. | `FUN_101b4a50` (no +0x1c call) |
| **ProcessInfo.Id** | must be nonzero and **== the traced pid** | `0x101b4aa8` cmp to model+0x84 |
| **run-state gate** | model run-state object `+0x2c` must already be `2` (debug target). Set by ATTACH; the plugin's ATTACH + ProcessInfo attrs satisfy it. | `0x101b4a70` |
| **ThreadId** | any tid that the ThreadInfo list contains (GetById must resolve it) | `get_ThreadId` +0x20 |
| **PC** | **the ThreadInfo entry's `CurrentPC` (wire `ENTRY+0x9c`) of that ThreadId must equal `completionBpAddr & ~1`.** Comes from the **ThreadInfo in the stop frame**, NOT a register read. | `IThreadInfo.get_PC` +0x84 -> wire +0x9c |
| **register read after stop?** | **No.** `get_PC` returns the cached ThreadInfo field; Razor never calls `IThread.GetRegisters` / DBGP GET_REG in this path. | - |
| **breakpoint id in the notification?** | **Not used.** Razor matches by PC==slot address, not by breakpoint id. `StopReason.Code`/`CodeSpecificId` in the entries are ignored by the GPU path. | `FUN_101b5300` compares PC only |

### 3d. How psp2tm fills IStopNotification (`tm!FUN_1400d20f0` + `tm!FUN_14011b140`)

`FUN_1400d20f0` returns the ProcessInfo pointer and stores `*param_2 = <first thread entry ptr>`;
`FUN_14011b140` then builds the COM object: `obj+0x14 = Status` (payload word after the process
entry), `obj+0x18 = ThreadId`, ProcessInfo from `FUN_1400f66f0(processEntry)`, thread vector from
`FUN_1400e49d0(threadEntries,count)` (0xAC basic entries), `obj+0xc0 = u64 tick`. The IStopNotification
COM getters map: `get_Status->obj+0x14`, `get_ThreadId->obj+0x18`, `get_ProcessInfo`, `get_Threads`.
So the wire `Status`/`ThreadId`/`ProcessInfo`/`ThreadInfo[]` map 1:1 onto the TMAPI interface Razor
reads. The x64 serializer/printer (`sn::CStopNotificationNotification` vtable `0x140314a18`:
serialize `FUN_1402470b0`, print `FUN_1401f0680`) confirms the field order
**`{ TargetID/pid, Status, ThreadID, ProcessInfo, ThreadInfo }`**.

**Status enum** (`eStopNotificationReason`, from `Interop.PSP2TMAPILib`): `STOP_REASON_NOTHING=0`,
`SUSPEND_PROCESS=0x10001`, `SUSPEND_THREAD=0x10002`, `SPONTANEOUS_EXIT=0x10005`,
`HARDWARE_BRKPT=0x20003`, **`SOFTWARE_BRKPT=0x20004`**, `PRX_STOP_INIT=0x20006`,
`EXCEPTION_DATA_ABORT=0x30004`, `UNRECOVERABLE_ERROR_LOW=0x80000`. Use `0x20004`. `StopReason.Attribute`
= `eStopReasonAttr` (`0` read / `1` write). Since Razor ignores Status here, any value works, but
`0x20004` reads correctly in psp2tm's Event Viewer and matches the per-thread `StopReason.Code`.

---

## 4. What Razor does after the stop, and the run-state precondition
### 4a. Ordered DBGP traffic the target sees around the breakpoint

Setup (all inside `CPSP2Target::...` HUD connect `FUN_101b17e0`->`FUN_101b1200`):

1. `ATTACH_PROCESS` (0x20/0x10) - earlier, at attach. Target: header-only (result 0 or 0x20052).
2. `SUSPEND_PROCESS` (0x20/0x20) - Razor stops the process to read HUD memory (`FUN_101b1200` needs
   run-state 2). Target answers **result `0x20056`** ("already stopped", success, no body) - this is
   what keeps `model+0x2c/run-state` at 2 without a StopNotification body.
3. `GET_MOD_INFO` (0x40/0x00) - find module `SceRazorHud`.
4. `RDMEM` (0x10/0x11) xN - scan the code segment for `B0 BE BA BE FE BE 77 BE` + info-struct addr,
   then read 0x20 bytes at the info struct (`FUN_101af550`).
5. `WRMEM` (0x10/0x12) - write the 0x204-byte command `cmd=1` (arm) at `commandBufAddr`
   (`FUN_101b1c50(1)` -> `FUN_101b6a50`). Reply `written_len == len`.
6. **`SET_SWBRKPT` (0x10/0x4a)** at `completionBpAddr & ~1`, slot 3 (`FUN_101b1b30(3,...)`).
7. `RESUME_PROCESS` (0x20/0x22) - `FUN_101b17e0` then calls model `+0xa8` = `CTarget::ResumeProcess`
   (`FUN_10130d40`, state event 0xb). Target: `pid | 0 threads`. Process runs; pump blocks (§3a).

Stop + teardown:

8. **Target pushes STOP_NOTIFICATION (0x10/0xc0)** with PC == `completionBpAddr & ~1`. This flips the
   model run-state to 2 (§3b) and unblocks the pump.
9. Razor **reads the `.pmon` from `host0:` via DRFP** (file transport, *not* DBGP) and loads it
   (`FUN_102589d0` -> `FUN_101d71a0`).
10. `WRMEM` `cmd=2` (stop) at `commandBufAddr` (`FUN_101b1e00`, model +0x100). Reply written_len==len.
11. **`CLEAR_SWBRKPT` (0x10/0x4c)** for the slot-3 BreakPtId, and `WRMEM` `cmd=4` (teardown)
    (`FUN_101b0ba0`/`FUN_101b1d00`, model +0x108/+0x10c; `FUN_1018d780`->ClearSoftwareBreakpoint).
    Order of 10/11 is not load-bearing for the target; answer each whenever it arrives.
12. A further `RESUME_PROCESS` / `RESUME_THREAD` may follow at teardown; answer as in step 7.

**No `GET_REGISTERS` / DBGP GET_REG (0x10/0x05) is issued after the stop** - the PC came from the
STOP_NOTIFICATION's ThreadInfo.

### 4b. The "run state == 2" precondition

`FUN_101b1200` and the wait pump both require the model **ProcessRunState == 2 (stopped)**:
- The *initial* run-state is set when the process is selected (`FUN_101b6840`/`FUN_101b2c30`) from
  **`ProcessInfo.Attributes`**: `attr & 0x8 (PROCESS_ATTR_SUSPENDED) -> 3`; else `attr & 0x2
  (PROCESS_ATTR_DEBUG_STATE) -> 1 (running)`; **else -> 2 (stopped)** (disasm `0x101b68a0`). So the
  target's `GET_PROCESS_INFO` **Attributes must set neither 0x2 nor 0x8** (e.g. `0x00030001` =
  LOADED|DEBUGGABLE|ATTACHED) to present as run-state 2. The plugin already sends `0x30001`.
- `SUSPEND_PROCESS` answered with **`0x20056`** is treated as "already stopped, success, no
  StopNotification body" (`FUN_1400d21f0` consumer path / `DBGP_MODULE_THREAD_FORMAT.md §7a`),
  keeping run-state at 2. `RESUME_PROCESS` answered with `pid | 0 threads` moves the process to the
  running state only for the windowed run between arm and the completion breakpoint; the pushed
  STOP_NOTIFICATION returns it to 2, which is the whole point.
- **Interpretation:** the plugin never actually suspends/resumes a thread; the `0x20056` +
  attrs-without-0x2/0x8 + the pushed STOP together make Razor *believe* the process cycled
  stopped->running->stopped-at-bp, which is all the state machine checks.

---

## 5. Byte-exact STOP_NOTIFICATION frame
Validator `tm!FUN_1400d20f0` (single-frame path selected when `payload+8 == 0`; `tm!FUN_14011b140`
`case 0xc0` uses `payload+8` as a multi-part reassembly **key**, so it MUST be 0 for one frame):

```
payload+0x00  <b0> 10 c0 00      b0 any (echo 0); group 0x10; code 0xc0; pad 0
payload+0x04  u16 seq = 0        first/only frame
payload+0x06  u8  frag = 0       bit0 = more-fragments (0 here)
payload+0x07  u8  0
payload+0x08  u32 key = 0        MUST be 0 for a single-frame STOP (else multi-part reassembly)
payload+0x0c  ProcessInfo entry  self-sized (>=0x58 bytes checked); DBGP_PROCINFO_FORMAT.md layout.
                                  entry+0x04 ProcessID MUST be nonzero and == traced pid.
payload+0x0c+ESZ:
        u32 Status               eStopNotificationReason; 0x20004 SOFTWARE_BRKPT (Razor ignores it)
        u32 ThreadId             the stopped thread id (GetById must resolve it)
        u32 count                number of ThreadInfo entries
        count x basic ThreadInfo entry (0xAC, DBGP_MODULE_THREAD_FORMAT.md §4b; walked by
                                  FUN_1400cdeb0). The entry for ThreadId MUST have CurrentPC
                                  (ENTRY+0x9c) == completionBpAddr & ~1.
        u64 tickTimestamp        optional (present if >=8 trailing bytes)
```

Validator bounds (`FUN_1400d20f0`): >=0x58 bytes at the process entry; >=0xc bytes for
Status/ThreadId/count; each ThreadInfo entry's `size` in-bounds; the u64 tick is copied only if
present. There is **no `entry@0x40==0x14` check** for STOP (that is GET_PROCESS_INFO only), but set
`StopReason.size=0x14` in every entry for consistency.

### 5a. Worked STOP_NOTIFICATION - pid `0x40010045`, tid `0x40010049`, PC `0x7E000100`

ProcessInfo: name `PCSE00000`, path `app0:eboot.bin`, Attributes `0x00030001`,
StopReason.Code `0x20004`, id `0x1`. One ThreadInfo: name `main`, Status `1 (RUNNING)`,
`CurrentPC = 0x7E000100`, StopReason.Code `0x20004`. tick `0x12345678`. (Decoded and PC-verified by
`gen_bp_frames.py`: `GetById(tid).PC == completionBpAddr & ~1`.)

```
0000  54 01 00 40 00 00 00 00 00 00 02 00 00 00 00 00   DECI4 hdr, len 0x154, proto=0x20000
0010  00 10 c0 00 00 00 00 00 00 00 00 00 78 00 00 00   .c0. seq0 frag0 | key=0 | P.entry size=0x78
0020  45 00 01 40 01 00 03 00 50 43 53 45 30 30 30 30   pid | attrs=0x00030001 | "PCSE0000
0030  30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   0"  (36-byte ProcessName slot)
0040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   Affinity | Entry | GUID | ParentPID
0050  00 00 00 00 00 00 00 00 00 00 00 00 14 00 00 00   ... | StopReason.size=0x14
0060  04 00 02 00 01 00 00 00 00 00 00 00 00 00 00 00   Code=0x20004 | CodeId=1 | rsv | Attr
0070  0f 00 00 00 61 70 70 30 3a 65 62 6f 6f 74 2e 62   Pathname.len=0x0f | "app0:eboot.b
0080  69 6e 00 00 00 00 00 00 00 00 00 00 00 00 00 00   in\0" pad + exidx/extab tail (zeros)
0090  00 00 00 00 04 00 02 00 49 00 01 40 01 00 00 00   <end P.entry> Status=0x20004 | ThreadId | count=1
00a0  ac 00 00 00 49 00 01 40 6d 61 69 6e 00 00 00 00   T.entry size=0xAC | ThreadID | "main"
00b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   (name slot continues to +0x28)
00c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   InitAttr | CurAttr ...
00d0  01 00 00 00 01 01 00 81 00 00 20 81 00 00 10 00   Status=1 | Entry | StackTop | StackSize
00e0  00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 10   +0x40 | ArgSize | ArgBlock | InitPrio
00f0  00 01 00 10 00 00 00 00 00 00 00 00 00 00 00 00   Prio | InitAff | Aff | LastCPU
0100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   WaitType | WaitTarget | ClockRun(u64)
0110  14 00 00 00 04 00 02 00 01 00 00 00 00 00 00 00   StopReason.size=0x14 | Code=0x20004 | CodeId | rsv
0120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   Attr | ExitStatus | IntPreempt | ThrPreempt
0130  00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 7e   Release | ChangeCPU | VFP | CurrentPC=0x7E000100
0140  00 00 00 00 00 00 00 00 00 00 00 00 78 56 34 12   WaitTimeout | WaitDetail(u64) | <end T.entry> tick(lo)
0150  00 00 00 00                                       tick(hi)=0x12345678 -> 0x0000000012345678
```

`CurrentPC` is at ThreadInfo `ENTRY+0x9c` -> absolute payload `0xa4 + 0x9c = 0x140`; in the frame,
DECI4 hdr (0x10) + payload 0x130 = **frame offset 0x13d** = bytes `00 01 00 7e` = `0x7E000100` =
`completionBpAddr & ~1`. This is the field Razor's `get_PC` returns and compares to the slot-3
breakpoint address.

---

## 6. Evidence addresses

psp2tm (x64, `tmproj`): SET builder `FUN_1400d9810`; SET txn `FUN_140085980`; SET RES decode
`FUN_1400d2030`; SET consumer/mapping `FUN_14013f080`; SET printer `FUN_14021b6b0`; SET request
printer `FUN_1401e0e40`. CLEAR builder `FUN_1400d84f0`; CLEAR txn `FUN_140083e60`; CLEAR RES decode
`FUN_1400cffe0`; CLEAR printer `FUN_1401d0500`. STOP validator `FUN_1400d20f0`; notif dispatch
`FUN_14012c040`->`FUN_14011b140` (`case 0xc0`); event push `FUN_140068190`; StopNotification COM ctor
`FUN_1400aa4d0`, vtable `0x140314a18`, serialize `FUN_1402470b0`, print `FUN_1401f0680`. Suspend
handler `FUN_140140270`; Resume handler `FUN_14013af90`; error map `FUN_1401417a0` (0x20056->success,
0x20058->0x800402ff, 0x20050->0x80040249, 8->0x80040223). RES-name table `FUN_140078590`
(`0x4b SET_SWBRKPT_RES`, `0x4d CLEAR_SWBRKPT_RES`, `0xc0 STOP_NOTIFICATION`).

Razor (x86, `gproj2`): HUD finder+arm `FUN_101b1200`; connect wrapper `FUN_101b17e0` (model +0xfc);
bp set `FUN_101b1b30`->`FUN_1018d660`(split addr/attr)->`FUN_1018d6c0`(SetSoftwareBreakpoint +0x4c);
bp clear `FUN_1018d780`(+0x50); slot addr read `FUN_1018d650`; wait pump vtable `0x10511138`, done
predicate `FUN_10131d90` (run-state via model +0x98 `FUN_10130160`); OnStopNotification (IEventDebug
+0x1c) `FUN_101b4a50`; state event 9 handler `FUN_10133900`; bp-hit callback 10 `FUN_101b5300` (slot
3 `this+0x2c8`, benign return at `0x101b5666`); event-post `FUN_101b7aa0`->`FUN_101343e0`; state
dispatch `FUN_10133490`; select-process run-state derivation `FUN_101b6840`/`FUN_101b2c30`; teardown
`FUN_101b1e00`(cmd2, +0x100)/`FUN_101b1d00`(+0x108)/`FUN_101b0ba0`(cmd4, +0x10c); session
`DoCaptureInternal FUN_10258c30`, `RunCapture FUN_102595a0`, load `FUN_102589d0`.

TMAPI (`Interop.PSP2TMAPILib`, reflected): `IProcess.SetSoftwareBreakpoint`=+0x4c,
`ClearSoftwareBreakpoint`=+0x50; `IStopNotification` {get_Status +0x1c, get_ThreadId +0x20,
get_ProcessInfo +0x24, get_Threads +0x28}; `IThreadInfoCollection.GetById`=+0x28;
`IThreadInfo.get_PC`=+0x84 (wire ENTRY+0x9c); `IEventDebug.OnStopNotification`=+0x1c;
enum `eStopNotificationReason` (STOP_REASON_SOFTWARE_BRKPT=0x20004); `eSoftwareBreakPtAttr`
(32BIT_MODE=0, 16BIT_MODE=1); `eProcessAttr` (DEBUG_STATE=0x2, SUSPENDED=0x8, DEBUGGABLE=0x10000,
ATTACHED=0x20000).

Generator/self-check: `tmp/gen_bp_frames.py` (mirrors `FUN_1400d2030`, `FUN_1400cffe0`,
`FUN_1400d20f0`, and Razor's PC lookup; all asserts pass).
