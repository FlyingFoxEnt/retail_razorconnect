# Neighborhood tool support - what each needs, and where we are

Every Neighborhood/SDK tool speaks its own DECI4 protocol over the same TCP 8540 session.
Protocol numbers below are confirmed from the per-protocol frame accessors in psp2tm.exe
(each tests `*(int*)(frame+8) == N`) paired with the "Decoding &lt;NAME&gt;" log string of the
validator that calls it.

| Tool | Protocol | Status | What is still needed |
|---|---|---|---|
| **Target discovery / Neighborhood listing** | TSMP `0x2000`, NETMP `0x1000` | **DONE - working on the retail Vita** | - |
| **Console Output** | TTYP `0x800300NN` | **Real device output wired** via `rrc_tty.skprx` (kernel printf on stream 0x90, every process's printf/stdout/sceClibPrintf on stream 0x00) | stderr is not separated from stdout (the putchar sink does not say which fd wrote); console input not implemented |
| **Battery Monitor** | PMEP `0x4000` | **Implemented, awaiting test** | decoded: validator `FUN_1400cedb0(msg, code)`, odd codes are RES with bodies 1=0xc, 3=8+wchar blob, 5=8, 7=4, 9=4. Fed live from `scePowerGetBatteryVolt/Temp/RemainCapacity/LifePercent/IsBatteryCharging`. |
| **Screen Capture** | VCP `0x2b000` | **Protocol solved and implemented** (`VCP_FORMAT.md`); the plugin answers FREEZE / GET_COMP_PICT with a black 960x544 image | real pixels: read the foreground framebuffer (kernel `ksceDisplayGetFrameBufInfoForPid`) |
| **Controller Capture / Replay** | CTRLP `0x2c000` | Protocol identified, not implemented | `DECI4_CTRLP_CODE_REC_DATA_NOTIFICATION` (record, target pushes pad state) and `PLAY_DATA_CMD/RES` (replay, host injects) |
| **Razor CPU trace** (Function Sampling) | PAMP `0x28000` + DBGP + VCP | **WORKING on the retail Vita (3.74).** Razor captures and opens it: per-thread timeline per CPU, PC-sample histogram (27 s SceShell capture: 2320 intervals, 1652 PC samples, 0 register or resume errors, mean sampler pass 90 us). **17/09:** long captures no longer come back empty (the trace is encoded window by window; 170 s scripted capture: 1.13 MB, 15032 intervals, no scheduler warnings) and the running game is offered as the debuggable process (SceAppMgr lists fail above 20 entries; the plugin asked for 24) | PA trace synthesised from 1 kHz software samples (`PAMP.md`, `RAZOR_*_FORMAT.md`). Keeps the newest 32768 records. Not available: Full Instrumentation (needs hardware PFT), callstacks, syscalls, user markers; screenshot is black |
| **Razor GPU trace** | PAMP CreateGpuTrace (cmd 4 sub 2) | **Implemented, awaiting a device run:** the UE4.15 GXM RHI records per-scene GPU timing to `ux0:data/gxm_gpu_*.csv` while `ux0:data/rrc_capturing` exists (`GPU_PROFILING.md`); at Stop the plugin converts the last 900 frames into a `.pmon` (`plugin/pmon_trace.c`) that Razor loads offline with no errors (0x71a solved, `PMON_SYNTH_NOTES.md` round 4) | Jobs are modelled from the CSV (all four USSE cores, EndScene-to-submit vertex window), not measured by GPU hardware. `.sgx` frame capture still needs the DevKit module |
| **Event Viewer / debugger** | DBGP `0x20000` | Partly: process, module, thread lists and attach/suspend acknowledgements (for Razor) | real stop/resume, memory read/write, breakpoints, core dumps |
| File serving (host0:) | DRFP / RDRFP `0x12000` | Not started | serve PC files to the target |
| **Install Package** (VPK) | unidentified | Not started | Neighborhood's Install returns `Target not ready (no protocol)` (0x8004029A) -- it wants a protocol we do not advertise. Host-side classes are `AVCPackageInstallRequest/Response`, `AVCInstallProgressNotification`, `AVCInstallCompleteNotification`. Would mean receiving package data and installing it, i.e. reimplementing the devkit package manager. |
| Process load (`psp2run`) | LOADP `0x24000` | Not started | receive and start an executable |

Other protocol numbers seen but not yet attributed: `0x100` (DCMP, control/errors),
`0x3000` (CPUP - we answer a stub), `0x11000`, `0x20052`, `0x2e000`.

## Effort

**Reachable with the current architecture** (user plugin in SceShell, protocol work only):

- Console Output - already implemented, needs verification.
- Battery Monitor - the Vita exposes real battery data to a user plugin. The work is
  decoding three PMEP response bodies. Realistically a short project.
- Screen Capture - `sceDisplayGetFrameBuf` from SceShell gives a framebuffer. The work is the
  VCP message set plus whatever pixel/compression format `GET_COMP_PICT` expects.
- Controller Capture - recording pad state is easy (`sceCtrlPeekBufferPositive`); replay means
  injecting input, which from a user plugin is limited.

**Blocked or disproportionate:**

- **Razor Profiler.** Two independent problems. The PAMP protocol is undocumented, and more
  fundamentally the profiling data comes from Razor's own on-device modules
  (`librazorcapture_es4.suprx`, `librazorhud_es4.suprx`) which retail firmware does not ship.
  Even with the protocol solved there would be nothing to feed it.
  **The practical route to GPU profiling remains offline `.sgx` captures** - load
  `librazorcapture_es4.suprx` (extractable from the DevKit 3.570.011 PUP) and open the capture
  in Razor. That path needs no target link at all. It also needs the one-line
  `sceGxmPadHeartBeat()` addition in `GXMViewport.cpp:831`, because Razor counts capture frames
  by that call and the GXM RHI never makes it.
- **Event Viewer / debugger (DBGP).** The largest of the set: process/thread enumeration,
  memory read/write, breakpoints, core dumps. Needs kernel access, which is exactly where the
  kernel-socket attempt failed. It would mean a hybrid design - user plugin for transport, a
  kernel helper for the debug services.

## Suggested order

1. Verify Console Output end to end (in progress).
2. Battery Monitor - small, self-contained, and proves a second tool works.
3. Screen Capture - high visible payoff.
4. Controller Capture (record only).
5. Leave Razor and DBGP alone unless the offline capture route proves insufficient.
