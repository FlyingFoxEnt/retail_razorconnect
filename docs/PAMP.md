# PAMP (protocol 0x28000): Performance Analysis, as psp2tm.exe speaks it

PAMP carries TMAPI's `IPerformanceAnalysis` interface (IID 4B774C15-82F7-4EFB-AA9F-791F0A28884F)
between Target Manager and the target. Razor's CPU trace is built on it (see
`RAZOR_PA_TRACE_FORMAT.md`). Everything below is from psp2tm.exe 3.60.0.2:
encoders FUN_1400db510..FUN_1400dd840, response validator FUN_1400cec60, payload accessor
FUN_1400d5380, request/wait FUN_140090e80, notification handler FUN_140131a60.
`tools/mock_pamp.py` implements the target side.

## Framing

Ordinary DECI frame (`u24 len | 0x40 | u16 flags | u16 node | u32 proto=0x28000 | u32 0`),
little-endian payload.

Request (host -> target):
```
+0x00 u32 command
+0x04 u32 requestId      incremented per request (psp2tm +0x270)
+0x08 u32 length         psp2tm writes total-0x10; do not rely on it, use the frame length
+0x0c ... body
```

Response (target -> host), matched on (command, requestId), 5 s timeout:
```
+0x00 u32 command        same as the request
+0x04 u32 requestId      same as the request
+0x08 u32 bodyLength
+0x0c u32 result         0 = OK; anything else fails the TMAPI call
+0x10 ... body[bodyLength]
```

Notifications (target -> host, unsolicited), same layout as a response with requestId 0:

| command | name | body |
|---|---|---|
| 0x80000000 | START_NOTIFICATION | u32 `ePAStartReason` (0 CAPTURE, 1 SYSTEM_CALL, 2 TRIGGER) -> `IEventPA.OnTraceStart` |
| 0x80000001 | STOP_NOTIFICATION | u32 `ePAStopReason` (0 CAPTURE, 1 SYSTEM_CALL, 2 TRIGGER, 3 BUFFER_1_OVERFLOW, 4 BUFFER_2_OVERFLOW) -> `OnTraceStop` |
| 0x80000002 | TRACE_DATA_NOTIFICATION | u32 (buffer?) then `bodyLength-4` data bytes -> `OnTraceData` |

## Commands

Numbering follows the `IPerformanceAnalysis` method order.

| cmd | TMAPI method | request body | response body |
|---|---|---|---|
| 0x00 | `Open` | - | - |
| 0x01 | `Close` | - | - |
| 0x02 | `TraceBufferAvailableSize` | - | u32 bytes |
| 0x03 | `Config*TraceBuffer` | u32 sub (0 Normal, 0x10000 VSync, 0x10001 Timer, 0x10002 OnSize) + u32 bufferId, bufferType, bufferSize, probeSelectMask [+ u32 vsyncCount/period/size] | - |
| 0x04 | `Create*Trace` | u32 sub + args. sub 0 ARM: `u32 traceMode, u32 sampleMode, u16 tsPeriod, u16 samplePeriod, u32 pid` (16). sub 1 Counter (0x18). sub 2 GPU (0x48) | - |
| 0x05 | `DestroyTrace` | u32 traceType | - |
| 0x06 | `StartCapture` | - | - |
| 0x07 | `StopCapture` | - | - |
| 0x08 | `GetTraceInfo` | - | u32 bufferStatus, u32 buffer1Bytes, u32 buffer2Bytes |
| 0x09 | `ReadTraceData` / `FetchTraceData` | u32 bufferId, u32 offset, u32 count | **one or more** responses, each `u32 more` + data; psp2tm appends data until a response with `more == 0` |
| 0x0a | `Set*TriggerCond` | u16 sub (0 ProcessLaunch, 1 ProcessExit, 2 FramePeriod, 3 Timer, 4 Breakpoint), u16 startStop, u32 pid, + per-sub | - |
| 0x0b | `ClearTriggerCondition` | u16 triggerType, u16 startStop, u32 pid | - |
| 0x0c | `SetBookmarkConfig` | 20 bytes | - |
| 0x0d | `GetBookmarkConfig` | - | 20 bytes (5 u32) |
| 0x0e | `ClearBookmarkInterruptCounts` | - | - |
| 0x0f | `GetBookmarkInterruptCounts` | - | 0x88 bytes |
| 0x10 | `GetGpuSampledData` | - | 16 bytes |
| 0x11 | `InsertBookmark` | u32 fifo, u32 channel, u32 data | - |
| 0x12 | `TimebaseFrequency` | - | u32 (Razor requires **333**) |

Razor fetches buffer id **0** in chunks of up to 4 MiB; a response frame can carry at most
~0x10000 bytes of data, so a large read is many cmd-9 responses with `more = 1`.

## Other host-side requirements for a Razor CPU capture

Seen in psp2tm's log while Razor ("PS Vita Razor CPU (stand-alone)") starts a capture:

1. `GET_PROCESS_INFO_SNAPSHOT_LIST`: exactly one process must carry
   `PROCESS_ATTR_DEBUGGABLE` (0x10000), else "No debuggable processes found" and Razor tries to
   `LOAD_PROCESS` an ELF instead.
2. `REQUEST_PROCESS_LOCK`, `REQUEST_DEBUG_EVENTS`, `REQUEST_PA_EVENTS` (host side only).
3. `GET_MODULE_INFO_LIST` -> DBGP 0x40/0x00 (`DBGP_MODULE_THREAD_FORMAT.md`).
4. `GET_MODULE_META_DATA` -> DBGP 0x40/0x02.
5. `SET_PROTOCOL_IN_USE {0x20000, "SCE PSP2 Razor"}` then `ATTACH_PROCESS` -> DBGP 0x20/0x10.
6. PAMP sequence from `CPSP2Target::ConfigurePerfmon` (see RAZOR_PA_TRACE_FORMAT.md).
