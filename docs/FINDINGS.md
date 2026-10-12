# Connecting a retail PS Vita to Sony's Razor / Neighborhood - research findings

Date: 2026-09-13
SDK `C:\PSVITA\sdk` (3.570.011), Tools `C:\Program Files (x86)\SCE\PSP2\Tools`
Device: retail Vita, HENkaku/taiHEN, firmware modules dated 2017-03-17, LAN 192.168.1.8

---

## Update: the handshake is solved and a mock target connects

Ghidra decompilation of `psp2tm.exe` `FUN_1400e01b0` gave up the whole handshake, and a
Python mock target now gets past it. Wall 2 below is **no longer a wall**.

The target side of the greeting, exactly:

```
server -> target :  "DECI"                       (4 bytes)
target -> server :  15 A3 F8 E1                  (u32 BIG-ENDIAN magic 0x15A3F8E1)
target -> server :  00 00 00 40                  (u32 BE total length = 0x40 = 64)
target -> server :  <56 bytes>                   (14 x u32 BIG-ENDIAN fields)
```

Decompiled source of truth:

```c
send(sock, &DAT_140319380, 4);              // "DECI"
recv(sock, &magic, 4);   magic = bswap(magic);
if (magic == 0x15a3f8e1) {
    recv(sock, &len, 4); len = bswap(len);
    if (len == 0x40) {
        recv(sock, this+0xa0, 0x38);        // 56 bytes
        ... bswap 14 u32 fields at +0xa0..+0xd4 ...
        std::_Pad::_Launch(... CPSP2Socket member thread ...);   // CONNECTED
    }
}
```

Observed result with an all-zero 56-byte payload (`tools/mock_target.py`):

- The server **keeps the connection open indefinitely** (45s+) instead of closing instantly.
- It **starts sending protocol messages to us**, e.g.

```
1c 00 00 40  00 00 00 40  00 20 00 00  00 00 00 00      len 0x1c = 28
01 00 00 00  00 00 00 00  00 00 00 00

38 00 00 40  00 00 00 40  00 20 00 00  00 00 00 00      len 0x38 = 56
05 00 00 00  ff ff ff ff  01 00 00 00  01 00 00 00
12 00 00 00  "TM has timed out!\0"                      strlen 0x12 = 18
```

- `psp2ctrl find 127.0.0.1` now reports **`TMAPI_COMMS_ERR_TIMEOUT_TOOL_MANAGER`
  ("Target failed to reply")** instead of "Couldn't connect to PSP2 Network Manager" - i.e.
  Target Manager now treats us as a *real target that failed to answer*, not as an absent one.

Post-handshake framing (from those captures, INFERRED but consistent): **little-endian**, with a
u16 length at offset 0, a 2-byte tag `0x4000`, then what looks like protocol/channel ids
(`0x40000000`, `0x00002000`), a message code (1, then 5), and for text messages a u32 string
length followed by a NUL-terminated ASCII string. Note the reversal: the *hello* is big-endian,
the *session* messages are little-endian.

Useful side-discovery: `FUN_14007a800` is psp2tm's log-category name table -
1=DECI, 2=FILESERVER, 4=CLIENT, 8=TARGET, 0x10=CLIENT_CONTROLLER, 0x20=TARGET_CONTROLLER,
0x40=SERVICE, 0x80=EVENTNOTIFY, 0x100=API, 0x200=RESPONSE, 0x400=SOCKET, 0x800=FSD,
0x1000=COREFILE. `Server.xml` has a `<LogLevel>`; raising it should make psp2tm narrate the
handshake and the session protocol, which is the cheapest next lever.

Also note the binary is full of named protocol constants recovered by Ghidra:
`DECI4_DCMP_TYPE_STATUS` / `TYPE_ERROR` with codes `NOCONNECT`, `INVALHEAD`, `NOPROTOCOL`,
`NOSPACE`, `SUSPENDED`; plus `DECI4_TSMP_*` (e.g. `POWER_CONTROL_RES`) and `DECI4_DBGP_*`
(e.g. `GROUP_THREAD_TYPE_GET_FIBER_STACK_INFO_RES`). These map onto the `libdeci4p.h` error
codes and give the protocol vocabulary directly. Full dump: run `ghidra/deci_hunt.py` (its output is not committed).

Firmware note: the retail `PSV_CRC[...]_FW[v01.030]_PSVUPDAT.PUP` is **retail** firmware (its
segment 0x101 is a consumer update EULA) and contains no Razor modules. The correct source is
`PSVita_Firmware\3.570.011\Devkit Firmwares\PSP2UPDAT.PUP` (and the TestKit one), which match
SDK 3.570.011.

---

## What would actually have to be ADDED to a retail console (2026-09-13)

Firmware comparison, from the PUP headers (`tools/pup_info.py`):

| PUP | version.txt | segments | devkit-only segment ids |
|---|---|---|---|
| DevKit `3.570.011\Devkit Firmwares` | `3.57` | 56 | **0x221, 0x231** |
| TestKit `3.570.011\Testkit Firmwares` | `3.57` | 37 | **0x221, 0x231** |
| Retail `PSV_CRC[...]FW[v01.030]` | `01.030` | 53 | - |

Segments 0x221 and 0x231 are SELFs present ONLY in DevKit/TestKit firmware, and they are a
different SELF class from the rest (`hdr_type=3`, the `0x140`-type field reads `0x40`, and no
plaintext ELF header in the first 0x200 bytes, unlike segments 0x200/0x204 which expose one at
offset 160). Everything else of interest - the deci4p kernel modules, the Network Manager,
`librazorcapture_es4.suprx` - is inside the encrypted `0x30x` filesystem images.

**Transplanting devkit modules onto retail is NOT the answer.** Those modules are signed for
devkit, depend on devkit-only kernel exports, and retail's loader will not take them. Nothing in
the PUP is a drop-in.

**The answer is to re-implement the target side as a plugin**, which is viable because the whole
transport is ordinary TCP on port 8540 - proven today by a Python mock that Target Manager
accepts (see the UPDATE section). A retail Vita with taiHEN can open sockets and do everything
that mock does.

### Component map for a retail target

| Layer | What it must do | Feasible on retail? |
|---|---|---|
| TCP listener on 8540 | Accept the host's connection, always-on | Yes - kernel plugin with `ksceNet*` (as `net_logging_mgr.skprx` already does), or a user plugin in SceShell |
| Greeting | Answer `"DECI"` with the 64-byte big-endian hello: magic `0x15A3F8E1`, length `0x40`, 14 u32 fields | **Solved** - already working in the mock |
| Session framing | Little-endian, u16 length at offset 0, tag `0x4000`, ids + message code | Partly known; readable from psp2tm captures |
| DCMP control | `DECI4_DCMP_TYPE_STATUS` / `TYPE_ERROR`, codes NOCONNECT / INVALHEAD / NOPROTOCOL / NOSPACE / SUSPENDED | Needs RE, no blocker in principle |
| netmp | connect, register protocol, registered list - multiplexes the sub-protocols | Needs RE |
| Sub-protocols | DRFP (host file serving), TTYP (console), TSMP (power), DBGP (debug) | Each is separate work |
| Debug services | process/module enumeration, memory read/write, thread stop/resume - what Razor CPU actually needs | Possible only from a **kernel** plugin; taiHEN gives the required access |
| Identity: HWID | Host registers targets by HWID (`psp2ctrl add <hwid>`, 7-digit decimal seen in the logs) | Unknown whether wire-reported or host-side only |
| Identity: activation | `TMAPI_COMMS_ERR_DEVKIT_NOT_ACTIVATED`, `psp2ctrl activate <file>` | **The real wall** - signed material from Sony |

### Encouraging data point

The mock's hello was accepted with an **all-zero** 56-byte payload. So none of those 14 fields
is validated at handshake time - identity checking happens later (or is purely host-side
registry). That means the early milestones are reachable without forging identity, and the
activation wall only appears further in.

### What the devkit firmware is actually good for

Not code to transplant, but a **reference implementation** of the target side to read the
session protocol from, plus `librazorcapture_es4.suprx` for the offline-capture route.
Extracting it needs `sceutils`-class firmware tooling and keys for 3.57 devkit - not attempted
here (blocked by tooling policy; see notes). Cheaper alternative: keep reversing the HOST side
(`psp2tm.exe`), which we have complete access to and which has already yielded the handshake.

---

## Summary

**A retail Vita cannot be made to appear in Neighborhood / Target Manager as a live target by
writing a plugin.** Not because one specific trick is missing, but because four independent
layers are missing at once, and the bottom two are not implementable from user or kernel
plugins alone.

**What *does* work today:** Razor opens capture files offline with no target attached. A retail
Vita can produce those files. That path is real and reachable - see "The route that works".

---

## How Razor actually reaches a target

There is no Razor-specific socket. The chain is:

```
PSP2Razor.exe / PSP2Razor.dll
        |  COM: psp2tmapi.PSP2TMAPI.1  {E4D8E7FF-6FC9-47EE-81EB-1287EB37C010}
        |       InprocServer32 = Target Manager Server\api\psp2tmapix86.dll
        v
psp2tm.exe  (Target Manager Server, runs as a local service)
        |  named pipes \\.\pipe\... for local clients
        v
DECI4P over IP  -------------->  target's "PSP2 Network Manager"
```

Razor's profiling data rides a **DECI4P custom protocol channel**, the same mechanism the SDK
sample `developer_tools/api_deci4p` demonstrates:

- Host side: `ITarget.RegisterCustomProtocol(0x0003f000)`, `SendCustomProtocolData()`,
  `IEventCustomProtocol.OnPacketReceived()` - see `api_deci4p/tmapi/CustomProtocol.cs`.
- Target side: `sceKernelDeci4pOpen("name", protonum, bufsize)` / `Read` / `Write`
  - see `<libdeci4p.h>` and `api_deci4p/libdeci4p/main.cpp`. Max payload `0x10800`.

Razor additionally drives a dedicated Performance Analysis COM channel
(`IPerformanceAnalysis`, IID `4B774C15-82F7-4EFB-AA9F-791F0A28884F`) with `CreateArmTrace`,
`CreateGpuTrace`, `StartCapture`/`StopCapture`, `ReadTraceData`.

Razor CPU capture works by the host **halting the target and reading a buffer out of its
memory** - the SDK's own sample comments say so:

> `sceRazorCpuSync()` - "Synchronization - used to mark frame boundaries and to allow Razor
> (host tool) to stop the target and read the capture buffer"
> - `target/samples/sample_code/developer_tools/api_libperf/razor/main.c:148`

That is a debugger-grade link, not a telemetry stream.

---

## Captured protocol data (new, from live probing)

Sony's tools were driven locally and the wire traffic observed. `psp2tm.exe` was already
running; nothing was installed or modified.

**1. Target Manager probes TCP port 8540.**

`psp2ctrl find` (subnet scan) and `psp2ctrl find <host>` both make psp2tm open TCP connections
to `<host>:8540`:

```
TCP psp2tm 127.0.0.1:61287  -> 127.0.0.1:8540    SynSent
TCP psp2tm 127.0.0.1:61809  -> 127.0.0.1:8540    SynSent
UDP psp2tm 0.0.0.0:61534        (subnet sweep)
```

**2. The greeting is the 4-byte magic `DECI`.**

Listening on 8540 and accepting the connection captures what the server sends first:

```
[conn 1] accepted from 127.0.0.1:65108
[conn 1] recv 4 bytes:
0000  44 45 43 49                       |DECI|
```

It then **waits** for the target to answer (held open with no further traffic for 10s).

**3. The reply is validated as exactly 4 bytes, and all guesses were rejected.**

Sweeping candidate replies - `DECI`, `ICED`, `PSP2`, `VITA`, `NETM`, `DECI4`, `DECI4P`,
zero/one words in both endiannesses, 16-byte headers - produced an immediate close every time,
with `psp2ctrl` always reporting:

```
[ERROR]: Failure checking 127.0.0.1
[ERROR]: Couldn't connect to PSP2 Network Manager.
```

Replies longer than 4 bytes get `WinError 10054` (RST), confirming the server reads exactly
4 bytes, validates them, and hangs up on mismatch. The expected value is a specific 32-bit
constant; recovering it needs disassembly of psp2tm.exe (the greeting literal itself sits at
file offset `0x00318180`, as `DECI\0\0\0\0`, surrounded by a pointer table rather than a
sibling magic).

**Naming note:** `netmp` in these binaries is the *network management protocol* - the
"PSP2 Network Manager" the error text refers to. Other DECI4 sub-protocols visible in
psp2tm.exe include `DECI4_DRFP_*` (file serving, `DECI4_DRFP_FILE_STAT`,
`DECI4_DRFP_CODE_*`), `tsmp`, and `ctrlp`.

---

## The four walls

### Wall 1 - retail firmware has no DECI4P stack at all

Sony's own documentation states the scope plainly (SDK docs,
`Developer_Tools/libdeci4p-Overview_e-1_1.htm`):

> "libdeci4p is a library **on the Development Kit** that is used to support data exchanges
> with the development host computer. The library on the development host computer is the
> Target Manager API. By using the libdeci4p and Target Manager APIs, it is possible to
> implement connectivity between the applications on the development host computer and the
> applications on the Development Kit."


`os0:kd/` on the device (listed over FTP) contains **no `deci4p_*` modules, no debug protocol
modules of any kind**. Full list includes `acmgr`, `authmgr`, `crashdump`, `display`,
`excpmgr`, `gpucoredump_es4`, `iofilemgr`, `modulemgr`, `processmgr`, `sysmem`, `threadmgr`,
`usbdev_serial`, `usbstor*` - and nothing DECI-related.

Consequently `sceKernelDeci4pOpen()` and the whole `libSceDeci4p` export set do not exist on
the device. A plugin could not call the DECI4P API; it would have to **reimplement the entire
DECI4P transport** (framing, node IDs, protocol registration, fragmentation, flow control) from
scratch, against an undocumented binary protocol.

### ~~Wall 2 - the handshake is unknown~~ - BROKEN, see the UPDATE section above

The greeting response is `0x15A3F8E1` + length `0x40` + 56 bytes, recovered by decompiling
`FUN_1400e01b0`, and a mock target using it is accepted by Target Manager. What remains beyond
it is the session conversation (netmp / DCMP messages) - now observable directly, because the
server sends us its messages once the handshake passes.

### Wall 3 - target type, hardware ID, and devkit activation

Target Manager validates the peer on connect. Strings and APIs present in the tools:

- Target type: `DEVKIT_MODE_UNKNOWN` / `VITA` / `DOLCE`, `PLATFORM_TYPE_DOLCE`,
  `"Invalid target type"`, `OnDevKitMode`
- Hardware ID: `IPSP2TMAPI.AddTarget(bstrHardwareId)`, `TMAPI_ERR_INVALID_HWID`,
  `"String does not represent a valid hardware ID"`
- **Activation**: `TMAPI_COMMS_ERR_DEVKIT_NOT_ACTIVATED`,
  `"The DevKit requires activation... DevKit_TestKit_Activation-Users_Guide"`,
  and `psp2ctrl activate <file>` - "Updates the activation code of the default DevKit"

The Neighborhood logs on this PC show the wall being hit already:

```
Neighborhood for PSP2.1.log :  Command line: addtarget -h 6556100   (2026-09-09 18:49)
Neighborhood for PSP2.log   :  Command line: addtarget -h 1444602   (2026-09-13 18:32)
```

and `AppData\Local\SCE\PSP2TM\Server.xml` still reads `<Targets/>` - neither registration
stuck. Targets are registered by **HWID**, not IP; a retail unit has no devkit HWID and no
activation code, and activation is a signed artifact issued by Sony.

### Wall 4 - the payload protocols on top

Even a connected target would then need to serve what Razor asks for: process/module
enumeration, memory read/write, thread stop/resume, the PA channel (`CreateArmTrace`,
`CreateGpuTrace`), and the file-serving protocol (DRFP). Each is a separate undocumented
protocol.

Walls 3 and 4 are why this is not a matter of persistence: even a perfect DECI4P
implementation on the Vita fails at activation, which is cryptographic material you do not
have.

---

## The route that works

Razor's file formats open **with no target connected** - confirmed from PSP2Razor.dll's own
file filters and error strings:

| Format | Meaning |
|---|---|
| `.sgx` | Raw GPU capture |
| `.rzr` | Razor Capture File (magic `RZR `) |
| `.pmon` | Raw GPU trace |
| `.raw` | Raw CPU capture |
| `.psp2dmp` / `.bin` | GPU core dumps |

Windows already associates `.rzr` with
`C:\Program Files (x86)\SCE\Common\Razor\binx64\razor-launcherx64.exe "%1"`.

And the on-device API is explicitly designed to write those files itself
(`<razor_capture.h>`):

```c
void sceRazorGpuCaptureSetTrigger(uint32_t frameIndex, const char *captureFilename);
void sceRazorGpuCaptureSetTriggerNextFrame(const char *captureFilename);
void sceRazorGpuCaptureEnableSalvage(const char *salvageFilename);  // capture on GPU crash
bool sceRazorGpuCaptureIsInProgress(void);
```

`EnableSalvage` is directly relevant to GPU crashes: it keeps the last ~20 GPU jobs in a
ring buffer and writes a loadable capture when the GPU faults.

### What that route needs

1. **`librazorcapture_es4.suprx`, decrypted from devkit firmware**, placed at
   `ur0:data/librazorcapture_es4.suprx`. Retail firmware does not ship it - `vs0:sys/external/`
   on the test console has `libperf.suprx`, `libsulpha.suprx`, `libdbg.suprx` but no Razor modules.
   This is the one hard prerequisite, and it has to come from a DevKit firmware dump.
2. **A plugin to load it and pull the trigger.** Prior art exists:
   [Rinnegatamante/RazorCap](https://github.com/Rinnegatamante/RazorCap) - loads the module,
   fixes the `sceIoOpen` mode it requests, and triggers a capture on START+SELECT+LEFT.
3. **A one-line engine change.** Razor counts capture frames by calls to
   `sceGxmPadHeartBeat()`, and the GXM RHI never calls it - verified across
   `Engine\Source\Runtime\PSP2\`. Without it a trigger never fires. Add it next to
   `sceGxmDisplayQueueAddEntry()` in `GXMViewport.cpp:831`.

Note the engine already has the build switch for the rest: `UEBuildPSP2.cs:144`
`bEnableRazorProfiler = false`, which when true links `SceRazorCapture_stub`,
`SceRazorHud_stub` and `ScePerf_stub`. The comment there also records why it is off - retail
units lack ScePerf, and `sceRazorCpuPushMarkerWithHud` resolves to address 0.

---

## Pushing on the Neighborhood path

In order, each step gated on the previous:

1. **Disassemble psp2tm.exe** (Ghidra is free) and find the code that sends the `DECI`
   literal at file offset `0x00318180`, then the comparison applied to the 4 bytes read back.
   That yields the response constant. This is the only step that is cheap.
2. Map the netmp message set from the `sn::CNetmp*` request/response classes in
   `psp2tmapix64.dll` (they are RTTI-named, so the class list is readable).
3. Build a PC-side fake target first - a Python service on 8540 - and iterate against
   `psp2ctrl find` / `add` / `connect` until Target Manager lists it. **Do this on the PC, not
   the Vita**, because the edit-run loop is seconds instead of minutes.
4. Only if a fake target ever reaches "connected" does porting to a Vita kernel plugin make
   sense - and step 3 is where activation/HWID will stop it.

The probe tools in `tools/` implement step 3's starting point.

---

## Tools included

| File | Purpose |
|---|---|
| `tools/deci_probe.py` | Listen on 8540, log everything Target Manager sends, never reply |
| `tools/deci_reply.py` | Same, but answer the greeting with a configurable payload and log what follows |
| `tools/deci_sweep.py` | Sweep candidate replies, using `psp2ctrl`'s error text as the oracle |

Run: `python tools/deci_probe.py 8540 60`, then in another shell
`psp2ctrl find 127.0.0.1`. All traffic stays on localhost.
