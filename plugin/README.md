# retail_razorconnect - a retail PS Vita as a Target Manager / Neighborhood target

`psp2ctrl find 192.168.1.8` returns the console as a target:

```
HardwareId                       Name    Host        ConnectionInfo NetMgr  CP      Kernel
00000000000000000000000100160afa PS Vita 192.168.1.8                0.0.0.0 0.0.0.0 0.000
```

TCP handshake and UDP discovery both verified directly against the device.

## What to install

Use the **user** plugin. `retail_razorconnect.suprx` goes in `ur0:tai/` and is listed under
`*main` (SceShell) in `ur0:tai/config.txt`:

```
*main
# main is a special titleid for SceShell
ur0:tai/henkaku.suprx
ur0:tai/retail_razorconnect.suprx
```

Reboot after changing it (`*main` plugins are injected when SceShell starts; a taiHEN config
reload is not enough). It logs to `ux0:data/rrc.log`:

```
--- rrc user plugin start ---
sysmodule net load 0x00000000
net ready after tries 0x00000000
tcp listening on 8540
udp listening
```

To remove it: delete `ur0:tai/retail_razorconnect.suprx` (taiHEN skips a missing plugin) or
drop the config line.

## Console Output: also install `rrc_tty.skprx`

`rrc_tty.skprx` is what makes Console Output show the device's real output: kernel printf,
and every process's SceLibc `printf` / stdout and `sceClibPrintf` (the UE4 PSP2 port logs
through `printf("%ls")` in `PSP2PlatformMisc.cpp`). It goes under `*KERNEL`, **after**
`net_logging_mgr.skprx`:

```
*KERNEL
...
ur0:tai/net_logging_mgr.skprx
ur0:tai/rrc_tty.skprx
```

Kernel plugins need a reboot.

How it works (details in `rrc_tty.c`): a retail kernel still sends all debug output to the two
sinks in SceSysmem that a DevKit's TTY uses - the putchar handler and the kprintf handler -
with nothing registered on them. `rrc_tty` registers both, tags each chunk with the TTYP stream
(`0x00` STDOUT for user processes, `0x90` KERNEL0 for the kernel), process id, thread id and
tick, and holds it in a 1024-chunk ring. The SceShell plugin drains the ring through the
`rrcTtyRead` syscall and pushes each chunk as a TTYP frame to the newest live session. Output
from before a tool connects (boot included) waits in the ring and is delivered on connect.

- Only one handler of each kind exists, so whichever module registers last wins. Listed after
  `net_logging_mgr`, `rrc_tty` gets the output and PrincessLog stops receiving it.
- `rrc_tty` links the 3.63+ `SceDebugForKernel` NIDs (library `0x13D793B7`). On older firmware
  it fails to load cleanly.
- It is optional. Without it the plugin still loads (the import is weak and checked before
  use), logs `rrc_tty.skprx not loaded`, sends one warning line to Console Output, and forwards
  only what is appended to `ux0:data/rrc_console.txt`.

`ux0:data/rrc.log` records whether capture linked, the handler registration results, and a
self-test that prints once through `sceClibPrintf` and once through stdout, with how many
characters each path delivered to the capture.

## Razor CPU trace: also install `rrc_pa.skprx`

`rrc_pa.skprx` lets PS Vita Razor's **Perform CPU Trace** (capture mode *Function Sampling*)
run against the retail console. **Verified on the 3.74 test console**: a 27 s capture of
SceShell gave 2320 scheduler intervals and 1652 PC samples with no register-read or resume
errors, and Razor opened it with the thread timeline per CPU. It goes under `*KERNEL`, after
`rrc_tty.skprx`:

```
*KERNEL
...
ur0:tai/rrc_tty.skprx
ur0:tai/rrc_pa.skprx
```

Reboot after adding it. `ux0:data/rrc.log` then says `rrc_pa capture linked - Razor CPU trace
available`.

What a capture does, end to end (formats in `../docs/PAMP.md`, `../docs/DBGP_MODULE_THREAD_FORMAT.md`,
`../docs/VCP_FORMAT.md`, `../docs/RAZOR_*_FORMAT.md`):

1. Razor lists processes. A running application is reported as the one *debuggable*
   process (SceShell itself when no application is running). SceAppMgr's app lists fail from
   the plugin (`0x8002710B`, logged as `appmgr probe` in `rrc.log`), so the plugin finds the
   game from its console output: `rrc_tty` tags every chunk with the printing pid, and a pid
   that still exists is offered (`proc list` lines in `rrc.log`). A game that has not printed
   anything since the plugin connected is not seen, so start the game before Razor's capture.
2. It lists that process's modules and every process's thread names (DBGP, answered from
   `rrc_pa` because user mode cannot inspect another process), attaches, suspends and resumes.
   Those three only flip flags here: nothing on the console is stopped.
3. It takes a screenshot (VCP). The image is black for now; Razor refuses to capture without one.
4. It configures and starts the Performance Analysis trace (PAMP). `rrc_pa`'s samplers start:
   one kernel thread per game core (0-2), pinned there at a priority above every user thread.
   Each wakes every millisecond, finds the traced process's threads that ran on its core since
   the last tick (runClocks), and reads the user registers of the one it preempted. Register
   reads need the thread suspended (`0x80028030` otherwise, even for a READY thread), so it is
   debug-suspended (status `0x1002`) for the read and resumed at once.
5. On **Stop**, `rrc_pa` turns the records into per-core on-CPU intervals and PC samples
   (`pa_trace.c`) in the DevKit's PA trace format (`pa_encode.c`): scheduler switch packets as
   FIFO B SYS_0 bookmarks, PC samples as CoreSight PFT I-sync packets. Razor reads it back and
   opens the capture: a thread timeline per CPU and a PC-sample histogram per function.
   The trace is never held whole: Stop sorts the records and measures the trace, and each read
   encodes the requested window into a fixed 100 KB kernel buffer. (Until 17/09 Stop encoded
   everything into one block sized 128 bytes per record; with a full ring that 4 MiB kernel
   allocation failed and Razor said **"Cannot capture. Capture buffer is empty."**)

The sampler keeps the newest 32768 records (`rrc_pa ring records` in `rrc.log`) and drops older
ones, like Razor's *Wrap Trace Buffer*. SceShell alone fills that in about 2.5 minutes; a game
with many busy threads fills it in seconds, so a long capture shows its last seconds.

When it asks for the executable, point it at the game's `.self` with symbols (for Vita_Testing,
`Binaries\PSP2\Vita_Testing.self`, or the copy kept with the deployed build) or answer No: the
timeline still works, samples stay unnamed. The process's main module is listed first, which
is the one Razor treats as the executable.

To test the console side without Razor, `../tools/pa_capture` runs the same capture over
TMAPI (`pa_capture procs`, `pa_capture cpu <seconds> out.raw`) and
`../tools/check_trace_file.py out.raw` decodes the result the way Razor does.

Pick **Capture > CPU Trace With Options... > Function Sampling** at least once: a fresh Razor
defaults to Full Instrumentation, which needs DevKit trace hardware. The plugin reports the
console as powered ON even on battery, because Razor refuses to capture from a target whose
power status is NO_SUPPLY ("Target power is unplugged").

Limits: samples are 1 kHz software samples, not hardware trace, so Full Instrumentation mode
is not available; no callstacks, syscalls or user markers; the screenshot is blank. The GPU trace
is separate (next section).
Diagnostics for the last capture (records, PC samples, register-read errors, slowest sampler
pass) are written to `rrc.log` at Stop.

## Razor GPU trace (needs the game's GPU profiler)

A retail console has no GPU trace hardware path, so the GPU trace is built from the game's own
measurements: a UE4 Development build with `GXMGpuProfiler.cpp` (see `../docs/GPU_PROFILING.md`)
records per-scene GPU timing to `ux0:data/gxm_gpu_<unix time>.csv` while
`ux0:data/rrc_capturing` exists. The plugin creates that file at capture start and removes it
at Stop. For a GPU trace it then waits up to 2 s for the recorder to finish the CSV (its last line
is `# end,frames,N`) and converts the last 900 frames into the `.pmon` Razor loads
(`pmon_trace.c`, the same bytes as `../tools/pmon_synth.py`; rules in
`../docs/PMON_SYNTH_NOTES.md`, "Round 4"). The conversion is streamed like the CPU trace, in a
640 KB block: nothing is written to the memory card. `rrc.log` lists the CSV, the `.pmon`
size, frames, jobs, samples and the conversion time (`gpu trace:` lines).

What Razor shows is modelled, not measured by GPU hardware: every GPU job is drawn on all four
USSE cores, vertex work is the EndScene-to-submit window and fragment work runs from submit to
the scene's completion fence. Frame numbers, per-scene draw counts and the frame, vsync and
scene-construction rows come straight from the game.

`../tools/pa_capture` can run the same capture without Razor (`pa_capture gpu <seconds> out.pmon`);
the result opens in Razor with `PSP2Razor.exe out.pmon`, and `../tools/check_pmon.py out.pmon`
checks it against Razor's job rules.

## Do NOT use the kernel build

`retail_razorconnect.c` is the kernel-mode attempt. Its source is kept for reference only
(no binary is published).
It loads and binds sockets, and `ksceNetAccept` works, but **every `ksceNetRecvfrom` fails with
`0xC0022005`** - the kernel net stack will not write into module `.bss` or a thread stack. The
`ksceKernelAllocMemBlock` workaround crashed the console. Do not install it.

## Gotchas, in the order they bit

1. **GCC emits libc calls in a freestanding module.** Byte loops become `memset`/`memcpy`/
   `strlen`, which do not exist. Build with `-ffreestanding -fno-builtin` *and* define them.
2. **Kernel net buffers** - see above. This is why the design is user-mode.
3. **`Library not found: [SceNet, ver=1]`.** A *strong* `SceNet` import makes the module load
   fail outright, because when taiHEN injects a `*main` plugin SceShell has not loaded the
   network library yet. Link `-lSceNet_stub_weak` and call
   `sceSysmoduleLoadModule(SCE_SYSMODULE_NET)` before the first socket call.
   That error names the offending library, which makes it a fast diagnostic loop.
4. **Thread functions are in `SceKernelThreadMgr_stub`**, not `SceLibKernel_stub`.
5. **`SCE_NET_SO_RCVTIMEO` takes an `int` in microseconds**, not a timeval. There is no
   `SceNetTimeval` in VitaSDK; code using one does not compile.
6. **A session socket has two writers** (the session thread's replies and the console pushes).
   Every write goes through the slot mutex, or frames interleave and psp2tm drops the stream.
7. **Sleep breaks the TCP listener.** After the console slept, the PC still found it (UDP
   discovery answered) and TCP connects completed in the kernel's backlog, but `sceNetAccept`
   never handed over another connection: no "got DECI" in `rrc.log`, no handshake, nothing to
   reconnect to until a reboot. See "Sleep and wake-up".

## Sleep and wake-up

Since 22/09 the plugin starts its network afresh when the console wakes from sleep or its
Wi-Fi comes back:

- A power callback (`SYSTEM_RESUMING` / `SYSTEM_RESUME`), or SceNetCtl's state returning to
  CONNECTED, ends every session and reopens the TCP and UDP listeners. The PC tools reconnect
  as they would after a DevKit reboot. The SceNetCtl watch is what vitacompanion and vdbtcp
  use; its import is weak and only read (SceShell owns netctl), so the plugin loads without it.
- Both listeners are non-blocking and polled every 100 ms, so their threads never wait inside a
  call on a socket the stack has dropped. Each also reopens its socket after three failures
  in a row, with or without a wake-up.
- Session sockets have a 10 s send timeout. A PC that went away while the console slept can no
  longer hold the send lock (and with it every other session's replies) for the minutes TCP
  spends retransmitting; a console push that fails ends that session.
- When all 8 slots are taken, a new connection replaces the session that has received nothing
  for longest (at least 10 s) instead of being dropped.

`rrc.log` shows it: `power callback registered` and `netctl state 0x00000003` at start, then
per wake-up `woke from sleep: resetting the network, power events 0x000N0000` and/or
`netctl state ...` followed by `Wi-Fi connected again: resetting the network`, then
`tcp listener reopened after wake-up`, `udp socket reopened after wake-up` and
`tcp listening on 8540` / `udp listening`. `tcp accept failed`, `udp receive failed` and
`... keeps failing - reopening it` mark the fallback path.

## Protocol

Full specification in `../docs/PROTOCOL.md`. The plugin implements:

- DECI handshake: `"DECI"` -> u32be `0x15A3F8E1`, u32be `0x40`, 56 bytes
- TSMP (0x2000): TARGET_LIST, SELECT/DESELECT, HW_INFO (CPID), SW_INFO, STICKY_NOTE,
  EXPIRY, USB_INFO, POWER_STATUS, GET_SETTINGS, SETTINGS_XML
- NETMP (0x1000): CONNECT, PROTO_LIST (advertises NETMP, TSMP, CPUP, TTYP stream 0x00,
  TTYP stream 0x90 and PMEP, each with a non-zero node), REGISTER/UNREGISTER,
  REGISTERED_LIST, DISCONNECT, FORCE_*
- CPUP (0x3000): code 0 -> 1 stub, avoids a 5s stall per session
- PMEP (0x4000): Battery Monitor values from `scePower*`
- TTYP (0x800300NN): pushed console output, NN = `eConsoleOutputStream` (0x00 STDOUT,
  0x01 STDERR, 0x02-0x07 USER2-7, 0x90-0x93 KERNEL0-3). psp2tm computes the stream as
  `proto + 0x7ffd0000` and joins text per (stream, process, thread).
- UDP discovery on 8540: UDP_FIND_TARGET_CMD -> RES
- DBGP (0x20000): process list; for Razor, module list and metadata, thread info and names,
  attach/detach, suspend/resume (acknowledged, not performed), empty sync-object, app-object,
  stack and fiber lists. Any other DBGP request is refused at once instead of timing out.
- PAMP (0x28000): the whole `IPerformanceAnalysis` command set, backed by `rrc_pa.skprx`.
- VCP (0x2b000): FREEZE and GET_COMP_PICT screenshot (zlib stream of stored blocks).

Not implemented yet: console *input* (TTYP from the host), real debugging (memory, breakpoints),
the screenshot's actual pixels.

## Building

In WSL with VitaSDK at `$HOME/vitasdk`, from this directory:

```
bash build_tty.sh     # rrc_tty.skprx + libRrcTty_stub_weak.a
bash build_pa.sh      # rrc_pa.skprx  + libRrcPa_stub_weak.a
bash build_user.sh    # retail_razorconnect.suprx (links both stubs above)
```

All copy their output back here. `build.sh` builds the deprecated kernel network plugin.

PC-side test tools in `../tools`:
- `mock_ttyp.py` pushes TTYP frames exactly like the plugin.
- `mock_pamp.py` is a complete Razor CPU-capture target on 127.0.0.1 (DBGP, PAMP, VCP); feed it
  a trace from `gen_trace.py` to check Razor's side without the console.
- `check_pa_encode.py` builds `pa_encode.c` for the PC (MSVC) and decodes its output with the
  Python mirrors of Razor's decoders.
