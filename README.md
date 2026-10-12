# retail_razorconnect

taiHEN plugins that make a retail PS Vita show up as a target in the PS Vita SDK's Target
Manager and Neighborhood, so Console Output, Battery Monitor and Razor CPU/GPU captures work
without a DevKit.

The plugins answer the DECI4 protocols the SDK tools speak on port 8540 (TSMP, NETMP, TTYP,
PMEP, DBGP, PAMP, VCP). All of it was worked out from the PC side; the notes are in
[docs/](docs/).

This project is not affiliated with Sony. The SDK tools themselves (Target Manager,
Neighborhood for PSP2, psp2ctrl, PSP2 Razor) are not included.

## What works

- Target discovery and the Neighborhood listing
- Console Output: kernel printf and every process's printf / stdout / sceClibPrintf (needs `rrc_tty.skprx`)
- Battery Monitor, with live values from scePower
- Razor CPU trace in Function Sampling mode: per-CPU thread timeline and PC-sample histogram
  (needs `rrc_pa.skprx`)
- Razor GPU trace for a UE4.15 game built with the GPU recorder in [ue4_15/](ue4_15/)
- The tools reconnect after the console sleeps or its Wi-Fi drops

Not done yet: Screen Capture answers but the picture is black, there is no real debugger
(only the process/module/thread queries Razor needs), and controller capture, package install
and psp2run are not implemented. [docs/FEATURES.md](docs/FEATURES.md) has the details.

## The plugins

There are three modules. Only the first one is required. The user plugin imports the two
kernel modules weakly, so if one is missing it still loads and just turns off what needs it.

- `retail_razorconnect.suprx` (user, SceShell): discovery and the TCP sessions for every tool.
- `rrc_tty.skprx` (kernel): captures the console's debug output for Console Output.
- `rrc_pa.skprx` (kernel): thread and module lists, process memory reads, and the CPU sampler
  behind Razor's CPU trace.

Prebuilt copies are in [plugin/](plugin/).

## Requirements

- A PS Vita running HENkaku / taiHEN. Tested on 3.74. The kernel modules use 3.63+ NIDs and
  won't load on older firmware.
- The console and the PC on the same network.
- Windows with the PS Vita SDK host tools. Tested with SDK 3.570.011.
- To build: Linux or WSL with [VitaSDK](https://vitasdk.org) in `~/vitasdk`.

## Installing

Copy the three files to `ur0:tai/` (VitaShell over FTP or USB works) and add them to your
taiHEN config. That's `ux0:tai/config.txt` if you have one, otherwise `ur0:tai/config.txt`.
The kernel modules go at the end of `*KERNEL`, the user plugin under `*main`:

```
*KERNEL
...
ur0:tai/rrc_tty.skprx
ur0:tai/rrc_pa.skprx

*main
ur0:tai/henkaku.suprx
ur0:tai/retail_razorconnect.suprx
```

If you use `net_logging_mgr.skprx`, put `rrc_tty.skprx` after it. Only one module can own the
debug output, and the last one to load wins.

Then reboot. Refreshing taiHEN from HENkaku Settings isn't enough, kernel and `*main` plugins
only load at boot.

The plugin logs to `ux0:data/rrc.log`. A good start looks like this:

```
--- rrc user plugin start ---
sysmodule net load 0x00000000
net ready after tries 0x00000000
tcp listening on 8540
udp listening
```

The log also says whether it found the kernel modules, e.g.
`rrc_pa capture linked - Razor CPU trace available`.

To uninstall, remove the lines from `config.txt` (or delete the files) and reboot.

## Connecting

On the PC:

```
psp2ctrl find <console IP>
```

The console shows up as "PS Vita":

```
HardwareId                       Name    Host        ConnectionInfo NetMgr  CP      Kernel
00000000000000000000000100160afa PS Vita 192.168.1.8                0.0.0.0 0.0.0.0 0.000
```

After that it's listed in Neighborhood, and Console Output, Battery Monitor and Razor can
connect to it.

Note that the plugin has no authentication. Anyone on your network can connect to port 8540
and, with `rrc_pa` installed, read the memory of running processes. Only run it on a network
you trust.

## Razor

CPU trace:

1. Start the game before you start the capture. The plugin finds the game through its console
   output, so a game that hasn't printed anything yet isn't offered.
2. Use Capture > CPU Trace With Options... > Function Sampling. A fresh Razor defaults to Full
   Instrumentation, which needs DevKit trace hardware.
3. When Razor asks for the executable, give it the game's `.self` with symbols, or say No. The
   timeline works either way; without it the samples have no function names.

Sampling is done in software at 1 kHz, and only the newest 32768 records are kept (like Razor's
Wrap Trace Buffer option). A busy game fills that in a few seconds, so a long capture shows the
last few seconds.

GPU trace: a retail console has no GPU trace hardware, so the trace is built from the game's own
timing. You need a UE4.15 PSP2 Development build with the recorder from [ue4_15/](ue4_15/).
While Razor captures, the plugin tells the game to record and turns the recording into the
`.pmon` file Razor loads. See [docs/GPU_PROFILING.md](docs/GPU_PROFILING.md).

## Building

From a Linux or WSL shell:

```sh
cd plugin
bash build_tty.sh     # rrc_tty.skprx  + libRrcTty_stub_weak.a
bash build_pa.sh      # rrc_pa.skprx   + libRrcPa_stub_weak.a
bash build_user.sh    # retail_razorconnect.suprx
```

Run them in that order: `build_user.sh` links against the stubs the other two produce. The
stubs are committed as well, so `build_user.sh` works on its own if you haven't touched the
kernel modules' exports.

Each script builds in a temp folder in your home directory (`~/rrct`, `~/rrcpa`, `~/rrcu`) and
copies the result back into `plugin/`. If VitaSDK isn't in `~/vitasdk`, change the `VITASDK=`
line at the top of the scripts.

`build.sh` builds `retail_razorconnect.skprx`, an old kernel-mode version of the network
plugin. It's only kept for reference, don't install it (the kernel network stack won't receive
into module memory, see [plugin/README.md](plugin/README.md)).

## Troubleshooting

- `psp2ctrl find` doesn't see the console: check `rrc.log` for `tcp listening on 8540`, make
  sure the plugin is under `*main`, and that you rebooted.
- `rrc.log` says `rrc_tty.skprx not loaded`: it's missing from `*KERNEL`, or the firmware is
  older than 3.63. Console Output then only shows lines appended to `ux0:data/rrc_console.txt`.
- Console Output is empty but PrincessLog still gets output: `rrc_tty` is listed before
  `net_logging_mgr`. Move it after.
- Razor offers SceShell instead of the game: start the game first and let it print something.
- Razor's CPU trace fails in the default mode: switch to Function Sampling.

[plugin/README.md](plugin/README.md) goes into how each part works, and the problems hit along
the way.

## Repository layout

```
plugin/   the three modules, build scripts, prebuilt binaries
tools/    PC-side scripts: mock targets, trace encoders and checkers, reports
ue4_15/   the GPU recorder for the UE4.15 PSP2 GXM RHI (source + hooks patch)
ghidra/   Ghidra headless scripts used on the SDK tools (their output isn't committed)
docs/     protocol and file format notes
```

The docs:

- [PROTOCOL.md](docs/PROTOCOL.md): DECI4 handshake, framing, TSMP and NETMP (how Target Manager finds a target)
- [FINDINGS.md](docs/FINDINGS.md): the original research log
- [FEATURES.md](docs/FEATURES.md): which tool needs which protocol, and where each one stands
- [PAMP.md](docs/PAMP.md): Performance Analysis, the commands behind a Razor capture
- [PMEP_FORMAT.md](docs/PMEP_FORMAT.md): Battery Monitor
- [VCP_FORMAT.md](docs/VCP_FORMAT.md): Screen Capture
- [DBGP_PROCINFO_FORMAT.md](docs/DBGP_PROCINFO_FORMAT.md), [DBGP_MODULE_THREAD_FORMAT.md](docs/DBGP_MODULE_THREAD_FORMAT.md), [DBGP_BREAKPOINT_STOP.md](docs/DBGP_BREAKPOINT_STOP.md): the debugger messages Razor uses
- [DRFP_FORMAT.md](docs/DRFP_FORMAT.md): the `host0:` file protocol
- [RAZOR_PA_TRACE_FORMAT.md](docs/RAZOR_PA_TRACE_FORMAT.md), [RAZOR_SYSTRACE_FORMAT.md](docs/RAZOR_SYSTRACE_FORMAT.md), [RAZOR_PFT_SAMPLE_FORMAT.md](docs/RAZOR_PFT_SAMPLE_FORMAT.md): the CPU trace buffer
- [RAZOR_GPU_TRACE_FORMAT.md](docs/RAZOR_GPU_TRACE_FORMAT.md), [PMON_SYNTH_NOTES.md](docs/PMON_SYNTH_NOTES.md), [GPU_TRACE_SESSION.md](docs/GPU_TRACE_SESSION.md): the `.pmon` GPU trace
- [GPU_PROFILING.md](docs/GPU_PROFILING.md): the UE4.15 GPU recorder

Useful tools (Python 3):

- `mock_pamp.py`, `mock_ttyp.py`, `mock_pmep.py`: fake targets on 127.0.0.1, to test Razor,
  Console Output or Battery Monitor without the console
- `check_trace_file.py`, `check_pmon.py`: decode a CPU or GPU trace the way Razor does
- `pmon_synth.py`: build a `.pmon` from a GPU recorder CSV on the PC
- `gxm_gpu_report.py`: summary of a GPU recorder CSV (frame time, GPU or CPU bound, heaviest scenes)
- `pa_capture/`: runs a CPU or GPU capture over TMAPI without Razor (C#, `build.cmd` builds it
  against your Target Manager install)

`tools/old/` has the earlier mock targets from when the protocol was being figured out.
