# GPU profiling a UE4.15 game on the retail Vita

Razor's GPU tooling needs DevKit modules (`librazorhud_es4.suprx`, `librazorcapture_es4.suprx`) that a
retail console does not have. This measures the GPU from inside the game instead, and ties the
recording to Razor captures made through `retail_razorconnect`.

Status (2026-09-15): engine side built and compiling into `Vita_Testing.self`; plugin flag file built;
report tool tested on synthetic data. **Not yet run on the device.** GPU rows inside Razor's own timeline
(PA trace bookmarks on `RAZOR_GPU_*`) are pending the reverse engineering of how PSP2Razor.dll parses
those channels.

## 1. What the game records

`ue4_15/GXMRHI/Private/GXMGpuProfiler.cpp` (GXM RHI, compiled out of Shipping) plus the hooks in
`ue4_15/gxm_gpu_profiler_hooks.patch` (apply from the engine root with `git apply -p1`).

- Every `sceGxmEndScene()` in the RHI carries the *frame fence* notification. A watcher thread waits in
  `sceGxmWaitEvent()` (documented as callable from any thread, wakes on each GPU job) and timestamps the
  moment the GPU writes each fence value, i.e. when that scene's fragment processing finished.
- Per scene: draw-event path when it opened (`SCOPED_DRAW_EVENT`, `GEmitDrawEvents` forced on while
  recording), size, back buffer or off-screen, draws and indices (also per innermost event), CPU open /
  EndScene call / submit times and GPU completion time.
  `gpu = done - max(submit, previous scene's done)`, `queue = previous done - submit`.
- Per frame: game and render thread time, and the render thread's blocked time in BeginScene, EndScene,
  the flip queue, the scene throttle and Present.
- Mode 2 (`r.PSP2.GpuProfile 2` / `-GpuProfileSerial`) calls `sceGxmFinish()` after each scene instead:
  exact per-scene cost, lower frame rate.

Output: `ux0:data/gxm_gpu_<unix time>.csv` (writer thread; the file header lists the columns) and a
top-scenes summary on `LogGXMGpuProfile`, which Console Output shows through `rrc_tty`.

## 2. Starting a recording

| Trigger | Length |
|---|---|
| Hold **L + R + SELECT** for one second in game | 600 frames; hold again to stop early |
| `-GpuProfile=<frames> [-GpuProfileDelay=<s>] [-GpuProfileSerial]` in `ux0:app/UEVT00002/ue4commandline.txt` | that many frames, after the delay (default 30 s) |
| `r.PSP2.GpuProfile 1` (or 2), e.g. from DefaultEngine.ini `[SystemSettings]` | until set to 0 or `r.PSP2.GpuProfile.Frames` |
| **Razor capture** of the game with this plugin | while `ux0:data/rrc_capturing` exists (capped at 9000 frames) |

The plugin (`rrc_user.c`) creates `ux0:data/rrc_capturing` (traced pid inside) when PAMP START_CAPTURE
succeeds, and removes it at STOP_CAPTURE, on PAMP OPEN/CLOSE and when the plugin starts, so a crash
cannot leave a game recording.

## 3. Reading it

```
python tools/gxm_gpu_report.py --fetch 192.168.1.8          # newest CSV over FTP, then the report
python tools/gxm_gpu_report.py gxm_gpu_1789512345.csv --skip-frames 30
```

The report gives frame time vs GPU busy time with a GPU-bound / CPU-bound verdict, the render thread's
blocked time, and scenes ranked by GPU ms per frame with their draws, indices and heaviest draw events.

## 4. Caveats

- `gpu` includes whatever of a scene's vertex processing was still running at submit; vertex jobs kicked
  mid-scene are not separated. Rankings are sound; for exact numbers use mode 2.
- Several scenes finishing between two watcher wake-ups share a timestamp; the first absorbs the interval.
- Timestamps are `sceKernelGetProcessTimeWide()` us. `rrc_pa` uses `ksceKernelGetSystemTimeWide()`; the
  offset between the two must be measured before GPU rows are merged into a Razor trace.
- Scenes opened before the watcher primes (first frame or two of a recording) have no completion time.
