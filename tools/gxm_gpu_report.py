"""Summarise a gxm_gpu_<unix time>.csv recorded by the UE4.15 PSP2 GXM RHI's GPU profiler.

The profiler (GXMGpuProfiler.cpp) writes one S line per libgxm scene and one F line per frame; the file's
own header documents the columns. This answers "what is holding the GPU":

  1. Is the frame GPU-bound?  Frame time against the GPU's busy time and the CPU's blocked time.
  2. Which scenes cost it?    GPU ms per frame per scene (kind, size, draw-event path), ranked.
  3. What is inside them?     Draws and indices per innermost draw event.

Usage:
  python gxm_gpu_report.py ux0_data_gxm_gpu_1789512345.csv [--skip-frames 30] [--top 15]
  python gxm_gpu_report.py --fetch 192.168.1.8        # list and download the newest CSV over FTP (port 1337)
"""
import argparse
import collections
import ftplib
import os
import statistics
import sys

S_FIELDS = ["frame", "fence", "kind", "width", "height", "draws", "indices", "open_us", "endcall_us",
            "submit_us", "done_us", "gpu_us", "queue_us", "serial_us", "path", "sections"]
F_FIELDS = ["frame", "start_us", "end_us", "scenes", "game_us", "render_us", "beginscene_us", "endscene_us",
            "flip_us", "throttle_us", "present_us", "render_stall_us", "engine_sleep_us", "dropped_scenes"]
INT_S = set(S_FIELDS) - {"kind", "path", "sections"}


def parse(path):
    header, scenes, frames = [], [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#"):
                header.append(line)
                continue
            parts = line.split(",")
            if parts[0] == "S" and len(parts) >= len(S_FIELDS) + 1:
                # path and sections never contain commas (the recorder sanitises them), but be safe:
                fixed = parts[1:len(S_FIELDS) - 1]
                path_field, sections_field = parts[len(S_FIELDS) - 1], ",".join(parts[len(S_FIELDS):])
                row = dict(zip(S_FIELDS[:-2], fixed))
                row["path"], row["sections"] = path_field, sections_field
                for k in INT_S:
                    row[k] = int(row[k])
                scenes.append(row)
            elif parts[0] == "F" and len(parts) >= len(F_FIELDS) + 1:
                frames.append({k: int(v) for k, v in zip(F_FIELDS, parts[1:len(F_FIELDS) + 1])})
    return header, scenes, frames


def pct(values, q):
    if not values:
        return 0.0
    values = sorted(values)
    i = min(len(values) - 1, max(0, int(round(q * (len(values) - 1)))))
    return values[i]


def ms(us):
    return us / 1000.0


def report(path, skip_frames, top):
    header, scenes, frames = parse(path)
    mode = next((h for h in header if h.startswith("# mode,")), "# mode,?")
    serial = mode.split(",")[1].strip() == "2"
    print(f"file: {path}")
    print(f"{mode[2:]}")
    if not frames:
        print("no F lines: the recording is empty or was cut before its first frame")
        return 1

    first_frame = frames[0]["frame"] + skip_frames
    frames = [f for f in frames if f["frame"] >= first_frame]
    scenes = [s for s in scenes if s["frame"] >= first_frame]
    n = max(len(frames), 1)

    periods = [f["end_us"] - f["start_us"] for f in frames if f["start_us"]]
    busy_by_frame = collections.Counter()
    unknown = 0
    for s in scenes:
        if s["done_us"] == 0:
            unknown += 1
            continue
        busy_by_frame[s["frame"]] += s["serial_us"] if serial and s["serial_us"] else s["gpu_us"]

    busy = [busy_by_frame.get(f["frame"], 0) for f in frames]
    mean_period = statistics.mean(periods) if periods else 0
    mean_busy = statistics.mean(busy) if busy else 0

    print(f"\n== frames (after skipping {skip_frames}) ==")
    print(f"{len(frames)} frames, {len(scenes)} scenes ({len(scenes) / n:.1f}/frame), {unknown} without an observed completion")
    if periods:
        print(f"frame time   mean {ms(mean_period):6.2f} ms  p50 {ms(pct(periods, .5)):6.2f}  p95 {ms(pct(periods, .95)):6.2f}"
              f"  -> {1e6 / mean_period:5.1f} FPS")
    print(f"GPU busy     mean {ms(mean_busy):6.2f} ms  p95 {ms(pct(busy, .95)):6.2f}"
          f"  = {100.0 * mean_busy / mean_period if mean_period else 0:4.0f}% of the frame"
          + ("   (serial mode: sceGxmFinish per scene, frame time is inflated)" if serial else ""))

    def mean_of(key):
        return statistics.mean(f[key] for f in frames) if frames else 0

    print("CPU side per frame (ms):  game {:.2f}  render {:.2f}  | blocked: begin scene {:.2f}  end scene {:.2f}"
          "  flip {:.2f}  throttle {:.2f}  present* {:.2f}  | render stall* {:.2f}  engine sleep* {:.2f}".format(
              ms(mean_of("game_us")), ms(mean_of("render_us")), ms(mean_of("beginscene_us")), ms(mean_of("endscene_us")),
              ms(mean_of("flip_us")), ms(mean_of("throttle_us")), ms(mean_of("present_us")),
              ms(mean_of("render_stall_us")), ms(mean_of("engine_sleep_us"))))
    print("  (* sampled one call later by the RHI, so belongs to the previous frame)")

    blocked = mean_of("beginscene_us") + mean_of("endscene_us") + mean_of("flip_us") + mean_of("throttle_us")
    if mean_period:
        if mean_busy > 0.8 * mean_period or blocked > 0.3 * mean_period:
            verdict = "GPU-bound: the GPU is busy for most of the frame and/or the render thread spends it blocked on libgxm"
        elif ms(mean_of("game_us")) > ms(mean_period) * 0.6:
            verdict = "CPU-bound on the game thread"
        else:
            verdict = "neither side saturated: look at render thread work and handoffs"
        print(f"verdict: {verdict}")

    groups = collections.OrderedDict()
    for s in scenes:
        if s["done_us"] == 0:
            continue                    # completion not observed: no cost to attribute
        key = (s["kind"], s["width"], s["height"], s["path"])
        g = groups.setdefault(key, {"costs": [], "queue": [], "draws": 0, "indices": 0, "sections": collections.Counter(),
                                    "section_idx": collections.Counter()})
        g["costs"].append(s["serial_us"] if serial and s["serial_us"] else s["gpu_us"])
        g["queue"].append(s["queue_us"])
        g["draws"] += s["draws"]
        g["indices"] += s["indices"]
        for part in filter(None, s["sections"].split("|")):
            name, _, counts = part.partition("=")
            d, _, i = counts.partition("/")
            g["sections"][name] += int(d or 0)
            g["section_idx"][name] += int(i or 0)

    total = sum(sum(g["costs"]) for g in groups.values()) or 1
    ranked = sorted(groups.items(), key=lambda kv: -sum(kv[1]["costs"]))
    print(f"\n== scenes by GPU time ({'sceGxmFinish per scene' if serial else 'fence-timed'}) ==")
    print(f"{'ms/frame':>8} {'share':>6} {'mean':>6} {'p95':>6} {'x/frm':>5} {'queue':>6}  kind size       {'draws':>6} {'indices':>8}  path")
    for (kind, w, h, p), g in ranked[:top]:
        c = len(g["costs"])
        print(f"{ms(sum(g['costs'])) / n:8.2f} {100.0 * sum(g['costs']) / total:5.1f}% {ms(statistics.mean(g['costs'])):6.2f}"
              f" {ms(pct(g['costs'], .95)):6.2f} {c / n:5.2f} {ms(statistics.mean(g['queue'])):6.2f}  {kind}    {w:>4}x{h:<4}"
              f" {g['draws'] / c:6.0f} {g['indices'] / c:8.0f}  {p}")
        for name, draws in g["sections"].most_common(4):
            print(f"{'':>62}- {name}: {draws / c:.0f} draws, {g['section_idx'][name] / c:.0f} indices")
    return 0


def fetch(host, port, dest):
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=10)
    ftp.login()
    ftp.cwd("ux0:/data/")
    names = sorted(n for n in ftp.nlst() if n.startswith("gxm_gpu_") and n.endswith(".csv"))
    if not names:
        print("no gxm_gpu_*.csv on the device")
        return None
    newest = names[-1]
    out = os.path.join(dest, newest)
    with open(out, "wb") as f:
        ftp.retrbinary("RETR " + newest, f.write)
    ftp.quit()
    print(f"downloaded {newest} ({os.path.getsize(out)} bytes) -> {out}  [{len(names)} on device]")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="?")
    ap.add_argument("--fetch", metavar="HOST", help="download the newest ux0:data/gxm_gpu_*.csv from the Vita FTP server")
    ap.add_argument("--port", type=int, default=1337)
    ap.add_argument("--dest", default=".")
    ap.add_argument("--skip-frames", type=int, default=30, help="ignore the first N frames (watcher priming, hitches)")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    path = args.csv
    if args.fetch:
        path = fetch(args.fetch, args.port, args.dest)
    if not path:
        ap.print_help()
        return 2
    return report(path, args.skip_frames, args.top)


if __name__ == "__main__":
    sys.exit(main())
