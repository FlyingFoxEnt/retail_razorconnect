"""Checks plugin/pmon_trace.c (the console-side GPU trace converter) against pmon_synth.py.

Builds tools/pmon_trace_host.c with MSVC, converts CSVs with it and with pmon_synth.py, and
requires identical bytes. Cases: a generated CSV (3 scenes per frame, lines slightly out of
time order, a long 'sections' field, skipped scenes), the same with --first-frame, and any
CSVs given on the command line (whole, and the last 200 frames). Then runs check_pmon.py's
model on one result.
Run: python check_pmon_trace.py [gxm_gpu_*.csv ...]
"""
import glob
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.join(HERE, "..", "plugin")


def build(tmp):
    vcvars = sorted(glob.glob(r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat"))[-1]
    exe = os.path.join(tmp, "pmon_trace_host.exe")
    src = [os.path.join(HERE, "pmon_trace_host.c"), os.path.join(PLUGIN, "pmon_trace.c")]
    cmd = 'call "%s" >nul && cl /nologo /O2 /W3 /DPMON_HOSTED /Fe"%s" /Fo"%s\\\\" %s' % (
        vcvars, exe, tmp, " ".join('"%s"' % s for s in src))
    subprocess.run(cmd, shell=True, check=True, cwd=tmp, stdout=subprocess.DEVNULL)
    return exe


def gen_csv(path, frames=240, seed=3):
    rnd = random.Random(seed)
    t = 30_000_000
    lines = ["# gxm_gpu 1", "# mode,1,source,razor,start_us,%d,unix,1,frame,0" % t]
    pending = []
    for fr in range(1, frames + 1):
        start = t
        for _ in range(3):
            open_us = t + rnd.randrange(100, 2000)
            endcall = open_us + rnd.randrange(500, 8000)
            submit = endcall + rnd.randrange(0, 400)            # 0 -> empty vertex job
            done = 0 if rnd.random() < 0.03 else submit + rnd.randrange(200, 20000)
            sections = "|".join("Ev%d=%d/%d" % (i, i, i * 7) for i in range(rnd.randrange(1, 60)))
            pending.append("S,%d,%d,V,960,544,%d,%d,%d,%d,%d,%d,%d,0,0,Frame%d,%s"
                           % (fr, fr * 3, rnd.randrange(1, 9000), rnd.randrange(1, 90000),
                              open_us, endcall, submit, done, max(0, done - submit), fr, sections))
            t = endcall
        t += rnd.randrange(1000, 30000)
        pending.append("F,%d,%d,%d,3,1,2,3,4,5,6,7,8,9,0" % (fr, start, t))
        # the game writes lines when events complete: shuffle a little
        if rnd.random() < 0.3 and len(pending) > 2:
            pending[-1], pending[-2] = pending[-2], pending[-1]
        lines.extend(pending)
        pending = []
    lines.append("# end,frames,%d" % frames)
    with open(path, "w", newline="\r\n" if seed % 2 else "\n") as f:
        f.write("\n".join(lines) + "\n")


def run_case(exe, tmp, name, csv, first):
    ours = os.path.join(tmp, name + ".c.pmon")
    ref = os.path.join(tmp, name + ".py.pmon")
    args = [exe, csv, ours] + ([first] if first else [])
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        print("FAIL %s: %s" % (name, (r.stderr + r.stdout).strip()))
        return None
    stats = dict(kv.split("=") for kv in r.stdout.split())
    subprocess.run([sys.executable, os.path.join(HERE, "pmon_synth.py"), csv, ref,
                    "--first-frame", stats["first"]], check=True, stdout=subprocess.DEVNULL)
    a, b = open(ours, "rb").read(), open(ref, "rb").read()
    if a != b:
        n = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
        print("FAIL %s: C %d bytes, Python %d bytes, first difference at 0x%x" % (name, len(a), len(b), n))
        return None
    print("%-22s identical: %9s bytes, %5s scenes, %5s frames, %6s bookmarks, %6s samples, late %s, dropped %s"
          % (name, stats["bytes"], stats["scenes"], stats["frames"], stats["bookmarks"],
             stats["samples"], stats["late"], stats["dropped"]))
    return ours


def main():
    tmp = tempfile.mkdtemp(prefix="pmon_trace_")
    exe = build(tmp)
    ok = True
    gen = os.path.join(tmp, "gen.csv")
    gen_csv(gen)
    gen2 = os.path.join(tmp, "gen_crlf.csv")
    gen_csv(gen2, frames=90, seed=5)
    cases = [("generated", gen, None), ("generated first 100", gen, "100"),
             ("generated last 50", gen, "-50"), ("generated crlf", gen2, None)]
    for path in sys.argv[1:]:
        base = os.path.splitext(os.path.basename(path))[0]
        cases += [(base, path, None), (base + " last 200", path, "-200")]
    last = None
    for name, csv, first in cases:
        out = run_case(exe, tmp, name.replace(" ", "_"), csv, first)
        ok = ok and out is not None
        last = out or last
    if last:
        subprocess.run([sys.executable, os.path.join(HERE, "check_pmon.py"), last])
    print("pmon_trace.c OK" if ok else "pmon_trace.c FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
