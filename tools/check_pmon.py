"""Offline model of the PSP2Razor.dll 3.60 GPU-trace pipeline for a .pmon (for pmon_synth checks).

Mimics: FUN_101ce170 (packet counts), FUN_101bcc30/FUN_101bce70 (counted AddWord/flush),
FUN_101bc930 (bookmarks), FUN_101c7540 event bars + combined union, FUN_10204da0/FUN_10202000
(job build + bookmark consumption), FUN_102044a0 (scene grouping), FUN_10201740 (too small).
"""
import struct, sys
from collections import defaultdict

TA_CAP = {0x10: "frame_ta", 0x11: "frame_3d", 0x12: "frame_spm", 0x14: "mt_lls", 0x40: "vdm"}


def parse(path):
    b = open(path, "rb").read()
    assert struct.unpack_from("<I", b, 0)[0] == 0x4E4F4D50
    start, end = struct.unpack_from("<I", b, 0x20)[0], struct.unpack_from("<I", b, 0x14)[0]
    masks = struct.unpack_from("<8I", b, 0x34)
    enabled = [p for p in range(256) if masks[p >> 5] >> (p & 31) & 1]
    nvals = len(enabled)
    body = b[start:end]
    bms = defaultdict(list)       # (fifo, regno) -> [(t, word)]
    counted = []                  # (t, {col: value})
    sampled = []
    state = None
    for f in range(0, len(body), 0x80):
        d = struct.unpack_from("<8H", body, f)
        for k in range(1, 8):
            desc = d[k]
            typ, lob = (desc >> 8) & 0x7f, desc & 0xff
            slot = body[f + 16 * k:f + 16 * k + 16]
            if typ == 0x7f:
                lo, hi = struct.unpack_from("<IH", slot, 0)
                bmdesc, w = struct.unpack_from("<HI", slot, 10)
                bms[((bmdesc >> 12) & 1, (bmdesc >> 8) & 0xf)].append(((hi << 32) | lo, w))
            elif typ == 0x61:
                if lob == 0:
                    lo, hi = struct.unpack_from("<IH", slot, 0)
                    state = {"t": (hi << 32) | lo, "v": list(struct.unpack_from("<5H", slot, 6))}
                    state["v"] = state["v"][:nvals]
                elif state is not None:
                    need = nvals - len(state["v"])
                    state["v"] += list(struct.unpack_from("<8H", slot, 0))[:need]
                if state is not None and len(state["v"]) == nvals:
                    # FUN_101bce70: column = enabled ordinal, value = state[10 + position]
                    cols = {}
                    for ordn, pos in enumerate(enabled):
                        cols[ordn] = state["v"][pos] if pos < len(state["v"]) else 0
                    counted.append((state["t"], cols))
                    state = None
            elif typ == 0x60 and lob == 0:
                lo, hi = struct.unpack_from("<IH", slot, 0)
                sampled.append((hi << 32) | lo)
    return bms, counted, sampled, nvals


def bars(counted, col):
    """FUN_101c7540 event bars: value series v[i], timestamps ts[i]; for i >= 1 a non-zero v[i]
    opens a bar at ts[i-1], a zero v[i] closes it at ts[i-1]; an open bar ends at ts[n-1]."""
    out, cur = [], None
    ts = [c[0] for c in counted]
    for i in range(1, len(counted)):
        v = counted[i][1].get(col, 0)
        if cur is None and v:
            cur = [ts[i - 1], None]
        elif cur is not None and not v:
            cur[1] = ts[i - 1]
            out.append(tuple(cur)); cur = None
    if cur is not None:
        cur[1] = ts[-1]; out.append(tuple(cur))
    return out


def union(lists):
    ivs = sorted(x for l in lists for x in l)
    out = []
    for s, e in ivs:
        if out and s < out[-1][1]:          # node.end <= bar.start -> separate
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def by_cap(bms, base, mask=0xff000000):
    return [(t, w) for t, w in bms[(1, 2)] if (w & mask) == base]


def build_jobs(kind, comb, per_core, bms):
    jobs = []
    if kind == "v":
        frames = by_cap(bms, 0x10000000)
        pids = by_cap(bms, 0x30000000, 0xfc000000)
        flags_bm = by_cap(bms, 0x20000000, 0xf0000000)
        vdm = by_cap(bms, 0x40000000)
    else:
        frames3d = by_cap(bms, 0x11000000)
        spm = by_cap(bms, 0x12000000)
        pids = by_cap(bms, 0x34000000, 0xfc000000)
        flags_bm = by_cap(bms, 0x50000000, 0xf0000000)
        mt = by_cap(bms, 0x14000000)
    pi = 1 if pids and pids[0][1] & 0x2000000 else 0
    fi = si = gi = 0
    vi = 1 if kind == "v" and vdm and comb and vdm[0][0] < comb[0][0] else 0
    mi = 0
    for n, (s, e) in enumerate(comb):
        j = {"s": s, "e": e, "flags": 0x10, "frame": None, "pid": None, "fl": 0, "spm": 0}
        for c in range(4):
            for ps, pe in per_core[c]:
                if ps >= s:
                    if pe <= e:
                        j["flags"] |= 1 << c
                    break
        if kind == "v":
            if fi < len(frames) and frames[fi][0] <= e:
                j["frame"] = frames[fi][1] & 0xffffff; j["flags"] |= 0x20; fi += 1
        else:
            f3 = frames3d[fi] if fi < len(frames3d) else None
            fs = spm[si] if si < len(spm) else None
            if f3 is None or (fs is not None and fs[0] <= f3[0]):
                if fs is not None and fs[0] <= e:
                    j["frame"] = fs[1] & 0xffffff; j["flags"] |= 0x20; si += 1; j["spm"] = 1
            elif f3[0] <= e:
                j["frame"] = f3[1] & 0xffffff; j["flags"] |= 0x20; fi += 1
        if pi + 1 < len(pids) and pids[pi + 1][0] <= e:
            j["pid"] = ((pids[pi + 1][1] << 16) & 0xffffffff) | (pids[pi][1] & 0xffff)
            j["flags"] |= 0x40; pi += 2
        if gi < len(flags_bm) and flags_bm[gi][0] <= e:
            j["fl"] = flags_bm[gi][1] & 0xfffffff; j["flags"] |= 0x80; gi += 1
        if kind == "v":
            if vi < len(vdm):
                t = vdm[vi][0]
                ok = (t <= comb[n + 1][0]) if n < len(comb) - 1 else (t >= e)
                if ok:
                    j["flags"] |= 0x100; vi += 1
        else:
            if mi < len(mt) and not (e < mt[mi][0]):
                j["flags"] |= 0x300; mi += 1
        jobs.append(j)
    return jobs


def scenes(vjobs, fjobs):
    ta, td = [], []
    open_ = {}
    for j in vjobs:
        f = j["flags"]
        if (f & 0x1f) == 0x1f and f & 0x20 and f & 0x40 and f & 0x80:
            sc = open_.get(j["pid"])
            if sc is None:
                sc = {"pid": j["pid"], "jobs": []}; ta.append(sc); open_[j["pid"]] = sc
            sc["jobs"].append(j)
            fl = j["fl"]
            if fl & 2 and not fl & 0x4000000 and not fl & 0x3c00000:
                open_[j["pid"]] = None
    open_ = {}
    for j in fjobs:
        f, fl = j["flags"], j["fl"]
        if (f & 0x1f) == 0x1f and f & 0x20 and f & 0x40 and f & 0x80 and (fl & 0x2000 or f & 0x100):
            sc = open_.get(j["pid"])
            if sc is None:
                sc = {"pid": j["pid"], "jobs": []}; td.append(sc); open_[j["pid"]] = sc
            sc["jobs"].append(j)
            if (not fl & 0x2000) and not fl & 0x4000 and not fl & 0x8000 and not j["spm"]:
                open_[j["pid"]] = None

    def index(lst):
        seen = {}
        for sc in lst:
            fr = sc["jobs"][0]["frame"]
            st = seen.get(sc["pid"])
            if st is None:
                seen[sc["pid"]] = [0, fr, 0]; sc["idx"] = None; continue
            if fr == st[1]:
                if st[0] == 0:
                    sc["idx"] = None; continue
            else:
                st[0], st[1], st[2] = 1, fr, 0
            sc["idx"] = st[2]; sc["frame"] = fr; st[2] += 1
    index(ta); index(td)
    tdmap = {(s["frame"], s["pid"], s["idx"]): s for s in td if s.get("idx") is not None}
    merged = [s for s in ta if s.get("idx") is not None and (s["frame"], s["pid"], s["idx"]) in tdmap]
    return ta, td, merged


def main(path):
    bms, counted, sampled, nvals = parse(path)
    print("counted packets=%d (values/packet=%d) sampled packets=%d bookmark channels=%s" % (
        len(counted), nvals, len(sampled), {k: len(v) for k, v in bms.items()}))
    res = {}
    for kind, bit in (("v", 0), ("f", 1), ("w", 2)):
        per = [bars(counted, c * 64 + bit) for c in range(4)]
        comb = union(per)
        res[kind] = (per, comb)
        print("%s: per-core bars %s combined %d" % (kind, [len(p) for p in per], len(comb)))
    vj = build_jobs("v", res["v"][1], res["v"][0], bms)
    fj = build_jobs("f", res["f"][1], res["f"][0], bms)
    for name, js in (("vertex", vj), ("fragment", fj)):
        good = sum(1 for j in js if (j["flags"] & 0x1f) == 0x1f and j["flags"] & 0x60 == 0x60)
        print("%s jobs=%d complete(ts+frame+pid)=%d flags-hist=%s" % (
            name, len(js), good, sorted(set(hex(j["flags"]) for j in js))[:6]))
        if js:
            print("   first:", {k: (hex(v) if isinstance(v, int) else v) for k, v in js[0].items()})
    ta, td, merged = scenes(vj, fj)
    frames0 = sorted(set(s["frame"] for s in merged if s["idx"] == 0))
    print("TA scenes=%d 3D scenes=%d merged=%d frames with scene0=%d (first %s)" % (
        len(ta), len(td), len(merged), len(frames0), frames0[:5]))
    print("0x71b too-small:", "NO (frames>=2)" if len(frames0) >= 2 else "YES")


if __name__ == "__main__":
    main(sys.argv[1])
