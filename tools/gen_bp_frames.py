"""Generates the worked hex frames for DBGP_BREAKPOINT_STOP.md and re-checks them
against Python mirrors of the psp2tm validators (FUN_1400d2030, FUN_1400cffe0,
FUN_1400d20f0) and Razor's OnStopNotification lookup (FUN_101b4a50)."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dbgp_builders as B  # noqa: E402  (read-only use)

PID = 0x40010045
TID = 0x40010049
HUD_BP_ADVERTISED = 0x7E000101        # info struct +0x0c; bit0 = Thumb
ADDR = HUD_BP_ADVERTISED & ~1         # FUN_1018d660: slot+8
ATTR = HUD_BP_ADVERTISED & 1          # FUN_1018d660: slot+0xc -> eSoftwareBreakPtAttr
BPID = 1
STOP_REASON_SOFTWARE_BRKPT = 0x20004


def deci4(payload, flags=0, node=0):
    return struct.pack("<I", (16 + len(payload)) | 0x40000000)[:3] + b"\x40" + \
        struct.pack("<HHII", flags, node, 0x20000, 0) + payload


def set_swbrkpt_req(pid, tid, addr, attr, dif=b""):
    # FUN_1400d9810 (disasm 0x1400d986e..0x1400d9907)
    body = struct.pack("<9I", pid, 0x20, 0, tid, addr, attr, 0, 8, len(dif) & 0xffff)
    return struct.pack("<I", 0x4a1000) + body + dif + b"\0" * ((-len(dif)) & 3)


def set_swbrkpt_res(pid, bpid, opsize, opcode, b0=0):
    return B.dbgp_header(b0, 0x10, 0x4b) + struct.pack("<4I", pid, bpid, opsize, opcode)


def clear_swbrkpt_req(pid, bpid):
    return struct.pack("<III", 0x4c1000, pid, bpid)       # FUN_1400d84f0


def clear_swbrkpt_res(pid, bpid, b0=0):
    return B.dbgp_header(b0, 0x10, 0x4d) + struct.pack("<II", pid, bpid)


# ---------------------------------------------------------------- validator mirrors
def v_set_res(p, req_pid):                  # FUN_1400d2030 + FUN_140085980
    assert p[1] == 0x10 and p[2] == 0x4b and struct.unpack_from("<I", p, 8)[0] == 0
    assert len(p) >= 0x0c + 0x10
    pid, bpid, opsize, opcode = struct.unpack_from("<4I", p, 0x0c)
    assert pid == req_pid                   # else 0x100010
    # FUN_14013f080: resp+0x38 = +0x18 (OriginalOpcode), +0x3c = +0x14 (Size), +0x40 = +0x10 (BreakPtId)
    return dict(BreakPtId=bpid, OriginalOpcodeSize=opsize, OriginalOpcode=opcode)


def v_clear_res(p, req_pid):                # FUN_1400cffe0 + FUN_140083e60
    assert p[1] == 0x10 and p[2] == 0x4d and struct.unpack_from("<I", p, 8)[0] == 0
    assert len(p) >= 0x0c + 8
    assert struct.unpack_from("<I", p, 0x0c)[0] == req_pid


def v_stop(p):                              # FUN_1400d20f0 + FUN_14011b140 case 0xc0
    assert p[1] == 0x10 and p[2] == 0xc0
    assert struct.unpack_from("<I", p, 8)[0] == 0          # key 0 = single frame
    e = 0x0c
    assert len(p) >= e + 0x58
    esz = struct.unpack_from("<I", p, e)[0]
    t = e + esz
    assert len(p) >= t + 0x0c
    status, tid, count = struct.unpack_from("<3I", p, t)
    off = t + 0x0c
    threads = {}
    for _ in range(count):                  # FUN_1400cdeb0 walk + FUN_1400f7020 decode
        sz = struct.unpack_from("<I", p, off)[0]
        assert len(p) >= off + sz
        threads[struct.unpack_from("<I", p, off + 4)[0]] = struct.unpack_from("<I", p, off + 0x9c)[0]
        off += sz
    ts = struct.unpack_from("<Q", p, off)[0] if len(p) >= off + 8 else 0
    proc_pid = struct.unpack_from("<I", p, e + 4)[0]
    return dict(pid=proc_pid, status=status, tid=tid, threads=threads, ts=ts)


def dump(title, frame):
    print("### " + title + " (frame 0x%x bytes, payload 0x%x)" % (len(frame), len(frame) - 16))
    for i in range(0, len(frame), 16):
        print("%04x  %s" % (i, " ".join("%02x" % b for b in frame[i:i + 16])))
    print()


if __name__ == "__main__":
    req = set_swbrkpt_req(PID, 0xFFFFFFFF, ADDR, ATTR)
    dump("SET_SWBRKPT request (host->target)", deci4(req))
    res = set_swbrkpt_res(PID, BPID, 2, 0xBF00)
    print(v_set_res(res, PID))
    dump("SET_SWBRKPT_RES", deci4(res))

    creq = clear_swbrkpt_req(PID, BPID)
    dump("CLEAR_SWBRKPT request (host->target)", deci4(creq))
    cres = clear_swbrkpt_res(PID, BPID)
    v_clear_res(cres, PID)
    dump("CLEAR_SWBRKPT_RES", deci4(cres))

    proc = dict(pid=PID, attributes=0x00030001, name="PCSE00000", path="app0:eboot.bin",
                stop_code=STOP_REASON_SOFTWARE_BRKPT, stop_code_id=BPID)
    thr = dict(id=TID, name="main", status=1, entry=0x81000101, stack_top=0x81200000,
               stack_size=0x100000, stop_code=STOP_REASON_SOFTWARE_BRKPT, stop_code_id=BPID,
               pc=ADDR)
    stop = B.stop_notification(proc, STOP_REASON_SOFTWARE_BRKPT, TID, [thr], timestamp=0x12345678)
    d = v_stop(stop)
    print(d)
    # Razor FUN_101b4a50 -> FUN_10133900 -> FUN_101b5300
    assert d["pid"] == PID and d["pid"] != 0
    assert d["threads"][d["tid"]] == ADDR, "GetById(ThreadId).PC must equal bp addr & ~1"
    print("entry size 0x%x" % struct.unpack_from("<I", stop, 0x0c)[0])
    dump("STOP_NOTIFICATION (target->host, unsolicited)", deci4(stop))
