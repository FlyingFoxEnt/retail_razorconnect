"""PC mock target that advertises PAMP (0x28000, Performance Analysis) so Razor's
CPU Trace can be driven against 127.0.0.1 without the Vita. Based on mock_dbg.

Run: python mock_pamp.py <seconds>
Env:
  MOCKHWID   HWID to report (default 1444603, the MockVita cache entry)
  TRACEFILE  bytes returned by ReadTraceData for buffer 0, the main buffer (default: empty)
  TRACEFILE2 bytes for buffer 1 (default: empty)
  TIMEBASE   PAMP_TIMEBASE_FREQUENCY answer (default 333; Razor rejects anything else)

PAMP payload (from psp2tm's encoders FUN_1400db470.. and validator FUN_1400cec60):
  request : u32 cmd | u32 reqId | u32 len | body
  response: u32 cmd | u32 reqId | u32 bodyLen | u32 result | body[bodyLen]
  notification (target -> host): cmd 0x80000000 START, 0x80000001 STOP,
                                 0x80000002 TRACE_DATA (u32 + data)
Commands follow IPerformanceAnalysis order; see PAMP.md.
"""
import os, socket, struct, sys, threading, time

import dbgp_builders
import vcp_builders

# 960x544 RGBA test image for VCP screenshots (Razor aborts a capture without one)
SHOT = bytes(b for y in range(544) for x in range(960) for b in (x * 255 // 959, y * 255 // 543, 96, 255))

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 300
HWID = int(os.environ.get("MOCKHWID", "1444603"))
MAGIC, MARKER, MAXPAY = 0x15A3F8E1, 0x40, 0x10800
NETMP, TSMP, CPUP, PMEP, DBGP, PAMP, VCP = 0x1000, 0x2000, 0x3000, 0x4000, 0x20000, 0x28000, 0x2b000
TTYP = 0x80030000
PROTOS = [(NETMP, 0x11), (TSMP, 0x22), (CPUP, 0x33), (TTYP | 0x00, 0xa000),
          (TTYP | 0x90, 0xa090), (DBGP, 0x44), (PAMP, 0x66), (VCP, 0x77)]
TIMEBASE = int(os.environ.get("TIMEBASE", "333"))

LOGF = open(os.environ.get("MOCKLOG", os.path.join(os.environ.get("TEMP", "."), "mock_pamp.log")), "a")
LOCK = threading.Lock()


def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    with LOCK:
        print(line, flush=True)
        LOGF.write(line + "\n")
        LOGF.flush()


def load(name):
    p = os.environ.get(name)
    return open(p, "rb").read() if p else b""


TRACE = {0: load("TRACEFILE"), 1: load("TRACEFILE2")}


def frame(payload, node, proto, flags=0):
    return struct.pack("<I", 16 + len(payload))[:3] + bytes([MARKER]) + \
        struct.pack("<HHII", flags, node, proto, 0) + payload


def pad4(b):
    return b + bytes((-len(b)) % 4)


def nv(name, value, vtype):
    nb = name.encode() + b"\0"
    body = pad4(nb) + struct.pack("<HH", len(value), vtype) + pad4(value)
    return struct.pack("<II", 8 + len(body), len(nb)) + body


def keys(body):
    out, off = [], 4
    cnt = struct.unpack_from("<I", body, 0)[0] if len(body) >= 4 else 0
    for _ in range(min(cnt, 64)):
        if off + 4 > len(body):
            break
        n = struct.unpack_from("<I", body, off)[0]
        off += 4
        if n == 0 or off + n > len(body):
            break
        out.append(body[off:off + n].rstrip(b"\0").decode())
        off += (n + 3) & ~3
    return out


def tsmp_body(t, c, body):
    cpid = struct.pack("<IIII", HWID, 1, 0, 0)
    if (t, c) == (1, 0):
        return struct.pack("<IHHI", 0, 1, 0, HWID)
    if (t, c) == (3, 0):
        ks = keys(body) or ["CPID"]
        return struct.pack("<IHH", 0, len(ks), 0) + b"".join(nv(k, cpid, 1) for k in ks)
    if (t, c) == (3, 4):
        ks = keys(body) or ["SdkVersion"]
        return struct.pack("<IHH", 0, len(ks), 0) + b"".join(nv(k, struct.pack("<I", 0x03650000), 0) for k in ks)
    if (t, c) == (3, 2):
        return struct.pack("<II", 0, 0)
    if (t, c) == (3, 6):
        return struct.pack("<II", 0, 0xFFFFFFFF)
    if (t, c) == (3, 8):
        head = bytearray(0x30)
        struct.pack_into("<I", head, 4, 0x2c)
        return bytes(head) + struct.pack("<II", 8, 0)
    if (t, c) == (4, 0):
        return struct.pack("<II", 0, 0x100)
    if t == 5 and c in (0, 2):
        ks = keys(body)
        return struct.pack("<IHH", 0, len(ks), 0) + b"".join(nv(k, b"MockVita\0", 2) for k in ks)
    if (t, c) == (5, 8):
        x = b"<?xml version=\"1.0\"?><settings/>\0"
        return struct.pack("<II", 0, len(x)) + pad4(x)
    return struct.pack("<I", 0)


# ---------------------------------------------------------------- DBGP (procs)
# eProcessAttr: LOADED 1, DEBUG_STATE 2, SYSTEM 4, SUSPENDED 8, DEBUGGABLE 0x10000,
# ATTACHED 0x20000. Razor's CPU Trace needs exactly one DEBUGGABLE process
# ("No debuggable processes found" / "More than one possible debuggable process").
PROCS = [(0x40010003, "SceShell", "vs0:vsh/shell/eboot.bin", 1),
         (0x40010045, "PCSE00000", "ux0:app/PCSE00000/eboot.bin",
          int(os.environ.get("GAMEATTR", "0x10001"), 0))]


def proc_entry(pid, name, path, attrs):
    namef = (name.encode()[:35] + b"\0").ljust(36, b"\0")[:36]
    pb = path.encode() + b"\0"
    body = struct.pack("<II", pid, attrs) + namef
    body += struct.pack("<IIII", 0, 0, 0, 0)
    body += struct.pack("<IIIII", 0x14, 0, 0, 0, 0)
    body += struct.pack("<I", len(pb)) + pad4(pb) + struct.pack("<4I", 0, 0, 0, 0)
    return struct.pack("<I", 4 + len(body)) + body


GAME_PID = PROCS[1][0]
MODULES = {GAME_PID: [
    {"id": 0x40010101, "name": "PCSE00000", "type": 0x10, "status": 2,
     "segments": [{"attr": 5, "base": 0x81000000, "size": 0x00200000, "align": 4},
                  {"attr": 6, "base": 0x81200000, "size": 0x00100000, "align": 4}]},
]}
THREADS = {GAME_PID: [
    {"id": 0x40010201, "name": "main", "priority": 0x10000100, "last_cpu": 0, "status": 1},
    {"id": 0x40010202, "name": "RenderThread", "priority": 0x10000100, "last_cpu": 1, "status": 1},
]}


ATTACHED = set()


def dbgp_res(pay):
    b0, group, code = pay[0], pay[1], pay[2]
    h = struct.pack("<BBBB", b0, group, code + 1, 0) + struct.pack("<II", 0, 0)
    if group == 0x20 and code == 0x00:
        # eProcessAttr ATTACHED (0x20000) once a debugger has attached
        return h + struct.pack("<I", len(PROCS)) + b"".join(
            proc_entry(pid, n, p, a | (0x20000 if pid in ATTACHED else 0)) for pid, n, p, a in PROCS)
    arg = struct.unpack_from("<I", pay, 4)[0] if len(pay) >= 8 else 0
    if group == 0x20 and code == 0x10:
        ATTACHED.add(arg)
    elif group == 0x20 and code == 0x12:
        ATTACHED.discard(arg)
    # MODULE / THREAD / PROCESS / SYSTEM builders RE'd from psp2tm (DBGP_MODULE_THREAD_FORMAT.md)
    return dbgp_builders.build_reply(pay, modules_by_pid=MODULES, threads_by_pid=THREADS)


# ---------------------------------------------------------------- PAMP
PAMP_NAMES = {
    0x00: "OPEN", 0x01: "CLOSE", 0x02: "GET_TRACE_BUFFER_AVAILABLE_SIZE",
    0x03: "CONFIG_TRACE_BUFFER", 0x04: "CREATE_TRACE", 0x05: "DESTROY_TRACE",
    0x06: "START_CAPTURE", 0x07: "STOP_CAPTURE", 0x08: "GET_TRACE_INFO",
    0x09: "READ_TRACE_DATA", 0x0a: "SET_TRIGGER_CONDITION", 0x0b: "CLEAR_TRIGGER_CONDITION",
    0x0c: "SET_BOOKMARK_CONFIG", 0x0d: "GET_BOOKMARK_CONFIG",
    0x0e: "CLEAR_BOOKMARK_INTERRUPT_COUNTS", 0x0f: "GET_BOOKMARK_INTERRUPT_COUNTS",
    0x10: "GET_GPU_SAMPLED_DATA", 0x11: "INSERT_BOOKMARK", 0x12: "TIMEBASE_FREQUENCY",
}


class Pa:
    def __init__(self):
        self.bookmark = struct.pack("<5I", 0, 0, 0, 0, 0)
        self.capturing = False
        self.buffers = {}


PA = Pa()


def describe(cmd, body):
    u = lambda o: struct.unpack_from("<I", body, o)[0] if len(body) >= o + 4 else None
    if cmd == 0x03:
        sub = u(0)
        s = "sub=0x%x bufId=%s type=%s size=0x%x probeMask=0x%08x" % (sub, u(4), u(8), u(12) or 0, u(16) or 0)
        if len(body) >= 24:
            s += " extra=0x%x" % u(20)
        return s
    if cmd == 0x04:
        sub = u(0)
        if sub == 0 and len(body) >= 20:
            tm, sm, tsp, spp, pid = struct.unpack_from("<IIHHI", body, 4)
            return "ARM traceMode=0x%x sampleMode=0x%x tsPeriod=%d samplePeriod=%d pid=0x%x" % (tm, sm, tsp, spp, pid)
        return "sub=%s raw=%s" % (sub, body[4:].hex())
    if cmd == 0x09:
        return "bufId=%s offset=0x%x count=0x%x" % (u(0), u(4) or 0, u(8) or 0)
    if cmd == 0x0a and len(body) >= 8:
        sub, ss, pid = struct.unpack_from("<HHI", body, 0)
        return "trigger sub=%d startStop=%d pid=0x%x rest=%s" % (sub, ss, pid, body[8:].hex())
    return body.hex()


def pamp_reply(send, node, flags, cmd, rid, body):
    def res(b=b"", result=0):
        send(frame(struct.pack("<IIII", cmd, rid, len(b), result) + b, node, PAMP, flags))

    def notify(ncmd, b):
        send(frame(struct.pack("<IIII", ncmd, 0, len(b), 0) + b, node, PAMP, flags))

    if cmd == 0x02:
        res(struct.pack("<I", 0x04000000))
    elif cmd == 0x03:
        bid = struct.unpack_from("<I", body, 4)[0] if len(body) >= 8 else 1
        PA.buffers[bid] = body
        res()
    elif cmd == 0x06:
        PA.capturing = True
        res()
        notify(0x80000000, struct.pack("<I", 0))
    elif cmd == 0x07:
        PA.capturing = False
        res()
        notify(0x80000001, struct.pack("<I", 0))
    elif cmd == 0x08:
        res(struct.pack("<III", 1 if PA.capturing else 0, len(TRACE[0]), len(TRACE[1])))
    elif cmd == 0x09:
        bid, off, cnt = struct.unpack_from("<III", body, 0)
        data = TRACE.get(bid, b"")[off:off + cnt]
        CH = 0xF000
        chunks = [data[i:i + CH] for i in range(0, len(data), CH)] or [b""]
        for i, ch in enumerate(chunks):
            more = 1 if i < len(chunks) - 1 else 0
            res(struct.pack("<I", more) + ch)
    elif cmd == 0x0c:
        PA.bookmark = body[:20].ljust(20, b"\0")
        res()
    elif cmd == 0x0d:
        res(PA.bookmark)
    elif cmd == 0x0f:
        res(bytes(0x88))
    elif cmd == 0x10:
        res(bytes(16))
    elif cmd == 0x12:
        res(struct.pack("<I", TIMEBASE))
    else:
        res()


def rx(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            return None
        b += d
    return b


def handle(conn, addr, idx):
    wl = threading.Lock()

    def send(b):
        with wl:
            conn.sendall(b)

    try:
        if rx(conn, 4) != b"DECI":
            return
        send(struct.pack(">II", MAGIC, 0x40) + bytes(56))
        while True:
            h = rx(conn, 16)
            if h is None:
                return
            ln = int.from_bytes(h[0:3], "little")
            if h[3] != MARKER or not 16 <= ln <= MAXPAY:
                log("[%d] bad hdr" % idx)
                return
            pay = rx(conn, ln - 16) if ln > 16 else b""
            flags, node, proto = struct.unpack_from("<HHI", h, 4)
            if proto == NETMP:
                code = pay[0] if pay else 0xff
                res = {0: struct.pack("<I", 0), 2: struct.pack("<I", 0), 4: bytes(8), 6: bytes(8), 8: bytes(8),
                       12: bytes(4), 14: bytes(4),
                       10: struct.pack("<II", 0, len(PROTOS)) + b"".join(
                           struct.pack("<IIIHH", p, MAXPAY, 0, nd, 0) for p, nd in PROTOS)}.get(code)
                if res is not None:
                    send(frame(struct.pack("<BBH", code + 1, 0, 0) + res, node, proto, flags))
                if code == 0 and len(pay) > 8:
                    log("[%d] NETMP CONNECT %s" % (idx, pay[8:].split(b"\0")[0].decode(errors="replace")))
                continue
            if proto == CPUP:
                if len(pay) < 12 or pay[0] & 1:
                    continue
                code, arg, seq = pay[0], *struct.unpack_from("<II", pay, 4)
                bl = {1: 0x18, 3: 8, 0xb: 0x10}.get(code + 1, 4)
                send(frame(struct.pack("<BBHII", code + 1, 0, 0, arg, seq) + bytes(bl), node, proto, flags))
                continue
            if proto == TSMP and len(pay) >= 12:
                t, c, _p, arg, seq = struct.unpack_from("<BBHII", pay, 0)
                if c & 1 or t == 6:
                    continue
                send(frame(struct.pack("<BBHII", t, c + 1, 0, arg, seq) + tsmp_body(t, c, pay[12:]), node, proto, flags))
                continue
            if proto == DBGP:
                r = dbgp_res(pay) if len(pay) >= 3 else None
                log("[%d] DBGP group=0x%02x code=0x%02x len=%d %s%s" % (
                    idx, pay[1] if len(pay) > 1 else 0, pay[2] if len(pay) > 2 else 0, ln,
                    pay[:64].hex(), "" if r else "  (UNANSWERED)"))
                if r:
                    for part in dbgp_builders.fragment(r, 0x10000):
                        send(frame(part, node, proto, flags))
                continue
            if proto == PAMP:
                if len(pay) < 12:
                    log("[%d] PAMP short %s" % (idx, pay.hex()))
                    continue
                cmd, rid, plen = struct.unpack_from("<III", pay, 0)
                body = pay[12:]
                log("[%d] PAMP %-32s id=%d len=%d  %s" % (idx, PAMP_NAMES.get(cmd, "0x%x" % cmd), rid, plen,
                                                        describe(cmd, body)))
                pamp_reply(send, node, flags, cmd, rid, body)
                continue
            if proto == VCP:
                frames = vcp_builders.screenshot_res(pay, 960, 544, SHOT, pid=GAME_PID)
                log("[%d] VCP %s -> %d frame(s)" % (idx, pay[:8].hex(), len(frames)))
                for p in frames:
                    send(frame(p, node, proto, flags))
                continue
            log("[%d] proto 0x%x len %d ignored: %s" % (idx, proto, ln, pay[:48].hex()))
    except Exception as e:
        log("[%d] ERR %r" % (idx, e))
    finally:
        conn.close()


def udp(stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 8540))
    s.settimeout(1)
    while time.time() < stop:
        try:
            d, a = s.recvfrom(65535)
        except OSError:
            continue
        if len(d) >= 32 and d[3] == MARKER and d[16:18] == b"\x01\x02":
            flags, node, proto = struct.unpack_from("<HHI", d, 4)
            s.sendto(frame(d[16:17] + b"\x03" + d[18:28] + d[28:32], node, proto, flags), a)


if __name__ == "__main__":
    stop = time.time() + DURATION
    threading.Thread(target=udp, args=(stop,), daemon=True).start()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8540))
    srv.listen(16)
    srv.settimeout(1)
    log("mock_pamp on 127.0.0.1:8540 hwid=%d trace0=%d trace1=%d bytes, %ds" % (
        HWID, len(TRACE[0]), len(TRACE[1]), DURATION))
    i = 0
    while time.time() < stop:
        try:
            c, a = srv.accept()
        except socket.timeout:
            continue
        i += 1
        threading.Thread(target=handle, args=(c, a, i), daemon=True).start()
    log("done")
