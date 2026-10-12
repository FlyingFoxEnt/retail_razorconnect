"""PC stand-in for the Vita that checks Battery Monitor end to end against psp2tm.

Answers Target Manager the way plugin/rrc_user.c does (same NETMP/TSMP replies)
and implements PMEP (0x4000) exactly as recovered from psp2tm.exe, see
PMEP_FORMAT.md. Every PMEP command is logged with its payload so the GUI's
requests can be read back.

    python mock_pmep.py <seconds> [hwid]
    psp2ctrl find 127.0.0.1
    psp2ctrl add 00000000000000000000000100160afb
    PSP2BatteryMonitor.exe /target 00000000000000000000000100160afb
    psp2ctrl delete 00000000000000000000000100160afb

Use an hwid other than the real console's (1444602) so its registration is
left alone.
"""
import math, os, socket, struct, sys, threading, time

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 300
HWID = int(sys.argv[2]) if len(sys.argv) > 2 else 1444603

MAGIC, MARKER, MAXPAY = 0x15A3F8E1, 0x40, 0x10800
NETMP, TSMP, CPUP, PMEP = 0x1000, 0x2000, 0x3000, 0x4000
PROTOS = [(NETMP, 0x0011), (TSMP, 0x0022), (CPUP, 0x0033), (PMEP, 0x0044)]

# eUnits (Interop.PSP2TMAPILib): NotUsed=0, MilliAmps=1, Celcius=2
UNITS_NONE, UNITS_MA, UNITS_C = 0, 1, 2
# (name, units, scale factor) -> GET_PROPERTIES_RES records
CHANNELS = [("Battery", UNITS_MA, 1.0), ("Temperature", UNITS_C, 1.0)]

# eBatteryValue ids -> values (GET_BATTERY_VALUES_RES).  Distinct numbers so the
# GUI's use of each one can be read off a screenshot.
BATTERY = {0: 31, 1: 3777, 2: 1234, 3: 2210, 4: -321, 5: 187, 6: 33, 7: 95, 8: 67}
STATE = {"ac": 0}
# Experiment: CPUP GET_INFO version words (PMEP_CPVER=0x01000400) to find the gate on
# GET_POWER_STATUS (psp2tm FUN_14010d4f0 needs target+0x784 > 0x1000300).
CPVER = int(os.environ.get("PMEP_CPVER", "0"), 0)

LOCK = threading.Lock()
def log(m):
    with LOCK:
        print("%s %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def frame(payload, node, proto, flags=0):
    return (struct.pack("<I", 16 + len(payload))[:3] + bytes([MARKER])
            + struct.pack("<HHII", flags, node, proto, 0) + payload)

def pad4(b):
    return b + bytes((-len(b)) % 4)

def nv(name, value, vtype):
    nb = name.encode() + b"\0"
    body = pad4(nb) + struct.pack("<HH", len(value), vtype) + pad4(value)
    return struct.pack("<II", 8 + len(body), len(nb)) + body

def keys(body):
    out, off = [], 4
    count = struct.unpack_from("<I", body, 0)[0] if len(body) >= 4 else 0
    for _ in range(min(count, 64)):
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
        return struct.pack("<IHH", 0, len(ks), 0) + b"".join(
            nv(k, struct.pack("<I", 0x03740000), 0) for k in ks)
    if (t, c) == (3, 2):
        return struct.pack("<II", 0, 0)
    if (t, c) == (3, 6):
        return struct.pack("<II", 0, 0xFFFFFFFF)
    if (t, c) == (3, 8):
        head = bytearray(0x30)
        struct.pack_into("<I", head, 4, 0x2c)
        return bytes(head) + struct.pack("<II", 8, 0)
    if (t, c) == (4, 0):
        return struct.pack("<II", 0, 0x100)            # POWER_STATUS_ON, like the plugin
    if t == 5 and c in (0, 2):
        ks = keys(body)
        return struct.pack("<IHH", 0, len(ks), 0) + b"".join(nv(k, b"MockPMEP\0", 2) for k in ks)
    if (t, c) == (5, 8):
        x = b"<?xml version=\"1.0\"?><settings/>\0"
        return struct.pack("<II", 0, len(x)) + pad4(x)
    return struct.pack("<I", 0)

# ------------------------------------------------------------------ PMEP
T0 = time.time()

def channel_values():
    t = time.time() - T0
    cur = int(180 + 60 * math.sin(t / 3.0))              # mA, wobbles so the graph moves
    temp = 31
    return [cur, temp]

def prop_record(name, units, scale):
    nb = name.encode("utf-8") + b"\0"
    body = struct.pack("<I", len(nb)) + pad4(nb) + struct.pack("<If", units, scale)
    return struct.pack("<I", 4 + len(body)) + body

def pmep_body(code, body):
    """Return (response body) for command `code`; None = no reply."""
    if code == 0x00:                                     # GET_PROPERTIES -> 0x01
        recs = b"".join(prop_record(*c) for c in CHANNELS)
        return struct.pack("<III", 0, 0, len(CHANNELS)) + recs
    if code == 0x02:                                     # GET_STATUS -> 0x03 (channel data)
        v = channel_values()
        return pad4(struct.pack("<II", 0, len(v)) + b"".join(
            struct.pack("<H", x & 0xffff) for x in v))
    if code == 0x04:                                     # GET_BATTERY_VALUES -> 0x05
        n = struct.unpack_from("<I", body, 0)[0] if len(body) >= 4 else 0
        ids = list(struct.unpack_from("<%dI" % n, body, 4)) if len(body) >= 4 + 4 * n else []
        out = b"".join(struct.pack("<Ii", i, BATTERY.get(i, 0)) for i in ids)
        return struct.pack("<II", 0, len(ids)) + out
    if code == 0x06:                                     # SET_BATTERY_VALUES -> 0x07
        n = struct.unpack_from("<I", body, 0)[0] if len(body) >= 4 else 0
        for k in range(n):
            if len(body) >= 12 + 8 * k:
                i, v = struct.unpack_from("<Ii", body, 4 + 8 * k)
                BATTERY[i] = v
        return struct.pack("<I", 0)
    if code == 0x08:                                     # SET_AC_STATUS -> 0x09
        STATE["ac"] = struct.unpack_from("<I", body, 0)[0] if len(body) >= 4 else 0
        return struct.pack("<I", 0)
    if code == 0x0C:                                     # GET_AC_STATUS -> 0x0D
        return struct.pack("<II", 0, STATE["ac"])
    if code == 0x12:                                     # GET_POWER_STATUS -> 0x13 (voltage)
        recs = [(0, 0, struct.unpack("<I", struct.pack("<f", 3.777))[0])]
        return struct.pack("<II", 0, len(recs)) + b"".join(struct.pack("<HHI", *r) for r in recs)
    return None

def rx(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            return None
        b += d
    return b

def handle(conn, addr, idx):
    log("[%d] connect from %s:%d" % (idx, addr[0], addr[1]))
    try:
        if rx(conn, 4) != b"DECI":
            return
        conn.sendall(struct.pack(">II", MAGIC, 0x40) + bytes(56))
        while True:
            h = rx(conn, 16)
            if h is None:
                log("[%d] peer closed" % idx)
                return
            ln = int.from_bytes(h[0:3], "little")
            if h[3] != MARKER or not 16 <= ln <= MAXPAY:
                log("[%d] bad header %s" % (idx, h.hex()))
                return
            pay = rx(conn, ln - 16) if ln > 16 else b""
            flags, node, proto = struct.unpack_from("<HHI", h, 4)
            if proto == NETMP:
                code = pay[0] if pay else 0xff
                res = {0: struct.pack("<I", 0), 2: struct.pack("<I", 0),
                       4: bytes(8), 6: bytes(8), 8: bytes(8), 12: bytes(4), 14: bytes(4),
                       10: struct.pack("<II", 0, len(PROTOS)) + b"".join(
                           struct.pack("<IIIHH", p, MAXPAY, 0, nd, 0) for p, nd in PROTOS)}.get(code)
                if res is None:
                    continue
                conn.sendall(frame(struct.pack("<BBH", code + 1, 0, 0) + res, node, proto, flags))
                continue
            if proto == PMEP:
                if len(pay) < 12 or pay[0] & 1:
                    continue
                code, arg, seq = pay[0], *struct.unpack_from("<II", pay, 4)
                body = pay[12:]
                res = pmep_body(code, body)
                log("[%d] PMEP cmd 0x%02x arg 0x%x seq %d body %s -> %s" % (
                    idx, code, arg, seq, body.hex(), "none" if res is None else res.hex()))
                if res is None:
                    continue
                conn.sendall(frame(struct.pack("<BBHII", code + 1, 0, 0, arg, seq) + res,
                                   node, proto, flags))
                continue
            if proto == CPUP:
                if len(pay) < 12 or pay[0] & 1:
                    continue
                code, arg, seq = pay[0], *struct.unpack_from("<II", pay, 4)
                bl = {1: 0x18, 3: 8, 0xb: 0x10}.get(code + 1, 4)
                res = bytes(bl)
                if code == 0 and CPVER:
                    res = struct.pack("<6I", 0, CPVER, CPVER, CPVER, CPVER, CPVER)
                log("[%d] CPUP cmd 0x%02x -> %s" % (idx, code, res.hex()))
                conn.sendall(frame(struct.pack("<BBHII", code + 1, 0, 0, arg, seq) + res,
                                   node, proto, flags))
                continue
            if proto == TSMP and len(pay) >= 12:
                t, c, _p, arg, seq = struct.unpack_from("<BBHII", pay, 0)
                if c & 1 or t == 6:
                    continue
                conn.sendall(frame(struct.pack("<BBHII", t, c + 1, 0, arg, seq)
                                   + tsmp_body(t, c, pay[12:]), node, proto, flags))
                continue
            log("[%d] ignored proto 0x%x len %d" % (idx, proto, ln))
    except Exception as e:
        log("[%d] ERR %r" % (idx, e))
    finally:
        conn.close()

def udp(stop_at):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 8540))
    s.settimeout(1.0)
    while time.time() < stop_at:
        try:
            d, a = s.recvfrom(65535)
        except OSError:
            continue
        if len(d) >= 32 and d[3] == MARKER and d[16:18] == b"\x01\x02":
            flags, node, proto = struct.unpack_from("<HHI", d, 4)
            s.sendto(frame(d[16:17] + b"\x03" + d[18:28] + d[28:32], node, proto, flags), a)

if __name__ == "__main__":
    stop_at = time.time() + DURATION
    threading.Thread(target=udp, args=(stop_at,), daemon=True).start()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8540))
    srv.listen(8)
    srv.settimeout(1.0)
    log("mock_pmep on 127.0.0.1:8540 for %ds, hwid %d" % (DURATION, HWID))
    i = 0
    while time.time() < stop_at:
        try:
            c, a = srv.accept()
        except socket.timeout:
            continue
        i += 1
        threading.Thread(target=handle, args=(c, a, i), daemon=True).start()
    log("done")
