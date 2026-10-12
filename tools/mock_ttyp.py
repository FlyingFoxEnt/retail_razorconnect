"""PC stand-in for the Vita that checks Console Output end to end against psp2tm.

Answers Target Manager the way plugin/rrc_user.c does (same PROTO_LIST, same
TSMP/CPUP replies) and, once a session is live, pushes TTYP frames built
byte-for-byte like ttyp_push(): user output on stream 0, kernel output on
stream 0x90, and one line split across two frames the way rrc_tty.skprx splits
a line that is still waiting for its newline.

    python mock_ttyp.py <seconds> [hwid]
    psp2ctrl find 127.0.0.1
    psp2ctrl add <hwid>
    psp2ctrl console all csv <hwid>      # Sink ID, Process ID, Thread ID, Time, Text
    psp2ctrl delete <hwid>

Use an hwid other than the real console's (1444602) so its registration is
left alone.
"""
import socket, struct, sys, threading, time

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 120
HWID = int(sys.argv[2]) if len(sys.argv) > 2 else 1444603

MAGIC, MARKER, MAXPAY = 0x15A3F8E1, 0x40, 0x10800
NETMP, TSMP, CPUP, PMEP, TTYP = 0x1000, 0x2000, 0x3000, 0x4000, 0x80030000
STDOUT, KERNEL0 = 0x00, 0x90
USER, KERNEL = 0x1000, 0x8000

# rrc_user.c g_pnum / g_pnode
PROTOS = [(NETMP, 0x0011), (TSMP, 0x0022), (CPUP, 0x0033),
          (TTYP | STDOUT, 0xa000), (TTYP | KERNEL0, 0xa090), (PMEP, 0x0044)]

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
            nv(k, struct.pack("<I", 0x03650000), 0) for k in ks)
    if (t, c) in ((3, 2),):
        return struct.pack("<II", 0, 0)
    if (t, c) == (3, 6):
        return struct.pack("<II", 0, 0xFFFFFFFF)
    if (t, c) == (3, 8):
        head = bytearray(0x30)
        struct.pack_into("<I", head, 4, 0x2c)
        return bytes(head) + struct.pack("<II", 8, 0)
    if (t, c) == (4, 0):
        return struct.pack("<II", 0, 1)
    if t == 5 and c in (0, 2):
        ks = keys(body)
        return struct.pack("<IHH", 0, len(ks), 0) + b"".join(nv(k, b"MockTTY\0", 2) for k in ks)
    if (t, c) == (5, 8):
        x = b"<?xml version=\"1.0\"?><settings/>\0"
        return struct.pack("<II", 0, len(x)) + pad4(x)
    return struct.pack("<I", 0)

SEQ = [0]
def ttyp(stream, source, pid, tid, tick, text):
    """rrc_user.c ttyp_push()"""
    b = text.encode()
    hdr = struct.pack("<HBBIIIQI", source, 0, 0, pid, tid, SEQ[0], tick, len(b))
    SEQ[0] += 1
    return frame(hdr + b, 0xa000 | stream, TTYP | stream)

def pusher(conn, idx, live, dead):
    n = 0
    while not dead.is_set():
        time.sleep(2.0)
        if not live.is_set():
            continue
        n += 1
        t = int(time.monotonic() * 1e6)
        frames = [
            ttyp(KERNEL0, KERNEL, 0x10005, 0x10029, t,
                 "[rrc_tty] console capture active, handlers 0x3 (%d)\n" % n),
            ttyp(STDOUT, USER, 0x40010003, 0x40010011, t + 1000,
                 "[2026.09.14-19:00:00:000][  0]LogInit: Display: split line "),
            ttyp(STDOUT, USER, 0x40010003, 0x40010017, t + 2000,
                 "other thread, whole line (%d)\n" % n),
            ttyp(STDOUT, USER, 0x40010003, 0x40010011, t + 3000,
                 "joined on the PC (%d)\n" % n),
        ]
        try:
            for f in frames:
                conn.sendall(f)
            log("[%d] pushed TTYP batch %d" % (idx, n))
        except OSError as e:
            log("[%d] push failed %r" % (idx, e))
            return

def rx(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            return None
        b += d
    return b

def handle(conn, addr, idx):
    live, dead = threading.Event(), threading.Event()
    log("[%d] connect from %s:%d" % (idx, addr[0], addr[1]))
    try:
        if rx(conn, 4) != b"DECI":
            return
        conn.sendall(struct.pack(">II", MAGIC, 0x40) + bytes(56))
        threading.Thread(target=pusher, args=(conn, idx, live, dead), daemon=True).start()
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
                log("[%d] NETMP %d -> %d" % (idx, code, code + 1))
                if code == 10:
                    live.set()
                continue
            if proto in (CPUP, PMEP):
                if len(pay) < 12 or pay[0] & 1:
                    continue
                code, arg, seq = pay[0], *struct.unpack_from("<II", pay, 4)
                bl = {1: 0x18, 3: 8, 0xb: 0x10}.get(code + 1, 4) if proto == CPUP else \
                     {1: 0xc, 3: 8, 5: 8}.get(code + 1, 4)
                conn.sendall(frame(struct.pack("<BBHII", code + 1, 0, 0, arg, seq) + bytes(bl),
                                   node, proto, flags))
                continue
            if proto == TSMP and len(pay) >= 12:
                t, c, _p, arg, seq = struct.unpack_from("<BBHII", pay, 0)
                if c & 1 or t == 6:
                    continue
                conn.sendall(frame(struct.pack("<BBHII", t, c + 1, 0, arg, seq)
                                   + tsmp_body(t, c, pay[12:]), node, proto, flags))
                log("[%d] TSMP %d.%d" % (idx, t, c))
                continue
            log("[%d] ignored proto 0x%x len %d" % (idx, proto, ln))
    except Exception as e:
        log("[%d] ERR %r" % (idx, e))
    finally:
        dead.set()
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

stop_at = time.time() + DURATION
threading.Thread(target=udp, args=(stop_at,), daemon=True).start()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8540))
srv.listen(8)
srv.settimeout(1.0)
log("mock_ttyp on 127.0.0.1:8540 for %ds, hwid %d" % (DURATION, HWID))
i = 0
while time.time() < stop_at:
    try:
        c, a = srv.accept()
    except socket.timeout:
        continue
    i += 1
    threading.Thread(target=handle, args=(c, a, i), daemon=True).start()
log("done")
