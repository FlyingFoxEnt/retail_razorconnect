"""Mock PS Vita DevKit for Sony Target Manager / Neighborhood - stage 13.

Adds the UDP discovery responder so the target self-announces to Neighborhood's
"Add Network Target" dialog, alongside the TCP session already implemented.

UDP discovery (captured live):
    TM broadcasts to UDP 8540 from an ephemeral port:
        20 00 00 40 | 00 00 00 00 | 00 20 00 00 | 00 00 00 00
        01 02 00 00 | 00 00 00 00 | 00 00 00 00 | <u32 attempt>
    i.e. a normal frame, node=0, proto=0x2000 (TSMP),
         type=1 code=2 = UDP_FIND_TARGET_CMD, 4-byte body.
    Reply: type=1 code=3 = UDP_FIND_TARGET_RES, 4-byte body (decoder reads 4).

Full protocol reference: PROTOCOL.md

Usage: mock13.py <seconds> [hwid] [udp-body-hex]
"""
import socket, struct, sys, threading, time

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 600
HWID = int(sys.argv[2]) if len(sys.argv) > 2 else 1444602
UDP_BODY_HEX = sys.argv[3] if len(sys.argv) > 3 else "echo"

MAGIC = 0x15A3F8E1
MARKER = 0x40
PROTO_TSMP = 0x2000
PROTO_NETMP = 0x1000

IDENT = "MockVita@PSP2,NetworkManager"

NAMES = {
    (1,0):"TARGET_LIST_CMD",(1,1):"TARGET_LIST_RES",
    (1,2):"UDP_FIND_TARGET_CMD",(1,3):"UDP_FIND_TARGET_RES",
    (2,0):"TARGET_SELECT_CMD",(2,1):"TARGET_SELECT_RES",
    (2,2):"TARGET_DESELECT_CMD",(2,3):"TARGET_DESELECT_RES",
    (3,0):"HW_INFO_CMD",(3,1):"HW_INFO_RES",(3,2):"STICKY_NOTE_CMD",(3,3):"STICKY_NOTE_RES",
    (3,4):"SW_INFO_CMD",(3,5):"SW_INFO_RES",(3,6):"EXPIRY_CMD",(3,7):"EXPIRY_RES",
    (3,8):"USB_INFO_CMD",(3,9):"USB_INFO_RES",
    (4,0):"POWER_STATUS_CMD",(4,1):"POWER_STATUS_RES",(4,2):"POWER_CONTROL_CMD",
    (4,3):"POWER_CONTROL_RES",(4,4):"UPDATE_ACTIVATION_CMD",(4,5):"UPDATE_ACTIVATION_RES",
    (5,0):"SETTINGS/NOTIFY",(5,1):"GET_SETTINGS_RES",
}

LOCK = threading.Lock()
def log(m):
    with LOCK:
        print("%s %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def hexdump(d, p=""):
    return "\n".join("%s%04x  %-47s |%s|" % (p, o, " ".join("%02x" % b for b in d[o:o+16]),
                     "".join(chr(b) if 32 <= b < 127 else "." for b in d[o:o+16]))
                     for o in range(0, len(d), 16))

def frame(t, c, arg, seq, body=b"", node=0x4000, proto=PROTO_TSMP, flags=0):
    p = struct.pack("<BBHII", t, c, 0, arg, seq) + body
    tot = 16 + len(p)
    return (struct.pack("<I", tot)[:3] + bytes([MARKER])
            + struct.pack("<HHII", flags, node, proto, 0) + p)

def blob(s):
    b = s.encode("ascii", "replace") + bytes([0])
    return struct.pack("<IHH", 0, len(b), 0) + b

BODY = {
    (1,1): lambda: struct.pack("<II", 0, 1) + struct.pack("<IIII", HWID, 1, 0, 0),
    (1,3): lambda: struct.pack("<I", 0),
    (2,1): lambda: struct.pack("<I", 0),
    (2,3): lambda: struct.pack("<I", 0),
    (3,1): lambda: blob("PSP2 DevKit"),
    (3,3): lambda: struct.pack("<II", 0, 0),
    (3,5): lambda: blob("3.570.011"),
    (3,7): lambda: struct.pack("<II", 0xFFFFFFFF, 0),
    (3,9): lambda: bytes(0x30),
    (4,1): lambda: struct.pack("<II", 1, 0),
    (4,3): lambda: struct.pack("<I", 0),
    (4,5): lambda: struct.pack("<I", 0),
    (5,1): lambda: blob(""),
}

# CONNECT_RES per decoder FUN_1400d42d0: u32 result; 0x60-byte block whose u32 at
# +0x5c is a count; then count entries of 16 bytes (protocol descriptors).
PROTOCOLS = [
    (0x1000, 1, 0x10800, 0),   # NETMP
    (0x2000, 1, 0x10800, 0),   # TSMP
]

def netmp_body(code):
    if code == 1:                                   # CONNECT_RES
        b = bytearray(0x60)
        struct.pack_into("<I", b, 0, 0)             # result = success
        struct.pack_into("<I", b, 0x5c, len(PROTOCOLS))
        ent = b"".join(struct.pack("<IIII", *p) for p in PROTOCOLS)
        return bytes(b) + ent
    if code == 11:                                  # PROTO_LIST_RES
        b = bytearray(4)
        ent = b"".join(struct.pack("<IIII", *p) for p in PROTOCOLS)
        return bytes(b) + struct.pack("<I", len(PROTOCOLS)) + ent
    return struct.pack("<I", 0)

# --------------------------------------------------------------- UDP discovery
def udp_server(stop_at):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        pass
    s.bind(("0.0.0.0", 8540))
    s.settimeout(1.0)
    log("UDP discovery responder on 0.0.0.0:8540")
    while time.time() < stop_at:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError as e:
            log("UDP error %s" % e)
            continue
        if len(data) < 28 or data[3] != MARKER:
            log("UDP <- %s:%d unrecognised %d bytes" % (addr[0], addr[1], len(data)))
            continue
        flags, node, proto, _r = struct.unpack_from("<HHII", data, 4)
        t, c, _p, arg, seq = struct.unpack_from("<BBHII", data, 16)
        body = data[28:]
        log("UDP <- %s:%d  %s t%d.c%d node=0x%x proto=0x%x body=%s"
            % (addr[0], addr[1], NAMES.get((t, c), "?"), t, c, node, proto, body.hex()))
        if (t, c) != (1, 2):
            continue
        rb = body[:4] if UDP_BODY_HEX == "echo" else bytes.fromhex(UDP_BODY_HEX)
        if len(rb) != 4:
            rb = struct.pack("<I", 0)
        reply = frame(1, 3, arg, seq, rb, node=node, proto=proto, flags=flags)
        try:
            s.sendto(reply, addr)
            log("UDP -> %s:%d  UDP_FIND_TARGET_RES body=%s\n%s"
                % (addr[0], addr[1], rb.hex(), hexdump(reply, "   ")))
        except OSError as e:
            log("UDP send failed: %s" % e)
    log("UDP responder stopped")

# --------------------------------------------------------------- TCP session
def rx(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            return None
        b += d
    return b

def handle(conn, addr, idx):
    log("[%d] TCP connect from %s:%d" % (idx, addr[0], addr[1]))
    conn.settimeout(30.0)
    try:
        if rx(conn, 4) != b"DECI":
            return
        conn.sendall(struct.pack(">II", MAGIC, 0x40) + bytes(56))
        while True:
            h = rx(conn, 16)
            if h is None:
                log("[%d] server closed" % idx)
                return
            ln = int.from_bytes(h[0:3], "little")
            if h[3] != MARKER or not (16 <= ln <= 0x11000):
                return
            r = rx(conn, ln - 16) if ln > 16 else b""
            if r is None:
                return
            m = h + r
            flags, node, proto, _resv = struct.unpack_from("<HHII", m, 4)
            t, c, _p, arg, seq = struct.unpack_from("<BBHII", m, 16)
            body = m[28:]
            txt = bytes(b for b in body if 32 <= b < 127)
            log("[%d] <- proto=0x%04x %-20s t%d.c%d arg=0x%x%s"
                % (idx, proto, NAMES.get((t, c), "?"), t, c, arg,
                   ("  %r" % txt) if len(txt) > 3 else ""))

            if proto == PROTO_NETMP:
                if t % 2 == 0:                      # NETMP: single code byte
                    nb = netmp_body(t + 1)
                    p = struct.pack("<BBHI", t + 1, 0, 0, len(nb)) + nb if False else                         struct.pack("<BBH", t + 1, 0, 0) + nb
                    tot = 16 + len(p)
                    pkt = (struct.pack("<I", tot)[:3] + bytes([MARKER])
                           + struct.pack("<HHII", flags, node, proto, 0) + p)
                    conn.sendall(pkt)
                    log("[%d] -> NETMP code=%d (%d body bytes)" % (idx, t + 1, len(nb)))
                continue
            if t == 5:
                continue
            if c % 2 == 1:
                continue
            rc = c + 1
            mk = BODY.get((t, rc))
            rb = mk() if mk else struct.pack("<I", 0)
            conn.sendall(frame(t, rc, arg, seq, rb, node=node, proto=proto))
            log("[%d] -> %-20s t%d.c%d" % (idx, NAMES.get((t, rc), "?"), t, rc))
    except socket.timeout:
        log("[%d] idle" % idx)
    except OSError as e:
        log("[%d] err %s" % (idx, e))
    finally:
        try:
            conn.close()
        except OSError:
            pass

stop_at = time.time() + DURATION
threading.Thread(target=udp_server, args=(stop_at,), daemon=True).start()

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 8540))
srv.listen(8)
srv.settimeout(1.0)
log("mock13 TCP+UDP on 0.0.0.0:8540 for %ds, hwid=%d" % (DURATION, HWID))
i = 0
while time.time() < stop_at:
    try:
        c, a = srv.accept()
    except socket.timeout:
        continue
    i += 1
    threading.Thread(target=handle, args=(c, a, i), daemon=True).start()
time.sleep(0.5)
log("done, %d TCP connections" % i)
