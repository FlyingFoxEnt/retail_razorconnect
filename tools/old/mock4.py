"""Mock PS Vita DECI4P target - stage 4: answer TSMP commands.

Recovered from psp2tm.exe with Ghidra:

  Handshake            FUN_1400e01b0
      <- "DECI"
      -> u32be 0x15A3F8E1 | u32be 0x40 | 56 bytes (14 x u32be)

  Frame header (16 b)  FUN_1400db470 (writer) / FUN_1400e0770 (reader)
      u24 length (LE)      total frame size, must be 16..0x11000
      u8  0x40             marker, reader checks == '@'
      u16 flags
      u16 node             0x4000 from host
      u32 protocol         0x2000 = TSMP
      u32 reserved

  TSMP payload (12 b)  FUN_1400db780
      u8 type | u8 code | u16 pad | u32 arg | u32 seq | ...body

  TSMP vocabulary      FUN_14008d1b0  (even code = CMD, odd = RES)
      1 LIST     0/1 TARGET_LIST      2/3 UDP_FIND_TARGET
      2 SELECT   0/1 TARGET_SELECT    2/3 TARGET_DESELECT
      3 INFO     0/1 HW_INFO  2/3 SET_STICKY_NOTE  4/5 SW_INFO
                 6/7 GET_EXPIRY_TIME  8/9 GET_USB_INFO
      4 CONTROL  0/1 POWER_STATUS  2/3 POWER_CONTROL  4/5 UPDATE_ACTIVATION
      5 SETTINGS 0/1 GET  2/3 GET_CURRENT  4/5 SET  6/7 UIFILE  8/9 XML

Usage: mock4.py <seconds> [payload-style]
   payload-style: empty | zeros | rich   (default rich)
"""
import socket, struct, sys, threading, time

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 90
STYLE = sys.argv[2] if len(sys.argv) > 2 else "rich"

MAGIC = 0x15A3F8E1
MARKER = 0x40
PROTO_TSMP = 0x2000

NAMES = {
    (0, 0): "ERROR",
    (1, 0): "TARGET_LIST_CMD", (1, 1): "TARGET_LIST_RES",
    (1, 2): "UDP_FIND_TARGET_CMD", (1, 3): "UDP_FIND_TARGET_RES",
    (2, 0): "TARGET_SELECT_CMD", (2, 1): "TARGET_SELECT_RES",
    (2, 2): "TARGET_DESELECT_CMD", (2, 3): "TARGET_DESELECT_RES",
    (3, 0): "HW_INFO_CMD", (3, 1): "HW_INFO_RES",
    (3, 2): "SET_STICKY_NOTE_CMD", (3, 3): "SET_STICKY_NOTE_RES",
    (3, 4): "SW_INFO_CMD", (3, 5): "SW_INFO_RES",
    (3, 6): "GET_EXPIRY_TIME_CMD", (3, 7): "GET_EXPIRY_TIME_RES",
    (3, 8): "GET_USB_INFO_CMD", (3, 9): "GET_USB_INFO_RES",
    (4, 0): "POWER_STATUS_CMD", (4, 1): "POWER_STATUS_RES",
    (4, 2): "POWER_CONTROL_CMD", (4, 3): "POWER_CONTROL_RES",
    (4, 4): "UPDATE_ACTIVATION_CMD", (4, 5): "UPDATE_ACTIVATION_RES",
    (5, 0): "GET_SETTINGS_CMD", (5, 1): "GET_SETTINGS_RES",
    (5, 2): "GET_CURRENT_SETTINGS_CMD", (5, 3): "GET_CURRENT_SETTINGS_RES",
    (5, 4): "SET_SETTINGS_CMD", (5, 5): "SET_SETTINGS_RES",
    (5, 6): "GET_SETTINGS_UIFILE_CMD", (5, 7): "GET_SETTINGS_UIFILE_RES",
    (5, 8): "GET_SETTINGS_XML_CMD", (5, 9): "GET_SETTINGS_XML_RES",
}

# Identity the mock reports. Strings are length-prefixed wide/ascii variants tried below.
TARGET_NAME = "MockVita"
HWID = 1444602          # the hwid seen in Neighborhood's logs
FW_VERSION = 0x03570011  # 3.570.011

LOCK = threading.Lock()
def log(m):
    with LOCK:
        print("%s %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def hexdump(d, p=""):
    return "\n".join("%s%04x  %-47s |%s|" % (p, o, " ".join("%02x" % b for b in d[o:o+16]),
                     "".join(chr(b) if 32 <= b < 127 else "." for b in d[o:o+16]))
                     for o in range(0, len(d), 16))

def frame(ttype, code, arg, seq, body=b"", node=0x4000, flags=0):
    payload = struct.pack("<BBHII", ttype, code, 0, arg, seq) + body
    total = 16 + len(payload)
    return (struct.pack("<I", total)[:3] + bytes([MARKER])
            + struct.pack("<HHII", flags, node, PROTO_TSMP, 0) + payload)

def cstr(s, size):
    b = s.encode("ascii", "replace")[:size - 1]
    return b + b"\x00" * (size - len(b))

def body_for(ttype, code):
    """Best-effort response bodies. Unknown layouts start zeroed; the server's
    log tells us which ones it rejects, and we refine from there."""
    if STYLE == "empty":
        return b""
    if STYLE == "zeros":
        return b"\x00" * 32
    # 'rich': plausible identity data
    if (ttype, code) == (1, 1):        # TARGET_LIST_RES
        # count + one entry: id, then a name
        return struct.pack("<II", 1, HWID) + cstr(TARGET_NAME, 32)
    if (ttype, code) == (3, 1):        # HW_INFO_RES
        return struct.pack("<III", HWID, 1, 0) + cstr("PSP2 DevKit", 32)
    if (ttype, code) == (3, 5):        # SW_INFO_RES
        return struct.pack("<II", FW_VERSION, FW_VERSION) + cstr("3.570.011", 32)
    if (ttype, code) == (3, 3):        # SET_STICKY_NOTE_RES
        return struct.pack("<I", 0)
    if (ttype, code) == (3, 7):        # GET_EXPIRY_TIME_RES
        return struct.pack("<II", 0xFFFFFFFF, 0)
    if (ttype, code) == (3, 9):        # GET_USB_INFO_RES
        return struct.pack("<I", 0) + cstr("", 32)
    if (ttype, code) == (4, 1):        # POWER_STATUS_RES  (1 = on?)
        return struct.pack("<II", 1, 0)
    if (ttype, code) == (2, 1):        # TARGET_SELECT_RES
        return struct.pack("<I", 0)
    return struct.pack("<I", 0)

def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        c = conn.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf

def handle(conn, addr, idx):
    log("[%d] connect from %s:%d" % (idx, addr[0], addr[1]))
    conn.settimeout(20.0)
    try:
        if recv_exact(conn, 4) != b"DECI":
            return
        conn.sendall(struct.pack(">II", MAGIC, 0x40) + b"\x00" * 56)
        log("[%d] handshake ok" % idx)
        while True:
            head = recv_exact(conn, 16)
            if head is None:
                log("[%d] server closed" % idx)
                return
            length = int.from_bytes(head[0:3], "little")
            if head[3] != MARKER or not (16 <= length <= 0x11000):
                log("[%d] bad header\n%s" % (idx, hexdump(head, "[%d] " % idx)))
                return
            rest = recv_exact(conn, length - 16) if length > 16 else b""
            if rest is None:
                return
            msg = head + rest
            flags, node, proto, _r = struct.unpack_from("<HHII", msg, 4)
            ttype, code, _p, arg, seq = struct.unpack_from("<BBHII", msg, 16)
            body = msg[28:]
            name = NAMES.get((ttype, code), "?")
            txt = bytes(b for b in body if 32 <= b < 127)
            log("[%d] <- proto=0x%x node=0x%x %s (t%d.c%d) arg=0x%x seq=%d len=%d%s"
                % (idx, proto, node, name, ttype, code, arg, seq, length,
                   ("  text=%r" % txt) if len(txt) > 3 else ""))
            if body:
                log(hexdump(body, "[%d]   body " % idx))

            if code % 2 == 1:
                log("[%d]    (already a RES - not replying)" % idx)
                continue
            rtype, rcode = ttype, code + 1
            reply = frame(rtype, rcode, arg, seq, body_for(rtype, rcode), node=node)
            conn.sendall(reply)
            log("[%d] -> %s (t%d.c%d) %d bytes"
                % (idx, NAMES.get((rtype, rcode), "?"), rtype, rcode, len(reply)))
    except socket.timeout:
        log("[%d] idle 20s, socket still open" % idx)
    except OSError as e:
        log("[%d] socket error: %s" % (idx, e))
    finally:
        try:
            conn.close()
        except OSError:
            pass

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 8540))
    srv.listen(8)
    srv.settimeout(1.0)
    log("mock4 on 0.0.0.0:8540 for %ds, payload style=%s" % (DURATION, STYLE))
    deadline = time.time() + DURATION
    idx = 0
    while time.time() < deadline:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        idx += 1
        threading.Thread(target=handle, args=(conn, addr, idx), daemon=True).start()
    time.sleep(0.5)
    log("done; %d connections" % idx)

main()
