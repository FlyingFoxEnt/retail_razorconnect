"""Mock PS Vita DevKit for Sony Target Manager - stage 16.

New in 16: correct TSMP "named value" records for HW_INFO / SW_INFO / SETTINGS.

Decoder ground truth (psp2tm.exe), TSMP payload base p = frame+0x10,
body = p+0xc (after u8 type, u8 code, u16 pad, u32 arg, u32 seq):

  FUN_1400d6ee0 TARGET_LIST_RES 1.1  u32 result, u16 count@+4, u16 pad, count*4 bytes
  FUN_1400d6800 UDP_FIND_RES    1.3  4
  FUN_1400d6cf0 SELECT_RES      2.1  4
  FUN_1400d6b70 HW_INFO_RES     3.1  u32 result, u16 count@+4, u16 pad, count named-values
  FUN_1400d6e70 SW_INFO_RES     3.5  same shape as 3.1
  FUN_1400d69a0 EXPIRY_RES      3.7  8
  FUN_1400d6ad0 USB_INFO_RES    3.9  0x30; if result==0, u32@+4 is a self-relative
                                     offset to a u32-length-prefixed blob
  FUN_1400d6be0 POWER_CTRL_RES  4.3  4
  FUN_1400d6fc0 UPD_ACT_RES     4.5  4
  FUN_1400d69f0 GET_SETTINGS_RES     5.1  u32, u16 count, u16, named-values
  FUN_1400d68a0 GET_CUR_SETTINGS_RES 5.3  same
  FUN_1400d6a60 SETTINGS_XML_RES     5.9  u32 result, u32 len@+4, len bytes @+8

Named-value record, pointer q (walked by FUN_1400cdeb0 using *(u32*)q as stride):
  q+0x00 u32 record_total_length
  q+0x04 u32 name_length (bytes, UTF-8, CP 0xfde9)
  q+0x08      name bytes, then padded to 4
  v = q + 8 + align4(name_length)
  v+0x00 u16 value_length (bytes)
  v+0x02 u16 value_type     (1 = binary, 2 = string)
  v+0x04      value bytes, then padded to 4
Proof: FUN_14007aad0 (name), FUN_14007aa40 + FUN_14007abb0 (value at v+4,
len = u16@v+0), FUN_14007a5d0 (CPID must be type 1, length 0x10).

Usage: mock16.py <seconds> [variant] [hwid]
"""
import socket, struct, sys, threading, time

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 600
VARIANT = sys.argv[2] if len(sys.argv) > 2 else "F"
HWID = int(sys.argv[3]) if len(sys.argv) > 3 else 1444602

MAGIC = 0x15A3F8E1
MARKER = 0x40
PROTO_TSMP = 0x2000
PROTO_NETMP = 0x1000
MAXPAY = 0x10800
PROTO_CPUP = 0x3000

# Protocol numbers, from the per-protocol frame accessors that test
# *(int*)(frame+8) == N, paired with the "Decoding <NAME> response" log string
# emitted by the validator that calls each accessor:
#   0x00100 DCMP   (FUN_1400d2810)   0x001000 NETMP  (FUN_1400d4e30)
#   0x02000 TSMP   (FUN_1400d6?..)   0x003000 CPUP   (FUN_1400cf610)
#   0x04000 PMEP   (FUN_1400d5950)   0x11000 ?       (FUN_1400d2cb0)
#   0x12000 RDRFP  (FUN_1400d6120)   0x20000 DBGP    (FUN_1400d1c80)
#   0x24000 LOADP  (FUN_1400d4940)   0x28000 PAMP    (FUN_1400d5380)
#   0x2b000 VCP    (FUN_1400d7270)   0x2c000 CTRLP   (FUN_1400cfa40)
#   0x2e000 ?      (FUN_1400d6420)

TARGET_ENTRY = struct.pack("<IIII", HWID, 1, 0, 0)

NETMP_NAMES = {0: "CONNECT_CMD", 1: "CONNECT_RES", 2: "DISCONNECT_CMD",
               3: "DISCONNECT_RES", 4: "REGISTER_CMD", 5: "REGISTER_RES",
               6: "UNREGISTER_CMD", 7: "UNREGISTER_RES", 8: "REGISTERED_LIST_CMD",
               9: "REGISTERED_LIST_RES", 10: "PROTO_LIST_CMD", 11: "PROTO_LIST_RES",
               12: "FORCE_DISCONNECT_CMD", 13: "FORCE_DISCONNECT_RES",
               14: "FORCE_UNREGISTER_CMD", 15: "FORCE_UNREGISTER_RES"}
NAMES = {(1, 0): "TARGET_LIST_CMD", (1, 1): "TARGET_LIST_RES",
         (1, 2): "UDP_FIND_TARGET_CMD", (1, 3): "UDP_FIND_TARGET_RES",
         (2, 0): "TARGET_SELECT_CMD", (2, 1): "TARGET_SELECT_RES",
         (2, 2): "TARGET_DESELECT_CMD", (2, 3): "TARGET_DESELECT_RES",
         (3, 0): "HW_INFO_CMD", (3, 1): "HW_INFO_RES",
         (3, 2): "STICKY_NOTE_CMD", (3, 3): "STICKY_NOTE_RES",
         (3, 4): "SW_INFO_CMD", (3, 5): "SW_INFO_RES",
         (3, 6): "EXPIRY_CMD", (3, 7): "EXPIRY_RES",
         (3, 8): "USB_INFO_CMD", (3, 9): "USB_INFO_RES",
         (4, 0): "POWER_STATUS_CMD", (4, 1): "POWER_STATUS_RES",
         (4, 2): "POWER_CONTROL_CMD", (4, 3): "POWER_CONTROL_RES",
         (4, 4): "UPDATE_ACTIVATION_CMD", (4, 5): "UPDATE_ACTIVATION_RES",
         (5, 0): "GET_SETTINGS_CMD", (5, 1): "GET_SETTINGS_RES",
         (5, 2): "GET_CURRENT_SETTINGS_CMD", (5, 3): "GET_CURRENT_SETTINGS_RES",
         (5, 4): "SET_SETTINGS_CMD", (5, 5): "SET_SETTINGS_RES",
         (5, 6): "GET_SETTINGS_UIFILE_CMD", (5, 7): "GET_SETTINGS_UIFILE_RES",
         (5, 8): "GET_SETTINGS_XML_CMD", (5, 9): "GET_SETTINGS_XML_RES",
         (6, 0): "NOTIFY_TOOL"}

LOCK = threading.Lock()
def log(m):
    with LOCK:
        print("%s %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def hexdump(d, p="   "):
    return "\n".join("%s%04x  %-47s |%s|" % (p, o, " ".join("%02x" % b for b in d[o:o + 16]),
                     "".join(chr(b) if 32 <= b < 127 else "." for b in d[o:o + 16]))
                     for o in range(0, len(d), 16))

def mkframe(payload, node=0x4000, proto=PROTO_TSMP, flags=0):
    return (struct.pack("<I", 16 + len(payload))[:3] + bytes([MARKER])
            + struct.pack("<HHII", flags, node, proto, 0) + payload)

def tsmp(t, c, arg, seq, body=b"", **kw):
    return mkframe(struct.pack("<BBHII", t, c, 0, arg, seq) + body, **kw)

def netmp(code, body=b"", **kw):
    return mkframe(struct.pack("<BBH", code, 0, 0) + body, **kw)

def pad4(b):
    return b + bytes((-len(b)) % 4)

def nv(name, value, vtype):
    """Build one named-value record.

    The NAME IS NUL-TERMINATED and name_length INCLUDES the NUL: psp2tm reads it
    with FUN_1401af520(ptr, 0xffffffff, 0xfde9, ...) i.e.
    MultiByteToWideChar(CP_UTF8, cbMultiByte = -1) which is NUL-terminated.
    Proof: HW_INFO_CMD on the wire asks for "CPID" as
        01 00 00 00 | 05 00 00 00 | 43 50 49 44 00 00 00 00
                       ^ len = 5, i.e. "CPID\\0"
    """
    nb = name.encode("utf-8") + b"\0"
    if isinstance(value, str):
        value = value.encode("utf-8") + b"\0"
    body = pad4(nb) + struct.pack("<HH", len(value), vtype) + pad4(value)
    return struct.pack("<II", 8 + len(body), len(nb)) + body

def nvlist(items):
    """items = [(name, value, type)] -> u32 result, u16 count, u16 pad, records"""
    recs = b"".join(nv(n, v, t) for n, v, t in items)
    return struct.pack("<IHH", 0, len(items), 0) + recs

def parse_nv_names(body):
    """Pull the requested keys out of a HW_INFO / SW_INFO / GET_SETTINGS _CMD body.

    Observed on the wire (HW_INFO_CMD asking for CPID, SW_INFO_CMD for SdkVersion):
        u32 count
        count x { u32 name_length_including_NUL ; name bytes ; pad to 4 }
    There is no per-record total-length word on the CMD side (unlike the RES side).
    """
    names, off = [], 4
    try:
        count = struct.unpack_from("<I", body, 0)[0]
    except struct.error:
        return names
    for _ in range(min(count, 64)):
        if off + 4 > len(body):
            break
        nlen = struct.unpack_from("<I", body, off)[0]
        off += 4
        if nlen == 0 or off + nlen > len(body):
            break
        names.append(body[off:off + nlen].rstrip(b"\0").decode("utf-8", "replace"))
        off += (nlen + 3) & ~3
    return names

# ------------------------------------------------------- protocol descriptors
def pentry(num, w1, w2, h3, h4=0):
    return struct.pack("<IIIHH", num, w1, w2, h3, h4)

CPID16 = {
    "F": TARGET_ENTRY,                                    # same bytes as target list
    "G": bytes(range(0x10)),                              # 00..0f
    "H": b"\x00" * 8 + struct.pack("<II", HWID, 0),
}

# entry+0x0c (u16) is stored by FUN_14008db60 in a map keyed by protocol number;
# variant "N" gives each protocol a DISTINCT value to test whether the host then
# addresses that protocol's frames with that value in the 16-bit `node` field.
PROTO_NODE = {
    "N": {0x1000: 0x0011, 0x2000: 0x0022},
    "M": {0x1000: 0x0011, 0x2000: 0x0022, 0x3000: 0x0033},
    "Z": {0x1000: 0x0011, 0x2000: 0x0022, 0x3000: 0x0033, 0x11000: 0x0044,
          0x20000: 0x0055, 0x24000: 0x0066, 0x2c000: 0x0077},
}

# CPUP code-1 body, read field-by-field by FUN_1400cf510 as 6 u32 at body+0,4,8,
# 0xc, 0x10, 0x14 (the last two only when 0x18 bytes are present).
# Variant "C1" puts a distinct marker in each so the psp2ctrl columns can be mapped.
CPUP_RES1 = {
    "C1": struct.pack("<6I", 0, 0x0A0B0C0D, 0x01020304, 0x11223344,
                      0x55667788, 0x99AABBCC),
    "C2": struct.pack("<6I", 0x000A0007, 0x05060708, 0x01020304, 0x000B0009,
                      0x000C000D, 0x000E000F),
}.get(VARIANT, bytes(0x18))

def variant_cfg():
    nodes = PROTO_NODE.get(VARIANT, {0x1000: 1, 0x2000: 1})
    ents = [pentry(p, MAXPAY, 0, n) for p, n in sorted(nodes.items())]
    cpid = CPID16.get(VARIANT, TARGET_ENTRY)
    return ents, cpid

def netmp_reply(code):
    ents, _ = variant_cfg()
    return {
        0: (1, struct.pack("<I", 0)),
        2: (3, struct.pack("<I", 0)),
        4: (5, struct.pack("<II", 0, 0)),
        6: (7, struct.pack("<II", 0, 0)),
        8: (9, struct.pack("<II", 0, 0)),
        10: (11, struct.pack("<II", 0, len(ents)) + b"".join(ents)),
        12: (13, struct.pack("<I", 0)),
        14: (15, struct.pack("<I", 0)),
    }.get(code, (None, None))

# Keys are echoed back verbatim; these are the values by requested key name.
HW_VALUES = {}                                     # CPID handled specially
SW_VALUES = {
    "SdkVersion": ("3.570.011", 2),
    "FirmwareVersion": ("3.570.011", 2),
    "SystemSoftwareVersion": ("3.570.011", 2),
}
SETTING_VALUES = {
    "registry:/DEVENV/HOST/devkitname": ("MockVita", 2),
}

def tsmp_reply(t, c, body):
    """Return the response body for CMD (t,c)."""
    _, cpid = variant_cfg()
    if (t, c) == (1, 0):                                  # TARGET_LIST
        return struct.pack("<IHH", 0, 1, 0) + TARGET_ENTRY
    if (t, c) == (1, 2):
        return struct.pack("<I", 0)
    if (t, c) in ((2, 0), (2, 2)):
        return struct.pack("<I", 0)
    if (t, c) == (3, 0):                                  # HW_INFO
        names = parse_nv_names(body) or ["CPID"]
        items = [(n, cpid, 1) if n == "CPID"
                 else (n,) + HW_VALUES.get(n, (bytes(0x10), 1)) for n in names]
        return nvlist(items)
    if (t, c) == (3, 2):
        return struct.pack("<II", 0, 0)
    if (t, c) == (3, 4):                                  # SW_INFO
        names = parse_nv_names(body) or ["SdkVersion"]
        return nvlist([(n,) + SW_VALUES.get(n, ("3.570.011", 2)) for n in names])
    if (t, c) == (3, 6):
        return struct.pack("<II", 0, 0xFFFFFFFF)
    if (t, c) == (3, 8):                                  # USB_INFO, 0x30 + blob
        head = bytearray(0x30)
        struct.pack_into("<I", head, 0, 0)                 # result
        struct.pack_into("<I", head, 4, 0x30 - 4)          # self-relative offset
        return bytes(head) + struct.pack("<I", 8) + bytes(4)
    if (t, c) == (4, 0):
        return struct.pack("<II", 0, 1)
    if (t, c) in ((4, 2), (4, 4)):
        return struct.pack("<I", 0)
    if (t, c) in ((5, 0), (5, 2)):                        # GET_SETTINGS
        names = parse_nv_names(body)
        return nvlist([(n,) + SETTING_VALUES.get(n, ("", 2)) for n in names])
    if (t, c) == (5, 4):
        return struct.pack("<II", 0, 0)
    if (t, c) == (5, 8):                                  # SETTINGS XML
        x = b"<?xml version=\"1.0\"?><settings/>\0"
        return struct.pack("<II", 0, len(x)) + pad4(x)
    return struct.pack("<I", 0)

# ------------------------------------------------------------ UDP discovery
def udp_server(stop_at):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        pass
    s.bind(("0.0.0.0", 8540))
    s.settimeout(1.0)
    log("UDP responder on 0.0.0.0:8540")
    while time.time() < stop_at:
        try:
            data, addr = s.recvfrom(65535)
        except (socket.timeout, OSError):
            continue
        if len(data) < 28 or data[3] != MARKER:
            continue
        flags, node, proto, _r = struct.unpack_from("<HHII", data, 4)
        t, c, _p, arg, seq = struct.unpack_from("<BBHII", data, 16)
        if (t, c) != (1, 2):
            continue
        s.sendto(tsmp(1, 3, arg, seq, data[28:32], node=node, proto=proto,
                      flags=flags), addr)

# ------------------------------------------------------------- TCP session
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
    conn.settimeout(120.0)
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
            if h[3] != MARKER or not (16 <= ln <= 0x11000):
                log("[%d] bad header %s" % (idx, h.hex()))
                return
            r = rx(conn, ln - 16) if ln > 16 else b""
            if r is None:
                return
            m = h + r
            flags, node, proto, _resv = struct.unpack_from("<HHII", m, 4)
            pay = m[16:]

            if proto == PROTO_NETMP:
                code = pay[0] if pay else -1
                log("[%d] <- NETMP %-22s code=%d node=0x%04x len=%d\n%s"
                    % (idx, NETMP_NAMES.get(code, "?"), code, node, ln, hexdump(m)))
                rc, body = netmp_reply(code)
                if rc is None:
                    continue
                pkt = netmp(rc, body, node=node, proto=proto, flags=flags)
                conn.sendall(pkt)
                log("[%d] -> NETMP %-22s code=%d len=%d\n%s"
                    % (idx, NETMP_NAMES.get(rc, "?"), rc, len(pkt), hexdump(pkt)))
                continue

            if proto == PROTO_CPUP:
                # CPUP payload is 12 bytes like TSMP but with a single code byte
                # (FUN_1400ce400 takes one code; RES codes are 1,3,5,7,9,0xb,0xd).
                # CPUP code 1 body = 6 u32 (0x18) or 4 u32 (0x10): FUN_1400cf510.
                code, _p0, _p1, arg, seq = struct.unpack_from("<BBHII", pay, 0)
                log("[%d] <- CPUP code=%d node=0x%04x arg=0x%x\n%s"
                    % (idx, code, node, arg, hexdump(m)))
                if code % 2:
                    continue
                cb = {1: CPUP_RES1, 3: bytes(8), 5: bytes(4), 7: bytes(4),
                      9: bytes(4), 0xb: bytes(0x10), 0xd: bytes(4)}.get(code + 1, bytes(4))
                conn.sendall(mkframe(struct.pack("<BBHII", code + 1, 0, 0, arg, seq) + cb,
                                     node=node, proto=proto, flags=flags))
                log("[%d] -> CPUP code=%d (%d body bytes)" % (idx, code + 1, len(cb)))
                continue
            if proto != PROTO_TSMP:
                log("[%d] <- UNKNOWN proto=0x%04x node=0x%04x len=%d\n%s"
                    % (idx, proto, node, ln, hexdump(m)))
                continue
            if len(pay) < 12:
                log("[%d] <- proto=0x%x SHORT payload %s" % (idx, proto, pay.hex()))
                continue
            t, c, _p, arg, seq = struct.unpack_from("<BBHII", pay, 0)
            body = pay[12:]
            log("[%d] <- proto=0x%04x %-26s t%d.c%d node=0x%04x arg=0x%x%s"
                % (idx, proto, NAMES.get((t, c), "?"), t, c, node, arg,
                   ("\n" + hexdump(body)) if body else ""))
            if c % 2 == 1 or t == 6:
                continue
            rb = tsmp_reply(t, c, body)
            conn.sendall(tsmp(t, c + 1, arg, seq, rb, node=node, proto=proto))
            log("[%d] -> %-26s t%d.c%d\n%s"
                % (idx, NAMES.get((t, c + 1), "?"), t, c + 1, hexdump(rb)))
    except socket.timeout:
        log("[%d] idle timeout" % idx)
    except Exception as e:
        log("[%d] ERR %r" % (idx, e))
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
log("mock16 variant=%s on 0.0.0.0:8540 for %ds hwid=%d" % (VARIANT, DURATION, HWID))
i = 0
while time.time() < stop_at:
    try:
        c, a = srv.accept()
    except socket.timeout:
        continue
    i += 1
    threading.Thread(target=handle, args=(c, a, i), daemon=True).start()
log("done, %d TCP connections" % i)
