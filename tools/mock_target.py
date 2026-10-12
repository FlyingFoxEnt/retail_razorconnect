"""Mock PS Vita DECI4P target for Sony's Target Manager.

Derived from psp2tm.exe FUN_1400e01b0 (Ghidra):
    send "DECI" (4 bytes)
    recv u32be magic   -> must equal 0x15A3F8E1
    recv u32be length  -> must equal 0x40 (64 total)
    recv 56 bytes      -> 14 big-endian u32 fields
    -> spawns the socket thread (connection accepted)

Listens on TCP 8540, answers the greeting, then logs everything the server sends
next so the post-handshake protocol can be mapped.

Usage: mock_target.py [seconds] [field-preset]
"""
import socket, struct, sys, threading, time

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 60
PRESET = sys.argv[2] if len(sys.argv) > 2 else "zeros"

MAGIC = 0x15A3F8E1
HELLO_LEN = 0x40
NFIELDS = 14  # 56 bytes / 4

PRESETS = {
    # All-zero payload: establishes whether the server accepts the frame at all.
    "zeros": [0] * NFIELDS,
    # Plausible "version 1 / node 1" shape, to see if any field is validated.
    "ones": [1] * NFIELDS,
    "v1": [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    "ascending": list(range(NFIELDS)),
}

LOCK = threading.Lock()
def log(m):
    with LOCK:
        print("%s %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def hexdump(data, prefix=""):
    out = []
    for off in range(0, len(data), 16):
        c = data[off:off + 16]
        h = " ".join("%02x" % b for b in c)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        out.append("%s%04x  %-47s |%s|" % (prefix, off, h, a))
    return "\n".join(out)

def build_hello(fields):
    body = b"".join(struct.pack(">I", f & 0xFFFFFFFF) for f in fields)
    assert len(body) == 56, len(body)
    return struct.pack(">II", MAGIC, HELLO_LEN) + body

def handle(conn, addr, idx, fields):
    log("[%d] connect from %s:%d" % (idx, addr[0], addr[1]))
    conn.settimeout(15.0)
    try:
        greeting = conn.recv(4096)
        log("[%d] <- greeting %d bytes: %r" % (idx, len(greeting), greeting))
        if greeting[:4] != b"DECI":
            log("[%d] unexpected greeting, bailing" % idx)
            return
        hello = build_hello(fields)
        conn.sendall(hello)
        log("[%d] -> sent 64-byte hello (magic 0x%08X, len 0x%X, preset=%s)\n%s"
            % (idx, MAGIC, HELLO_LEN, PRESET, hexdump(hello, "[%d] " % idx)))

        total = b""
        t0 = time.perf_counter()
        while True:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                log("[%d] no further data for 15s; connection STILL OPEN after %.1fs -- handshake likely ACCEPTED"
                    % (idx, time.perf_counter() - t0))
                continue
            if not data:
                log("[%d] server closed after %.3fs, %d bytes received post-hello"
                    % (idx, time.perf_counter() - t0, len(total)))
                break
            total += data
            log("[%d] <- %d bytes after %.3fs:\n%s"
                % (idx, len(data), time.perf_counter() - t0, hexdump(data, "[%d] " % idx)))
    except OSError as e:
        log("[%d] socket error: %s" % (idx, e))
    finally:
        try:
            conn.close()
        except OSError:
            pass

def main():
    fields = PRESETS.get(PRESET, PRESETS["zeros"])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 8540))
    srv.listen(8)
    srv.settimeout(1.0)
    log("mock target listening on 0.0.0.0:8540 for %ds, preset=%s" % (DURATION, PRESET))
    deadline = time.time() + DURATION
    idx = 0
    while time.time() < deadline:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        idx += 1
        threading.Thread(target=handle, args=(conn, addr, idx, fields), daemon=True).start()
    time.sleep(0.5)
    log("done; %d connection(s)" % idx)

main()
