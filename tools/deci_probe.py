"""Passive capture of what Target Manager (psp2tm.exe) sends to a target on TCP 8540.

Listens on 127.0.0.1:8540, accepts connections, logs every byte received as hex +
ASCII, and never replies. Purely local; no traffic leaves the machine.
"""
import socket, sys, time, threading, binascii

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8540
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 60

def hexdump(data, prefix=""):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{prefix}{off:04x}  {hexpart:<47}  |{asciipart}|")
    return "\n".join(out)

def handle(conn, addr, idx):
    log(f"[conn {idx}] accepted from {addr[0]}:{addr[1]}")
    conn.settimeout(10.0)
    total = b""
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                log(f"[conn {idx}] peer closed after {len(total)} bytes")
                break
            total += data
            log(f"[conn {idx}] recv {len(data)} bytes:")
            log(hexdump(data, prefix=f"[conn {idx}] "))
    except socket.timeout:
        log(f"[conn {idx}] idle 10s, total {len(total)} bytes (server may be waiting for OUR greeting)")
    except OSError as e:
        log(f"[conn {idx}] error {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass

LOCK = threading.Lock()
def log(msg):
    with LOCK:
        print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(8)
    srv.settimeout(1.0)
    log(f"listening on 0.0.0.0:{PORT} for {DURATION}s")
    deadline = time.time() + DURATION
    idx = 0
    while time.time() < deadline:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        idx += 1
        threading.Thread(target=handle, args=(conn, addr, idx), daemon=True).start()
    log(f"done; {idx} connection(s) seen")

main()
