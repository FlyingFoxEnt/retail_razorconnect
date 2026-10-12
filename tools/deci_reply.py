"""Interactive DECI handshake prober.

Listens on TCP 8540 (the port Target Manager probes), replies to the initial
"DECI" greeting with a configurable payload, and logs everything the server
sends afterwards. Local only.

Usage: deci_reply.py <seconds> <reply-hex-or-'echo'-or-'none'>
"""
import socket, sys, time, threading

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 60
REPLY_SPEC = sys.argv[2] if len(sys.argv) > 2 else "echo"

LOCK = threading.Lock()
def log(msg):
    with LOCK:
        print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)

def hexdump(data, prefix=""):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{prefix}{off:04x}  {hexpart:<47}  |{asciipart}|")
    return "\n".join(out)

def make_reply(greeting):
    if REPLY_SPEC == "echo":
        return greeting
    if REPLY_SPEC == "none":
        return b""
    return bytes.fromhex(REPLY_SPEC)

def handle(conn, addr, idx):
    log(f"[{idx}] connect from {addr[0]}:{addr[1]}")
    conn.settimeout(8.0)
    try:
        greeting = conn.recv(4096)
        if not greeting:
            log(f"[{idx}] closed with no data")
            return
        log(f"[{idx}] <- {len(greeting)} bytes\n{hexdump(greeting, f'[{idx}] ')}")
        reply = make_reply(greeting)
        if reply:
            conn.sendall(reply)
            log(f"[{idx}] -> sent {len(reply)} bytes: {reply.hex()}")
        # Keep reading whatever the server says next.
        while True:
            data = conn.recv(65536)
            if not data:
                log(f"[{idx}] server closed connection")
                break
            log(f"[{idx}] <- {len(data)} bytes\n{hexdump(data, f'[{idx}] ')}")
    except socket.timeout:
        log(f"[{idx}] timeout waiting for more data (server silent)")
    except OSError as e:
        log(f"[{idx}] socket error: {e}")
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
    log(f"listening on 0.0.0.0:8540 for {DURATION}s, reply mode = {REPLY_SPEC}")
    deadline = time.time() + DURATION
    idx = 0
    while time.time() < deadline:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        idx += 1
        threading.Thread(target=handle, args=(conn, addr, idx), daemon=True).start()
    time.sleep(1)
    log(f"done; {idx} connection(s)")

main()
