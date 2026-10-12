"""Capture the UDP discovery datagrams Target Manager sends during a subnet scan.

Binds a set of candidate UDP ports (8540 first, since TCP discovery uses it) and
logs every datagram with its source, so we can see UDP_FIND_TARGET_CMD on the wire.

Usage: udp_probe.py <seconds> [port ...]
"""
import socket, sys, threading, time, select

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 60
PORTS = [int(p) for p in sys.argv[2:]] or [8540, 8541, 8539, 9540, 1900]

LOCK = threading.Lock()
def log(m):
    with LOCK:
        print("%s %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def hexdump(d, p=""):
    return "\n".join("%s%04x  %-47s |%s|" % (p, o, " ".join("%02x" % b for b in d[o:o+16]),
                     "".join(chr(b) if 32 <= b < 127 else "." for b in d[o:o+16]))
                     for o in range(0, len(d), 16))

socks = []
for port in PORTS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        s.bind(("0.0.0.0", port))
        s.setblocking(False)
        socks.append((port, s))
        log("bound UDP %d" % port)
    except OSError as e:
        log("could not bind UDP %d: %s" % (port, e))

if not socks:
    log("no ports bound, exiting")
    raise SystemExit(1)

log("listening %ds" % DURATION)
deadline = time.time() + DURATION
count = 0
while time.time() < deadline:
    r, _, _ = select.select([s for _, s in socks], [], [], 0.5)
    for s in r:
        port = next(p for p, sk in socks if sk is s)
        try:
            data, addr = s.recvfrom(65535)
        except OSError:
            continue
        count += 1
        log("UDP :%d <- %s:%d  %d bytes\n%s" % (port, addr[0], addr[1], len(data),
                                                hexdump(data, "   ")))
log("done; %d datagram(s)" % count)
