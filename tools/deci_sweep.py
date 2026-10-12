"""Sweep candidate replies to the Target Manager 'DECI' greeting.

For each candidate: listen on 8540, run `psp2ctrl find 127.0.0.1`, answer the
greeting with the candidate bytes, and record both what the server did
(closed immediately / sent more data) and what psp2ctrl printed. A change in
the error text is the oracle that a reply was better accepted.

Local only: psp2ctrl is pointed at 127.0.0.1.
"""
import socket, subprocess, threading, time, sys

PSP2CTRL = r"C:\Program Files (x86)\SCE\PSP2\Tools\Target Manager Server\bin\psp2ctrl.exe"

CANDIDATES = [
    ("echo DECI",        b"DECI"),
    ("ICED",             b"ICED"),
    ("PSP2",             b"PSP2"),
    ("VITA",             b"VITA"),
    ("zeros4",           b"\x00\x00\x00\x00"),
    ("one_le",           b"\x01\x00\x00\x00"),
    ("one_be",           b"\x00\x00\x00\x01"),
    ("DECI+zeros4",      b"DECI\x00\x00\x00\x00"),
    ("DECI+one_le",      b"DECI\x01\x00\x00\x00"),
    ("DECI4",            b"DECI4"),
    ("DECI4P",           b"DECI4P"),
    ("NETM",             b"NETM"),
    ("zeros16",          b"\x00" * 16),
    ("DECI+16zeros",     b"DECI" + b"\x00" * 16),
    ("len16_hdr",        b"\x10\x00\x00\x00" + b"\x00" * 12),
]

class Listener:
    def __init__(self, reply):
        self.reply = reply
        self.events = []
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("0.0.0.0", 8540))
        self.srv.listen(8)
        self.srv.settimeout(0.5)
        self.stop = False
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        conn.settimeout(3.0)
        try:
            greeting = conn.recv(4096)
            if not greeting:
                return
            conn.sendall(self.reply)
            t0 = time.time()
            try:
                more = conn.recv(65536)
            except socket.timeout:
                self.events.append(f"greet={greeting!r} -> server SILENT (held open 3s)")
                return
            dt = time.time() - t0
            if not more:
                self.events.append(f"greet={greeting!r} -> server CLOSED after {dt:.2f}s")
            else:
                self.events.append(f"greet={greeting!r} -> server SENT {len(more)} bytes: {more.hex()}")
        except OSError as e:
            self.events.append(f"error {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass
        time.sleep(0.2)

for name, reply in CANDIDATES:
    lis = Listener(reply)
    time.sleep(0.4)
    try:
        proc = subprocess.run([PSP2CTRL, "find", "127.0.0.1"], capture_output=True,
                              text=True, timeout=25)
        out = (proc.stdout + proc.stderr).strip().replace("\n", " | ")
    except subprocess.TimeoutExpired:
        out = "<psp2ctrl TIMED OUT>"
    time.sleep(0.5)
    lis.close()
    evs = "; ".join(lis.events[:3]) or "<no connection>"
    print(f"[{name:14}] reply={reply.hex():<40} ctrl={out[:110]}")
    print(f"                 server: {evs}")
    sys.stdout.flush()
