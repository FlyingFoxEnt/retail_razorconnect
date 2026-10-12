"""Mock PS Vita DevKit for Sony Target Manager / Neighborhood - stage 6.

Everything below was recovered from psp2tm.exe with Ghidra plus live probing.

  Handshake (FUN_1400e01b0)
      <- "DECI"
      -> u32be 0x15A3F8E1 | u32be 0x40 | 56 bytes

  Frame (FUN_1400db470 writer / FUN_1400e0770 reader)
      u24 len (LE) | u8 0x40 | u16 flags | u16 node | u32 proto(0x2000=TSMP) | u32 resv
      u8 type | u8 code | u16 pad | u32 arg | u32 seq | body

  TSMP types/codes (FUN_14008d1b0), even = CMD, odd = RES
      1 LIST 0/1 TARGET_LIST, 2/3 UDP_FIND_TARGET
      2 SELECT 0/1 SELECT, 2/3 DESELECT
      3 INFO 0/1 HW_INFO, 2/3 STICKY_NOTE, 4/5 SW_INFO, 6/7 EXPIRY, 8/9 USB_INFO
      4 CONTROL 0/1 POWER_STATUS, 2/3 POWER_CONTROL, 4/5 UPDATE_ACTIVATION
      5 SETTINGS, 6 NOTIFICATIONS

  Body sizes from the decoder table (FUN_1400cf160 callers):
      (0,0)=4  (1,3)=4  (2,1)=4  (2,3)=4  (3,1)=8+blob  (3,5)=8+blob
      (3,7)=8  (3,9)=0x30  (4,1)=8  (4,3)=4  (4,5)=4  (5,1)=8+blob (7,1)=0xc

  TARGET_LIST_RES body (found empirically): u32 status | u32 count | entry[count]
      entry = 16 bytes. With count=1 the host proceeds to TARGET_SELECT.

Usage: mock6.py <seconds> [entry-style]
"""
import socket, struct, sys, threading, time

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 90
STYLE = sys.argv[2] if len(sys.argv) > 2 else "hwid"

MAGIC = 0x15A3F8E1
MARKER = 0x40
PROTO = 0x2000

HWID = 1444602
TARGET_NAME = "MockVita"
FW = 0x03570011

NAMES = {
    (0,0):"ERROR",(1,0):"TARGET_LIST_CMD",(1,1):"TARGET_LIST_RES",
    (1,2):"UDP_FIND_CMD",(1,3):"UDP_FIND_RES",
    (2,0):"TARGET_SELECT_CMD",(2,1):"TARGET_SELECT_RES",
    (2,2):"TARGET_DESELECT_CMD",(2,3):"TARGET_DESELECT_RES",
    (3,0):"HW_INFO_CMD",(3,1):"HW_INFO_RES",(3,2):"STICKY_NOTE_CMD",(3,3):"STICKY_NOTE_RES",
    (3,4):"SW_INFO_CMD",(3,5):"SW_INFO_RES",(3,6):"EXPIRY_CMD",(3,7):"EXPIRY_RES",
    (3,8):"USB_INFO_CMD",(3,9):"USB_INFO_RES",
    (4,0):"POWER_STATUS_CMD",(4,1):"POWER_STATUS_RES",(4,2):"POWER_CONTROL_CMD",
    (4,3):"POWER_CONTROL_RES",(4,4):"UPDATE_ACTIVATION_CMD",(4,5):"UPDATE_ACTIVATION_RES",
    (5,0):"GET_SETTINGS_CMD",(5,1):"GET_SETTINGS_RES",
}

LOCK = threading.Lock()
def log(m):
    with LOCK:
        print("%s %s" % (time.strftime("%H:%M:%S"), m), flush=True)

def hexdump(d,p=""):
    return "\n".join("%s%04x  %-47s |%s|"%(p,o," ".join("%02x"%b for b in d[o:o+16]),
                     "".join(chr(b) if 32<=b<127 else "." for b in d[o:o+16]))
                     for o in range(0,len(d),16))

def frame(t,c,arg,seq,body=b"",node=0x4000):
    p = struct.pack("<BBHII",t,c,0,arg,seq)+body
    tot = 16+len(p)
    return struct.pack("<I",tot)[:3]+bytes([MARKER])+struct.pack("<HHII",0,node,PROTO,0)+p

def blob(s):
    """8-byte head + length-prefixed payload, matching the (3,1)/(3,5) decoders:
       u32 field | u16 blob_len | u16 pad | bytes"""
    b = s.encode("ascii","replace")+b"\x00"
    return struct.pack("<IHH",0,len(b),0)+b

def entry(style):
    if style == "hwid":
        return struct.pack("<IIII", HWID, 1, 0, 0)
    if style == "hwid_type":
        return struct.pack("<IIII", HWID, 1, 1, 0)
    if style == "seq":
        return struct.pack("<IIII", 1, HWID, 0, 0)
    return b"\x00"*16

BODY = {
    (1,1): lambda: struct.pack("<II",0,1)+entry(STYLE),   # status, count, entries
    (1,3): lambda: struct.pack("<I",0),
    (2,1): lambda: struct.pack("<I",0),
    (2,3): lambda: struct.pack("<I",0),
    (3,1): lambda: blob("PSP2 DevKit"),                   # HW_INFO
    (3,3): lambda: struct.pack("<II",0,0),
    (3,5): lambda: blob("3.570.011"),                     # SW_INFO
    (3,7): lambda: struct.pack("<II",0xFFFFFFFF,0),       # expiry
    (3,9): lambda: b"\x00"*0x30,                          # usb info
    (4,1): lambda: struct.pack("<II",1,0),                # power status = on
    (4,3): lambda: struct.pack("<I",0),
    (4,5): lambda: struct.pack("<I",0),
    (5,1): lambda: blob(""),
    (7,1): lambda: b"\x00"*0xc,
}

def rx(c,n):
    b=b""
    while len(b)<n:
        d=c.recv(n-len(b))
        if not d: return None
        b+=d
    return b

def handle(conn,addr,idx):
    log("[%d] connect (entry style=%s)"%(idx,STYLE))
    conn.settimeout(25.0)
    try:
        if rx(conn,4)!=b"DECI": return
        conn.sendall(struct.pack(">II",MAGIC,0x40)+b"\x00"*56)
        while True:
            h=rx(conn,16)
            if h is None:
                log("[%d] server closed"%idx); return
            ln=int.from_bytes(h[0:3],"little")
            if h[3]!=MARKER or not(16<=ln<=0x11000):
                log("[%d] bad header"%idx); return
            r=rx(conn,ln-16) if ln>16 else b""
            if r is None: return
            m=h+r
            t,c,_p,arg,seq=struct.unpack_from("<BBHII",m,16)
            body=m[28:]
            txt=bytes(b for b in body if 32<=b<127)
            log("[%d] <- %-22s t%d.c%d arg=0x%x seq=%d%s"
                %(idx,NAMES.get((t,c),"?"),t,c,arg,seq,("  %r"%txt) if len(txt)>3 else ""))
            if c%2==1:
                continue
            if t == 0:
                # Host identity frame: {u8 t,u8 c,u16 pad,u32 strlen,char str[]}
                ident = b"MockVita@PSP2,NetworkManager" + bytes([0])
                p = struct.pack("<BBHI", 0, 1, 0, len(ident)) + ident
                tot = 16 + len(p)
                node = struct.unpack_from("<H", m, 6)[0]
                pkt = struct.pack("<I", tot)[:3] + bytes([MARKER]) + struct.pack("<HHII",0,node,PROTO,0) + p
                conn.sendall(pkt)
                log("[%d] -> IDENTITY reply (%d bytes) %r" % (idx, len(pkt), ident))
                continue
            rc=c+1
            mk=BODY.get((t,rc))
            rb=mk() if mk else struct.pack("<I",0)
            conn.sendall(frame(t,rc,arg,seq,rb,node=struct.unpack_from("<H",m,6)[0]))
            log("[%d] -> %-22s t%d.c%d (%d body bytes)"
                %(idx,NAMES.get((t,rc),"?"),t,rc,len(rb)))
    except socket.timeout:
        log("[%d] idle"%idx)
    except OSError as e:
        log("[%d] err %s"%(idx,e))
    finally:
        try: conn.close()
        except OSError: pass

s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",8540)); s.listen(8); s.settimeout(1.0)
log("mock6 listening, entry style=%s hwid=%d"%(STYLE,HWID))
dl=time.time()+DURATION; i=0
while time.time()<dl:
    try: c,a=s.accept()
    except socket.timeout: continue
    i+=1; threading.Thread(target=handle,args=(c,a,i),daemon=True).start()
time.sleep(0.5)
log("done %d connections"%i)
