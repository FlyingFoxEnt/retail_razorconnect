"""Mock target - sweep TARGET_LIST_RES body shapes, using psp2ctrl's error as oracle."""
import socket, struct, sys, threading, time
DURATION=int(sys.argv[1]) if len(sys.argv)>1 else 90
MAGIC=0x15A3F8E1; MARKER=0x40; PROTO=0x2000
LOCK=threading.Lock()
def log(m):
    with LOCK: print("%s %s"%(time.strftime("%H:%M:%S"),m),flush=True)
def frame(t,c,arg,seq,body=b"",node=0x4000):
    p=struct.pack("<BBHII",t,c,0,arg,seq)+body
    tot=16+len(p)
    return struct.pack("<I",tot)[:3]+bytes([MARKER])+struct.pack("<HHII",0,node,PROTO,0)+p
def z(n): return b"\x00"*n
BODIES=[
 ("empty",        b""),
 ("u32_0",        struct.pack("<I",0)),
 ("u32_0_cnt0",   struct.pack("<II",0,0)),
 ("status_60",    struct.pack("<I",0)+z(0x60)),
 ("status_cnt_60",struct.pack("<II",0,0)+z(0x60)),
 ("0x30",         z(0x30)),
 ("0x10",         z(0x10)),
 ("cnt1_entry16", struct.pack("<II",0,1)+z(0x10)),
 ("u32_0_x3",     struct.pack("<III",0,0,0)),
 ("0x64",         z(0x64)),
]
CNT=[0]
def rx(c,n):
    b=b""
    while len(b)<n:
        d=c.recv(n-len(b))
        if not d: return None
        b+=d
    return b
def handle(conn,addr,idx):
    with LOCK:
        name,body=BODIES[CNT[0]%len(BODIES)]; CNT[0]+=1
    log("[%d] BODY=%s (%d bytes)"%(idx,name,len(body)))
    conn.settimeout(10.0)
    try:
        if rx(conn,4)!=b"DECI": return
        conn.sendall(struct.pack(">II",MAGIC,0x40)+z(56))
        while True:
            h=rx(conn,16)
            if h is None:
                log("[%d] closed"%idx); return
            ln=int.from_bytes(h[0:3],"little")
            if h[3]!=MARKER or not(16<=ln<=0x11000): return
            r=rx(conn,ln-16) if ln>16 else b""
            if r is None: return
            m=h+r
            t,c,_p,arg,seq=struct.unpack_from("<BBHII",m,16)
            txt=bytes(b for b in m[28:] if 32<=b<127)
            log("[%d] <- t%d.c%d arg=0x%x seq=%d%s"%(idx,t,c,arg,seq,("  %r"%txt) if len(txt)>3 else ""))
            if c%2==1: continue
            conn.sendall(frame(t,c+1,arg,seq,body))
            log("[%d] -> t%d.c%d + %s"%(idx,t,c+1,name))
    except socket.timeout: log("[%d] idle"%idx)
    except OSError as e: log("[%d] err %s"%(idx,e))
    finally:
        try: conn.close()
        except OSError: pass
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",8540)); s.listen(8); s.settimeout(1.0)
log("mock5 bodies=%s"%[b[0] for b in BODIES])
dl=time.time()+DURATION; i=0
while time.time()<dl:
    try: c,a=s.accept()
    except socket.timeout: continue
    i+=1; threading.Thread(target=handle,args=(c,a,i),daemon=True).start()
log("done %d"%i)
