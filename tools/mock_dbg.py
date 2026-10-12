"""PC mock target that advertises DBGP (0x20000) and logs/answers the process
list, so the DBGP GET_PROCESS_INFO wire format can be solved against the real
TMAPI decoder without touching the Vita. Based on the repo's mock16.

Run: python mock_dbg.py <seconds>
Then drive it from TMAPI (dbg_probe.ps1 calls target.ProcessInfoSnapshot).

The process-list RES body is built by build_procinfo_res() and is the ONE
thing we iterate. Everything it logs (the CMD bytes psp2tm sends, and whether
TMAPI accepts the RES) tells us the layout.
"""
import socket, struct, sys, threading, time

import os
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 300
HWID = int(os.environ.get("MOCKHWID", "1444603"))   # not the real Vita's 1444602
MAGIC, MARKER, MAXPAY = 0x15A3F8E1, 0x40, 0x10800
NETMP, TSMP, CPUP, DBGP = 0x1000, 0x2000, 0x3000, 0x20000
TTYP = 0x80030000

# PROTO_LIST descriptors: proto, version, limit, node
PROTOS = [(NETMP,0x11),(TSMP,0x22),(CPUP,0x33),(TTYP|0x00,0xa000),(TTYP|0x90,0xa090),(DBGP,0x44)]

LOCK=threading.Lock()
def log(m):
    with LOCK: print("%s %s"%(time.strftime("%H:%M:%S"),m),flush=True)
def hexd(d,p="    "):
    return "\n".join("%s%04x  %-47s |%s|"%(p,o," ".join("%02x"%b for b in d[o:o+16]),
        "".join(chr(b) if 32<=b<127 else "." for b in d[o:o+16])) for o in range(0,len(d),16))

def frame(payload,node,proto,flags=0):
    return struct.pack("<I",16+len(payload))[:3]+bytes([MARKER])+struct.pack("<HHII",flags,node,proto,0)+payload
def pad4(b): return b+bytes((-len(b))%4)
def nv(name,value,vtype):
    nb=name.encode()+b"\0"
    body=pad4(nb)+struct.pack("<HH",len(value),vtype)+pad4(value)
    return struct.pack("<II",8+len(body),len(nb))+body
def keys(body):
    out,off=[],4
    cnt=struct.unpack_from("<I",body,0)[0] if len(body)>=4 else 0
    for _ in range(min(cnt,64)):
        if off+4>len(body): break
        n=struct.unpack_from("<I",body,off)[0]; off+=4
        if n==0 or off+n>len(body): break
        out.append(body[off:off+n].rstrip(b"\0").decode()); off+=(n+3)&~3
    return out

def tsmp_body(t,c,body):
    cpid=struct.pack("<IIII",HWID,1,0,0)
    if (t,c)==(1,0): return struct.pack("<IHHI",0,1,0,HWID)
    if (t,c)==(3,0):
        ks=keys(body) or ["CPID"]; return struct.pack("<IHH",0,len(ks),0)+b"".join(nv(k,cpid,1) for k in ks)
    if (t,c)==(3,4):
        ks=keys(body) or ["SdkVersion"]; return struct.pack("<IHH",0,len(ks),0)+b"".join(nv(k,struct.pack("<I",0x03650000),0) for k in ks)
    if (t,c)==(3,2): return struct.pack("<II",0,0)
    if (t,c)==(3,6): return struct.pack("<II",0,0xFFFFFFFF)
    if (t,c)==(3,8):
        head=bytearray(0x30); struct.pack_into("<I",head,4,0x2c); return bytes(head)+struct.pack("<II",8,0)
    if (t,c)==(4,0): return struct.pack("<II",0,1)
    if t==5 and c in (0,2):
        ks=keys(body); return struct.pack("<IHH",0,len(ks),0)+b"".join(nv(k,b"MockVita\0",2) for k in ks)
    if (t,c)==(5,8):
        x=b"<?xml version=\"1.0\"?><settings/>\0"; return struct.pack("<II",0,len(x))+pad4(x)
    return struct.pack("<I",0)

# ---- DBGP: this is what we iterate ----
# DBGP payload 12-byte header (mirrors TSMP): type,code,pad2,arg,seq then body.
# From FUN_1400d1c80 the host reads payload[1]=group, payload[2]=code for the
# name; so byte0=type? Log the whole thing to be sure.
FMT = os.environ.get("PROCFMT","A")
PROCS=[(0x00010005,"SceShell","vs0:vsh/shell/eboot.bin"),
       (0x00011861,"NPXS10015","ur0:appmeta/NPXS10015/eboot.bin")]

def _hdr(b0,group,code):
    # RES header: echo type/group, code+1. FUN_1400d1c80 reads 0xc bytes after
    # the frame header, so the RES needs >=12 header bytes before/incl body.
    return struct.pack("<BBBB",b0,group,code+1,0)

def build_dbgp_res(b0,group,code,cmd):
    """Build a GET_PROCESS_INFO RES to iterate against TMAPI's decoder.
    PROCESS group 0x20, GET_PROCESS_INFO code 0x00 -> RES code 0x01."""
    if group!=0x20 or code!=0x00:
        # answer other DBGP with a bare success so the tool proceeds
        return _hdr(b0,group,code)+struct.pack("<II",0,0)
    # 12-byte DBGP header: [type,group,code,pad] + reserved u32 + result u32.
    # psp2tm reads the result at payload offset 8 (proven: count there read as
    # error 2). Body (count + procs) follows at offset 12.
    h=_hdr(b0,group,code)+struct.pack("<II",0,0)   # reserved=0, result=0
    n=len(PROCS)
    def slp(s):    # u32 len + bytes pad4
        b=s.encode()+b"\0"; return struct.pack("<I",len(b))+pad4(b)
    def svar(s):   # u16 len, u16 pad, bytes pad4
        b=s.encode()+b"\0"; return struct.pack("<HH",len(b),0)+pad4(b)
    if FMT=="EMPTY":
        return h+struct.pack("<I",0)
    if FMT=="D":   # count; per proc: id + name(lp)+path(lp) + 10 u32
        out=h+struct.pack("<I",n)
        for pid,name,path in PROCS:
            out+=struct.pack("<I",pid)+slp(name)+slp(path)+struct.pack("<10I",0,0,0,0,0,0,0,0,0,0)
        return out
    if FMT=="E":   # count; per proc: id + 10 u32 + name(lp)+path(lp)
        out=h+struct.pack("<I",n)
        for pid,name,path in PROCS:
            out+=struct.pack("<11I",pid,0,0,0,0,0,0,0,0,0,0)+slp(name)+slp(path)
        return out
    if FMT=="F":   # count; per proc: id + name(var)+path(var) + 10 u32
        out=h+struct.pack("<I",n)
        for pid,name,path in PROCS:
            out+=struct.pack("<I",pid)+svar(name)+svar(path)+struct.pack("<10I",0,0,0,0,0,0,0,0,0,0)
        return out
    if FMT=="G":   # RE'd real layout (PROCINFO_FORMAT.md)
        out=h+struct.pack("<I",n)
        for pid,name,path in PROCS:
            out+=proc_entry(pid,name,path)
        return out
    return h+struct.pack("<I",0)

def proc_entry(pid,name,path,guid=0,ppid=0,attrs=0,affinity=0,entry=0):
    namef=(name.encode()[:35]+b"\0").ljust(36,b"\0")[:36]
    pb=path.encode()+b"\0"; pathlen=len(pb); pathf=pad4(pb)
    tail=struct.pack("<4I",0,0,0,0)   # exidx start/end, extab start/end
    body =struct.pack("<II",pid,attrs)+namef
    body+=struct.pack("<IIII",affinity,entry,guid,ppid)
    body+=struct.pack("<IIIII",0x14,0,0,0,0)          # StopReason.size + 4 words
    body+=struct.pack("<I",pathlen)+pathf+tail
    return struct.pack("<I",4+len(body))+body

def rx(c,n):
    b=b""
    while len(b)<n:
        d=c.recv(n-len(b))
        if not d: return None
        b+=d
    return b

SEQ=[0]
def ttyp(stream,source,pid,tid,tick,text):
    b=text.encode()
    hdr=struct.pack("<HBBIIIQI",source,0,0,pid,tid,SEQ[0],tick,len(b)); SEQ[0]+=1
    return frame(hdr+b,0xa000|stream,TTYP|stream)

def pusher(conn,idx,live,dead):
    n=0
    while not dead.is_set():
        time.sleep(2.0)
        if not live.is_set(): continue
        n+=1; t=int(time.monotonic()*1e6)
        try:
            conn.sendall(ttyp(0x90,0x8000,0x10005,0x10213,t,"[kernel] heartbeat %d net up\n"%n))
            conn.sendall(ttyp(0x00,0x1000,0x11861,0x11a39,t+1,"[Shell] LogGame: tick %d\n"%n))
        except OSError:
            return

def handle(conn,addr,idx):
    log("[%d] connect %s:%d"%(idx,addr[0],addr[1]))
    live,dead=threading.Event(),threading.Event()
    try:
        if rx(conn,4)!=b"DECI": return
        conn.sendall(struct.pack(">II",MAGIC,0x40)+bytes(56))
        threading.Thread(target=pusher,args=(conn,idx,live,dead),daemon=True).start()
        while True:
            h=rx(conn,16)
            if h is None: log("[%d] closed"%idx); return
            ln=int.from_bytes(h[0:3],"little")
            if h[3]!=MARKER or not 16<=ln<=MAXPAY: log("[%d] bad hdr"%idx); return
            pay=rx(conn,ln-16) if ln>16 else b""
            flags,node,proto=struct.unpack_from("<HHI",h,4)
            if proto==NETMP:
                code=pay[0] if pay else 0xff
                res={0:struct.pack("<I",0),2:struct.pack("<I",0),4:bytes(8),6:bytes(8),8:bytes(8),
                     12:bytes(4),14:bytes(4),
                     10:struct.pack("<II",0,len(PROTOS))+b"".join(struct.pack("<IIIHH",p,MAXPAY,0,nd,0) for p,nd in PROTOS)}.get(code)
                if res is None: continue
                conn.sendall(frame(struct.pack("<BBH",code+1,0,0)+res,node,proto,flags))
                if code==10: live.set()
                continue
            if proto==CPUP:
                if len(pay)<12 or pay[0]&1: continue
                code,arg,seq=pay[0],*struct.unpack_from("<II",pay,4)
                bl={1:0x18,3:8,0xb:0x10}.get(code+1,4)
                conn.sendall(frame(struct.pack("<BBHII",code+1,0,0,arg,seq)+bytes(bl),node,proto,flags)); continue
            if proto==TSMP and len(pay)>=12:
                t,c,_p,arg,seq=struct.unpack_from("<BBHII",pay,0)
                if c&1 or t==6: continue
                conn.sendall(frame(struct.pack("<BBHII",t,c+1,0,arg,seq)+tsmp_body(t,c,pay[12:]),node,proto,flags)); continue
            if proto==DBGP:
                log("[%d] *** DBGP CMD len=%d node=0x%04x pay=%s"%(idx,ln,node,pay.hex()))
                if len(pay)<3: continue
                b0,group,code=pay[0],pay[1],pay[2]
                log("[%d]     type=0x%02x group=0x%02x code=0x%02x"%(idx,b0,group,code))
                res_pay=build_dbgp_res(b0,group,code,pay)
                if res_pay is None:
                    log("[%d]     (no RES built)"%idx); continue
                conn.sendall(frame(res_pay,node,proto,flags))
                log("[%d]     -> DBGP RES fmt=%s len=%d\n%s"%(idx,FMT,len(res_pay),hexd(res_pay)))
                continue
            log("[%d] proto 0x%x len %d ignored"%(idx,proto,ln))
    except Exception as e:
        log("[%d] ERR %r"%(idx,e))
    finally:
        dead.set(); conn.close()

def udp(stop):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",8540)); s.settimeout(1)
    while time.time()<stop:
        try: d,a=s.recvfrom(65535)
        except OSError: continue
        if len(d)>=32 and d[3]==MARKER and d[16:18]==b"\x01\x02":
            flags,node,proto=struct.unpack_from("<HHI",d,4)
            s.sendto(frame(d[16:17]+b"\x03"+d[18:28]+d[28:32],node,proto,flags),a)

stop=time.time()+DURATION
threading.Thread(target=udp,args=(stop,),daemon=True).start()
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(("127.0.0.1",8540)); srv.listen(8); srv.settimeout(1)
log("mock_dbg on 127.0.0.1:8540 PROCFMT=%s for %ds"%(FMT,DURATION))
i=0
while time.time()<stop:
    try: c,a=srv.accept()
    except socket.timeout: continue
    i+=1; threading.Thread(target=handle,args=(c,a,i),daemon=True).start()
log("done")
