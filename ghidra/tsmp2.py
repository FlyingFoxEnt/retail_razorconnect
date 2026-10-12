# @category Analysis
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
OUT = "tsmp2_out.txt"  # written to the working directory
lines=[]
def emit(s):
    try: t=str(s)
    except Exception: t=repr(s)
    try: t=t.encode("ascii","replace").decode("ascii")
    except Exception: pass
    try: print(t)
    except Exception: pass
    lines.append(t)
prog=currentProgram; fm=prog.getFunctionManager(); listing=prog.getListing()
monitor=ConsoleTaskMonitor(); dec=DecompInterface(); dec.openProgram(prog)
def dump(a,why,maxlen=30000):
    f=fm.getFunctionContaining(toAddr(a)) if isinstance(a,str) else a
    if f is None: emit("none at %s"%a); return
    emit(""); emit("#"*60); emit("# %s"%why); emit("# %s @ %s"%(f.getName(),f.getEntryPoint())); emit("#"*60)
    try:
        r=dec.decompileFunction(f,300,monitor)
        c=r.getDecompiledFunction().getC() if (r and r.decompileCompleted()) else "<incomplete>"
    except Exception as e: c="<failed %s>"%e
    if len(c)>maxlen: c=c[:maxlen]+"\n/*...*/"
    emit(c)

dump("14008d1b0","TSMP type/code -> NAME mapping (gives numeric constants)")

emit(""); emit("=== search: 'Type Unhandled' / 'Unhandled' format strings ===")
targets={}
di=listing.getDefinedData(True)
while di.hasNext():
    d=di.next()
    try: v=d.getValue()
    except Exception: continue
    if v is None: continue
    try: s=str(v)
    except Exception: continue
    if "Unhandled" in s or "TIMEOUT: Proto" in s:
        emit("  %s : %r"%(d.getAddress(), s[:90]))
        for r in getReferencesTo(d.getAddress()):
            g=fm.getFunctionContaining(r.getFromAddress())
            if g: targets[g.getEntryPoint().toString()]=(g,"refs %r"%s[:40])
emit("")
for k in list(targets.keys())[:6]:
    g,why=targets[k]
    dump(g,why,20000)
with open(OUT,"w") as fh: fh.write("\n".join(lines))
emit(""); emit("WROTE %s"%OUT)
