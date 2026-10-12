# @category Analysis
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
OUT = "hdr_hunt_out.txt"  # written to the working directory
lines=[]
def emit(s):
    try: t=str(s)
    except Exception: t=repr(s)
    try: t=t.encode("ascii","replace").decode("ascii")
    except Exception: pass
    try: print(t)
    except Exception: pass
    lines.append(t)
prog=currentProgram; fm=prog.getFunctionManager(); monitor=ConsoleTaskMonitor()
dec=DecompInterface(); dec.openProgram(prog)
def dump(a,why,maxlen=16000):
    f=fm.getFunctionContaining(toAddr(a))
    if f is None:
        emit("no function at %s"%a); return
    emit(""); emit("#"*60); emit("# %s  [%s]"%(why,a)); emit("# %s @ %s"%(f.getName(),f.getEntryPoint())); emit("#"*60)
    try:
        r=dec.decompileFunction(f,180,monitor)
        c=r.getDecompiledFunction().getC() if (r and r.decompileCompleted()) else "<incomplete>"
    except Exception as e: c="<failed %s>"%e
    if c and len(c)>maxlen: c=c[:maxlen]+"\n/*...*/"
    emit(c)

dump("1400db780","GENERIC FRAME HEADER BUILDER")

emit(""); emit("=== callers of FUN_1400db780 (message vocabulary) ===")
b=fm.getFunctionContaining(toAddr("1400db780"))
callers={}
for r in getReferencesTo(b.getEntryPoint()):
    g=fm.getFunctionContaining(r.getFromAddress())
    emit("  from %s (%s)"%(r.getFromAddress(), g.getName() if g else "?"))
    if g: callers[g.getEntryPoint().toString()]=g
emit("")
emit("=== decompiling %d callers ==="%len(callers))
for k in list(callers.keys())[:22]:
    dump(k,"caller of header builder",6000)
with open(OUT,"w") as fh: fh.write("\n".join(lines))
emit(""); emit("WROTE %s"%OUT)
