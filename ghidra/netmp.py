# @category Analysis
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
OUT = "netmp_out.txt"  # written to the working directory
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
found={}
emit("=== NETMP strings ===")
di=listing.getDefinedData(True)
while di.hasNext():
    d=di.next()
    try: v=d.getValue()
    except Exception: continue
    if v is None: continue
    try: s=str(v)
    except Exception: continue
    if "NETMP" in s:
        emit("  %s : %r"%(d.getAddress(), s[:90]))
        for r in getReferencesTo(d.getAddress()):
            g=fm.getFunctionContaining(r.getFromAddress())
            if g: found[g.getEntryPoint().toString()]=g
emit("")
emit("=== decompiling %d NETMP functions ==="%len(found))
for k in list(found.keys())[:6]:
    g=found[k]
    emit(""); emit("#"*60); emit("# %s @ %s"%(g.getName(),g.getEntryPoint())); emit("#"*60)
    try:
        r=dec.decompileFunction(g,240,monitor)
        c=r.getDecompiledFunction().getC() if (r and r.decompileCompleted()) else "<incomplete>"
    except Exception as e: c="<failed %s>"%e
    if len(c)>22000: c=c[:22000]+"\n/*...*/"
    emit(c)
with open(OUT,"w") as fh: fh.write("\n".join(lines))
emit(""); emit("WROTE %s"%OUT)
