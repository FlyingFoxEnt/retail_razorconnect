# @category Analysis
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
OUT = "dec_hunt_out.txt"  # written to the working directory
lines=[]
def emit(s):
    try: t=str(s)
    except Exception: t=repr(s)
    try: t=t.encode("ascii","replace").decode("ascii")
    except Exception: pass
    try: print(t)
    except Exception: pass
    lines.append(t)
prog=currentProgram; fm=prog.getFunctionManager()
monitor=ConsoleTaskMonitor(); dec=DecompInterface(); dec.openProgram(prog)

emit("=== functions in 0x1400d6000..0x1400d7600 ===")
funcs=[]
it=fm.getFunctions(True)
while it.hasNext():
    g=it.next()
    off=g.getEntryPoint().getOffset()
    if 0x1400d6000 <= off <= 0x1400d7600:
        funcs.append(g)
funcs.sort(key=lambda g: g.getEntryPoint().getOffset())
for g in funcs:
    emit("  %s  %s"%(g.getEntryPoint(), g.getName()))

emit(""); emit("=== decompiling them ===")
for g in funcs[:26]:
    emit(""); emit("#"*60); emit("# %s @ %s"%(g.getName(),g.getEntryPoint())); emit("#"*60)
    try:
        r=dec.decompileFunction(g,180,monitor)
        c=r.getDecompiledFunction().getC() if (r and r.decompileCompleted()) else "<incomplete>"
    except Exception as e: c="<failed %s>"%e
    if len(c)>5000: c=c[:5000]+"\n/*...*/"
    emit(c)
with open(OUT,"w") as fh: fh.write("\n".join(lines))
emit(""); emit("WROTE %s"%OUT)
