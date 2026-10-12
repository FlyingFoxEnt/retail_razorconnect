# @category Analysis
import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
OUT = "table_out.txt"  # written to the working directory
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

target=fm.getFunctionContaining(toAddr("1400cf160"))
emit("validator = %s @ %s"%(target.getName(), target.getEntryPoint()))
callers={}
for r in getReferencesTo(target.getEntryPoint()):
    g=fm.getFunctionContaining(r.getFromAddress())
    if g: callers[g.getEntryPoint().toString()]=g
emit("callers: %d"%len(callers))

pat=re.compile(r"FUN_1400cf160\([^,]+,(\d+),(\d+)\)")
rd=re.compile(r"FUN_140242a90\([^,]+,[^,]+,(0x[0-9a-fA-F]+|\d+)\)")
emit("")
emit("%-10s %-6s %-6s %-10s %s"%("FUNC","TYPE","CODE","BODYSIZE","extra"))
rows=[]
for k,g in callers.items():
    try:
        r=dec.decompileFunction(g,120,monitor)
        c=r.getDecompiledFunction().getC() if (r and r.decompileCompleted()) else ""
    except Exception:
        c=""
    m=pat.search(c)
    if not m: continue
    t,cd=int(m.group(1)),int(m.group(2))
    sizes=rd.findall(c)
    extra=""
    if "FUN_1400cdeb0" in c: extra+="var-blob "
    if len(sizes)>1: extra+="multi-read "
    rows.append((t,cd,g.getName(),sizes,extra))
rows.sort()
for t,cd,name,sizes,extra in rows:
    emit("%-10s %-6d %-6d %-10s %s"%(name,t,cd,",".join(sizes) if sizes else "-",extra))
with open(OUT,"w") as fh: fh.write("\n".join(lines))
emit(""); emit("WROTE %s"%OUT)
