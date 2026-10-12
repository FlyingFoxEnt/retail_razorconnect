# @category Analysis
import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
OUT = "netmp2_out.txt"  # written to the working directory
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

val=fm.getFunctionContaining(toAddr("1400ce940"))
emit("NETMP validator = %s @ %s"%(val.getName(), val.getEntryPoint()))
callers={}
for r in getReferencesTo(val.getEntryPoint()):
    g=fm.getFunctionContaining(r.getFromAddress())
    if g: callers[g.getEntryPoint().toString()]=g
emit("callers: %d"%len(callers))
pat=re.compile(r"FUN_1400ce940\([^,]+,(\d+),(\d+)\)")
rd=re.compile(r"FUN_140242a90\([^,]+,[^,]+,(0x[0-9a-fA-F]+|\d+)\)")
rows=[]
srcs={}
for k,g in callers.items():
    try:
        r=dec.decompileFunction(g,120,monitor)
        c=r.getDecompiledFunction().getC() if (r and r.decompileCompleted()) else ""
    except Exception: c=""
    m=pat.search(c)
    if not m: continue
    a,b=int(m.group(1)),int(m.group(2))
    rows.append((a,b,g.getName(),rd.findall(c),"var" if "FUN_1400ce100" in c or "FUN_1400cdeb0" in c else ""))
    srcs[(a,b)]=(g.getName(),c)
rows.sort()
emit("")
emit("%-16s %-6s %-6s %-14s %s"%("FUNC","ARG1","ARG2","READS","extra"))
for a,b,name,reads,extra in rows:
    emit("%-16s %-6d %-6d %-14s %s"%(name,a,b,",".join(reads) if reads else "-",extra))

# Dump the ones most likely to be PROTO_LIST / REGISTERED_LIST
emit("")
for key in sorted(srcs.keys()):
    a,b=key
    if a in (10,11,8,9,4,5,1):
        name,c=srcs[key]
        emit(""); emit("#"*60); emit("# args (%d,%d)  %s"%(a,b,name)); emit("#"*60)
        emit(c[:6000])
with open(OUT,"w") as fh: fh.write("\n".join(lines))
emit(""); emit("WROTE %s"%OUT)
