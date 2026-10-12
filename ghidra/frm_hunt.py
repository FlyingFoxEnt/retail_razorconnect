# @category Analysis
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
OUT = "frm_hunt_out.txt"  # written to the working directory
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
def dump(a,why,maxlen=15000):
    f=fm.getFunctionContaining(toAddr(a))
    if f is None: emit("no function at %s"%a); return None
    emit(""); emit("#"*60); emit("# %s  [%s]"%(why,a)); emit("# %s @ %s"%(f.getName(),f.getEntryPoint())); emit("#"*60)
    try:
        r=dec.decompileFunction(f,180,monitor)
        c=r.getDecompiledFunction().getC() if (r and r.decompileCompleted()) else "<incomplete>"
    except Exception as e: c="<failed %s>"%e
    if c and len(c)>maxlen: c=c[:maxlen]+"\n/*...*/"
    emit(c); return f

dump("1400db470","FRAME HEADER WRITER (protocol,flags)")
dump("1400e0770","FRAME READER")
dump("1400e0040","reader helper")

# Who consumes parsed frames? decompile callers of the reader.
emit(""); emit("=== callers of frame reader FUN_1400e0770 ===")
b=fm.getFunctionContaining(toAddr("1400e0770"))
for r in getReferencesTo(b.getEntryPoint()):
    g=fm.getFunctionContaining(r.getFromAddress())
    emit("  from %s (%s)"%(r.getFromAddress(), g.getName() if g else "?"))

# The 0x40000000 constant: where does it come from?
emit(""); emit("=== instructions using scalar 0x40000000 near the frame code ===")
listing=prog.getListing()
lo=0x1400db000; hi=0x1400e1000
it=listing.getInstructions(toAddr("1400db000"), True)
n=0
while it.hasNext() and n<80:
    i=it.next()
    if i.getAddress().getOffset()>hi: break
    for op in range(i.getNumOperands()):
        sc=i.getScalar(op)
        if sc is not None:
            v=sc.getUnsignedValue()&0xFFFFFFFF
            if v in (0x40000000,0x2000,0x4000,0x15a3f8e1):
                f=fm.getFunctionContaining(i.getAddress())
                emit("  %s  %-40s  (%s)"%(i.getAddress(), i, f.getName() if f else "?"))
                n+=1
with open(OUT,"w") as fh: fh.write("\n".join(lines))
emit(""); emit("WROTE %s"%OUT)
