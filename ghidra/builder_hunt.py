# Ghidra headless script (Jython): decompile the connect driver and message builders.
# @category Analysis

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = "builder_hunt_out.txt"  # written to the working directory
lines = []

def emit(s):
    try:
        t = str(s)
    except Exception:
        t = repr(s)
    try:
        t = t.encode("ascii", "replace").decode("ascii")
    except Exception:
        pass
    try:
        print(t)
    except Exception:
        pass
    lines.append(t)

prog = currentProgram
fm = prog.getFunctionManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)

def dump(addr_str, why, maxlen=16000):
    try:
        f = fm.getFunctionContaining(toAddr(addr_str))
    except Exception as e:
        emit("bad addr %s: %s" % (addr_str, e))
        return
    if f is None:
        emit("no function containing %s" % addr_str)
        return
    emit("")
    emit("############################################################")
    emit("# %s   [%s]" % (why, addr_str))
    emit("# %s @ %s" % (f.getName(), f.getEntryPoint()))
    emit("############################################################")
    try:
        res = decomp.decompileFunction(f, 180, monitor)
        c = res.getDecompiledFunction().getC() if (res and res.decompileCompleted()) else "<incomplete>"
    except Exception as e:
        c = "<failed: %s>" % e
    if c and len(c) > maxlen:
        c = c[:maxlen] + "\n/* ...truncated... */"
    emit(c)

TARGETS = [
    ("140077b40", "connect driver - calls the handshake"),
    ("1400df380", "message builder used for the timeout text frame"),
    ("1400e0770", "frame reader (called by the session thread)"),
    ("1400e0bc0", "send/queue used after building the timeout frame"),
    ("140089bb0", "timeout frame construction (context)"),
]
for a, why in TARGETS:
    dump(a, why)

# Neighbours of the builder: sibling builders usually sit adjacent.
emit("")
emit("=== functions near FUN_1400df380 (likely sibling message builders) ===")
try:
    base = toAddr("1400df380")
    f = fm.getFunctionContaining(base)
    it = fm.getFunctions(True)
    near = []
    while it.hasNext():
        g = it.next()
        off = g.getEntryPoint().getOffset() - base.getOffset()
        if -0x1200 <= off <= 0x1200:
            near.append((off, g))
    near.sort()
    for off, g in near:
        emit("  %+6d  %s @ %s" % (off, g.getName(), g.getEntryPoint()))
except Exception as e:
    emit("  error: %s" % e)

# Callers of the builder tell us every message type that uses this frame format.
emit("")
emit("=== callers of FUN_1400df380 ===")
try:
    b = fm.getFunctionContaining(toAddr("1400df380"))
    for r in getReferencesTo(b.getEntryPoint()):
        g = fm.getFunctionContaining(r.getFromAddress())
        emit("  from %s (%s)" % (r.getFromAddress(), g.getName() if g else "?"))
except Exception as e:
    emit("  error: %s" % e)

with open(OUT, "w") as fh:
    fh.write("\n".join(lines))
emit("")
emit("WROTE %s" % OUT)
