# Ghidra headless script (Jython): decompile the post-handshake session machinery.
# @category Analysis

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = "session_hunt_out.txt"  # written to the working directory
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
listing = prog.getListing()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)

def decompile(func):
    try:
        res = decomp.decompileFunction(func, 180, monitor)
        if res and res.decompileCompleted():
            return res.getDecompiledFunction().getC()
        return "<decompile incomplete>"
    except Exception as e:
        return "<decompile failed: %s>" % e

def dump(func, why, maxlen=14000):
    emit("")
    emit("############################################################")
    emit("# %s" % why)
    emit("# %s @ %s" % (func.getName(), func.getEntryPoint()))
    emit("############################################################")
    c = decompile(func)
    if c and len(c) > maxlen:
        c = c[:maxlen] + "\n/* ...truncated... */"
    emit(c)

# ---- 1. explicit addresses of interest (from the handshake function) ----
WANTED = ["1400e08b0", "1400e04d0", "1400e01b0"]
for a in WANTED:
    try:
        f = fm.getFunctionContaining(toAddr(a))
        if f:
            dump(f, "explicitly requested %s" % a)
        else:
            emit("no function at %s" % a)
    except Exception as e:
        emit("error at %s: %s" % (a, e))

# ---- 2. functions referencing telltale session strings ----
NEEDLES = [
    "TM has timed out",
    "timed out",
    "DECI4_DCMP",
    "NOPROTOCOL",
    "INVALHEAD",
    "Unhandled",
]
emit("")
emit("=== string-driven function discovery ===")
found_funcs = {}
di = listing.getDefinedData(True)
scanned = 0
while di.hasNext():
    d = di.next()
    scanned += 1
    try:
        v = d.getValue()
    except Exception:
        continue
    if v is None:
        continue
    try:
        s = str(v)
    except Exception:
        continue
    for needle in NEEDLES:
        if needle in s:
            emit("  %s : %r" % (d.getAddress(), s[:110]))
            for r in getReferencesTo(d.getAddress()):
                f = fm.getFunctionContaining(r.getFromAddress())
                if f:
                    key = f.getEntryPoint().toString()
                    if key not in found_funcs:
                        found_funcs[key] = (f, "references %r" % needle)
                    emit("      <- %s (%s)" % (r.getFromAddress(), f.getName()))
            break

emit("")
emit("=== decompiling %d string-discovered functions ===" % len(found_funcs))
for key in list(found_funcs.keys())[:10]:
    f, why = found_funcs[key]
    dump(f, why)

# ---- 3. callers of the handshake function (context: who drives connections) ----
emit("")
emit("=== callers of the handshake FUN_1400e01b0 ===")
try:
    hs = fm.getFunctionContaining(toAddr("1400e01b0"))
    if hs:
        for r in getReferencesTo(hs.getEntryPoint()):
            f = fm.getFunctionContaining(r.getFromAddress())
            emit("  called from %s (%s)" % (r.getFromAddress(), f.getName() if f else "?"))
except Exception as e:
    emit("  error: %s" % e)

with open(OUT, "w") as fh:
    fh.write("\n".join(lines))
emit("")
emit("WROTE %s" % OUT)
