# Ghidra headless script (Jython): locate the DECI greeting and the handshake logic.
# @category Analysis

import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = "deci_hunt_out.txt"  # written to the working directory
lines = []

def emit(s):
    try:
        t = str(s)
    except Exception:
        t = repr(s)
    # Jython's console is ASCII; sanitize so a stray non-ASCII byte cannot kill the run.
    t = t.encode("ascii", "replace").decode("ascii") if hasattr(t, "encode") else t
    try:
        print(t)
    except Exception:
        pass
    lines.append(t)

prog = currentProgram
mem = prog.getMemory()
fm = prog.getFunctionManager()
listing = prog.getListing()
monitor = ConsoleTaskMonitor()

decomp = DecompInterface()
decomp.openProgram(prog)

emit("=== program: %s ===" % prog.getName())
emit("image base: %s" % prog.getImageBase())
emit("functions: %d" % fm.getFunctionCount())

def decompile(func, tag):
    try:
        res = decomp.decompileFunction(func, 120, monitor)
        if res and res.decompileCompleted():
            return res.getDecompiledFunction().getC()
    except Exception as e:
        return "<decompile failed: %s>" % e
    return "<no decompilation>"

def report_func(func, why, maxlen=9000):
    emit("")
    emit("############################################################")
    emit("# %s" % why)
    emit("# function %s @ %s" % (func.getName(), func.getEntryPoint()))
    emit("############################################################")
    c = decompile(func, why)
    if c and len(c) > maxlen:
        c = c[:maxlen] + "\n/* ...truncated... */"
    emit(c)

# ---------------------------------------------------------------- 1. byte pattern
emit("")
emit("=== occurrences of bytes 'DECI' ===")
pat = "\x44\x45\x43\x49"  # real bytes 'DECI', not literal backslash-x text
addr = mem.findBytes(prog.getMinAddress(), pat, None, True, monitor)
found = []
while addr is not None:
    found.append(addr)
    emit("  at %s" % addr)
    nxt = addr.add(1)
    addr = mem.findBytes(nxt, pat, None, True, monitor)
    if len(found) > 40:
        break

# ---------------------------------------------------------------- 2. xrefs
emit("")
emit("=== references to each 'DECI' occurrence ===")
seen_funcs = {}
for a in found:
    refs = getReferencesTo(a)
    emit("  %s : %d refs" % (a, len(refs)))
    for r in refs:
        frm = r.getFromAddress()
        f = fm.getFunctionContaining(frm)
        emit("      from %s  (%s)  type=%s" % (frm, f.getName() if f else "?", r.getReferenceType()))
        if f:
            seen_funcs[f.getEntryPoint().toString()] = (f, "references DECI literal at %s" % a)

# ---------------------------------------------------------------- 3. scalar 0x49434544
emit("")
emit("=== instructions using scalar 0x49434544 ('DECI' LE) ===")
count = 0
inst = listing.getInstructions(True)
while inst.hasNext() and count < 60:
    i = inst.next()
    try:
        n = i.getNumOperands()
    except:
        continue
    for op in range(n):
        sc = i.getScalar(op)
        if sc is not None and (sc.getUnsignedValue() & 0xFFFFFFFF) == 0x49434544:
            f = fm.getFunctionContaining(i.getAddress())
            emit("  %s  %s   (%s)" % (i.getAddress(), i, f.getName() if f else "?"))
            count += 1
            if f:
                seen_funcs[f.getEntryPoint().toString()] = (f, "uses immediate 0x49434544")

# ---------------------------------------------------------------- 4. key strings
KEY_STRINGS = [
    "Couldn't connect to PSP2 Network Manager",
    "Failure checking",
    "PSP2 Network Manager",
    "DECI",
]
emit("")
emit("=== functions referencing key strings ===")
for needle in KEY_STRINGS:
    emit("")
    emit("--- string: %r ---" % needle)
    # search defined strings
    di = listing.getDefinedData(True)
    hits = 0
    while di.hasNext() and hits < 12:
        d = di.next()
        try:
            v = d.getValue()
        except:
            continue
        if v is None:
            continue
        try:
            s = str(v)
        except Exception:
            try:
                s = unicode(v).encode("ascii", "replace")
            except Exception:
                continue
        if needle in s:
            hits += 1
            emit("  data %s : %r" % (d.getAddress(), s[:120]))
            for r in getReferencesTo(d.getAddress()):
                f = fm.getFunctionContaining(r.getFromAddress())
                emit("      xref from %s (%s)" % (r.getFromAddress(), f.getName() if f else "?"))
                if f:
                    seen_funcs[f.getEntryPoint().toString()] = (f, "references string %r" % needle[:40])
    if hits == 0:
        emit("  (no defined string matched)")

# ---------------------------------------------------------------- 5. decompile
emit("")
emit("=== decompilations (%d functions) ===" % len(seen_funcs))
for key in list(seen_funcs.keys())[:14]:
    f, why = seen_funcs[key]
    report_func(f, why)

with open(OUT, "w") as fh:
    fh.write("\n".join(lines))
emit("")
emit("WROTE %s" % OUT)
