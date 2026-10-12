"""Widen the hunt for the DECI greeting:
  1. RIP-relative code refs into a RANGE around the literal (struct-base refs).
  2. 8-byte pointers anywhere in the image that point at / near the literal.
Reports each with context.
"""
import pefile, capstone
from capstone import x86

PATH = r"C:\Program Files (x86)\SCE\PSP2\Tools\Target Manager Server\bin\psp2tm.exe"
TARGET_OFF = 0x00318180
SPAN = 0x80

pe = pefile.PE(PATH, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(PATH, "rb").read()

def off_to_rva(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            return s.VirtualAddress + (off - s.PointerToRawData)

def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)

target_va = base + off_to_rva(TARGET_OFF)
lo, hi = target_va - SPAN, target_va + SPAN
print(f"target va 0x{target_va:x}; scanning refs into [0x{lo:x}, 0x{hi:x}]\n")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

code_refs = []
for s in pe.sections:
    if not (s.Characteristics & 0x20000000):
        continue
    blob = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
    for insn in md.disasm(blob, base + s.VirtualAddress):
        for op in insn.operands:
            if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                r = insn.address + insn.size + op.mem.disp
                if lo <= r <= hi:
                    code_refs.append((insn.address, r, insn.mnemonic, insn.op_str))

print(f"code refs into range: {len(code_refs)}")
for a, r, m, o in code_refs[:40]:
    delta = r - target_va
    print(f"  0x{a:x}  -> 0x{r:x} (target{delta:+#x})  {m} {o}")
print()

# Pointer-table scan: any qword in the image equal to an address in range.
ptr_hits = []
for off in range(0, len(data) - 8, 4):
    v = int.from_bytes(data[off:off + 8], "little")
    if lo <= v <= hi:
        ptr_hits.append((off, v))
print(f"qword pointers into range: {len(ptr_hits)}")
for off, v in ptr_hits[:40]:
    rva = off_to_rva(off)
    sec = "?"
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            sec = s.Name.rstrip(b"\x00").decode(errors="replace")
    va = base + rva if rva else 0
    print(f"  file 0x{off:x} (va 0x{va:x}, {sec}) -> 0x{v:x} (target{v-target_va:+#x})")
