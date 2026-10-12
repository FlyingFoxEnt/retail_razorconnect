"""Find code sites that use the 4-byte immediate 'DECI' (0x49434544) and dump the
surrounding disassembly, flagging every nearby 32-bit immediate compare.

Usage: find_imm.py [pe-path]
"""
import sys, pefile, capstone
from capstone import x86

PATH = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:\Program Files (x86)\SCE\PSP2\Tools\Target Manager Server\bin\psp2tm.exe"

WANT = 0x49434544  # 'DECI' little-endian

pe = pefile.PE(PATH, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(PATH, "rb").read()

def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

print(f"== {PATH}")
print(f"   scanning for immediate 0x{WANT:08x} ('DECI')\n")

hits = []
for s in pe.sections:
    if not (s.Characteristics & 0x20000000):
        continue
    code = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
    sec_va = base + s.VirtualAddress
    for insn in md.disasm(code, sec_va):
        for op in insn.operands:
            if op.type == x86.X86_OP_IMM and (op.imm & 0xFFFFFFFF) == WANT:
                hits.append((insn.address, insn.mnemonic, insn.op_str))

print(f"sites using the immediate: {len(hits)}")
for a, m, o in hits:
    print(f"  0x{a:x}  {m} {o}")
print()

def ascii_imm(v):
    b = (v & 0xFFFFFFFF).to_bytes(4, "little")
    return b if all(32 <= c < 127 for c in b) else None

BACK, FWD = 0x80, 0x300
for addr, _, _ in hits[:8]:
    start_va = addr - BACK
    off = rva_to_off(start_va - base)
    if off is None:
        continue
    print(f"========== around 0x{addr:x} ==========")
    for insn in md.disasm(data[off:off + BACK + FWD], start_va):
        mark = ">>" if insn.address == addr else "  "
        line = f" {mark} 0x{insn.address:x}  {insn.mnemonic:<9} {insn.op_str}"
        for op in insn.operands:
            if op.type == x86.X86_OP_IMM:
                a = ascii_imm(op.imm)
                if a and op.imm != WANT:
                    line += f"        <== {a!r}"
        print(line)
    print()
