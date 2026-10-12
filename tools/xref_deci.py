"""Find code cross-references to the 'DECI' greeting literal in psp2tm.exe and
disassemble around them, looking for the constant the response is compared against.

Usage: xref_deci.py [file-offset-hex]
"""
import sys, pefile, capstone

PATH = r"C:\Program Files (x86)\SCE\PSP2\Tools\Target Manager Server\bin\psp2tm.exe"
TARGET_FILE_OFF = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x00318180

pe = pefile.PE(PATH, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(PATH, "rb").read()

def off_to_rva(off):
    for s in pe.sections:
        start = s.PointerToRawData
        end = start + s.SizeOfRawData
        if start <= off < end:
            return s.VirtualAddress + (off - start)
    return None

def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

target_rva = off_to_rva(TARGET_FILE_OFF)
target_va = base + target_rva
print(f"image base      0x{base:x}")
print(f"target file off 0x{TARGET_FILE_OFF:x}  ->  rva 0x{target_rva:x}  va 0x{target_va:x}")
print(f"bytes there     {data[TARGET_FILE_OFF:TARGET_FILE_OFF+16]!r}\n")

print("sections:")
for s in pe.sections:
    name = s.Name.rstrip(b"\x00").decode(errors="replace")
    print(f"  {name:<10} rva 0x{s.VirtualAddress:08x} vsize 0x{s.Misc_VirtualSize:08x} raw 0x{s.PointerToRawData:08x}")
print()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Scan executable sections for RIP-relative operands resolving to target_va.
hits = []
for s in pe.sections:
    if not (s.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
        continue
    sec_off = s.PointerToRawData
    sec_rva = s.VirtualAddress
    code = data[sec_off:sec_off + s.SizeOfRawData]
    sec_va = base + sec_rva
    for insn in md.disasm(code, sec_va):
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                resolved = insn.address + insn.size + op.mem.disp
                if resolved == target_va:
                    hits.append(insn.address)
print(f"RIP-relative references to 0x{target_va:x}: {len(hits)}")
for h in hits:
    print(f"  0x{h:x}")
print()

CTX_BACK = 0x120
CTX_FWD = 0x220

for h in hits[:6]:
    start_va = h - CTX_BACK
    off = rva_to_off(start_va - base)
    if off is None:
        continue
    blob = data[off:off + CTX_BACK + CTX_FWD]
    print(f"===== context around 0x{h:x} =====")
    for insn in md.disasm(blob, start_va):
        marker = "  >>" if insn.address == h else "    "
        text = f"{marker} 0x{insn.address:x}  {insn.mnemonic:<8} {insn.op_str}"
        # Flag compares with 32-bit immediates that look like ASCII
        if insn.mnemonic.startswith("cmp") or insn.mnemonic.startswith("sub"):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                    b = v.to_bytes(4, "little")
                    if all(32 <= c < 127 for c in b):
                        text += f"      <== imm 0x{v:08x} = {b!r}"
        print(text)
    print()
