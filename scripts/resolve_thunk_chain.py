"""
GOT-based thunk chain resolution.

The vtable[19]/[21] functions found in the previous step are all thunks
that load from GOT slots and tail-call (BR) to the real function.

This script resolves the full thunk chains:
  vtable[19] func -> GOT load -> real function
  vtable[21] func -> GOT load -> real function

Then disassembles the REAL functions to see what they write.
"""

import lief
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ELF_PATH = r"D:\SGANEM\test.so"
elf = lief.parse(ELF_PATH)

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

CODE_START = 0x2185770
CODE_END = 0x2185770 + 0x29bcbc0

def get_func_bytes(va, max_size=8192):
    for seg in elf.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            content = bytes(seg.content)
            if seg.virtual_address <= va < seg.virtual_address + len(content):
                offset = va - seg.virtual_address
                return content[offset:offset + max_size]
    return b''

def resolve_got(va):
    for reloc in elf.pltgot_relocations:
        if reloc.address == va:
            return reloc.addend if reloc.addend else (reloc.symbol.value if reloc.has_symbol else 0)
    for reloc in elf.dynamic_relocations:
        if reloc.address == va:
            return reloc.addend if reloc.addend else (reloc.symbol.value if reloc.has_symbol else 0)
    return 0

def disasm_func(addr, label, max_insns=80):
    print(f"\n--- 0x{addr:07x}: {label} ---")
    func_bytes = get_func_bytes(addr, 320)
    adrp_pages = {}
    count = 0
    got_targets = []
    for insn in cs.disasm(func_bytes, addr):
        annotation = ""
        if insn.mnemonic == 'adrp':
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                try:
                    page = int(parts[1].replace('#', ''), 0)
                    adrp_pages[parts[0]] = page
                    annotation = f"; {parts[0]} = 0x{page:x}"
                except: pass
        elif insn.mnemonic == 'add' and ',' in insn.op_str:
            parts = insn.op_str.split(', ')
            if len(parts) >= 3:
                try:
                    imm = int(parts[2].replace('#', '').replace('0x', ''), 16)
                    base = adrp_pages.get(parts[1], 0)
                    adrp_pages[parts[0]] = base + imm
                    annotation = f"; {parts[0]} = 0x{base + imm:x}"
                except: pass
        elif insn.mnemonic == 'ldr' and '[' in insn.op_str:
            parts = insn.op_str.split(', ', 1)
            if len(parts) == 2:
                dst = parts[0]
                src = parts[1]
                if '[' in src and ']' in src:
                    inner = src[src.index('[')+1:src.index(']')]
                    sp = inner.split(', ')
                    if len(sp) == 2:
                        base = sp[0]
                        try:
                            off = int(sp[1].replace('#', ''), 0)
                            page = adrp_pages.get(base, 0)
                            got_va = page + off
                            tgt = resolve_got(got_va)
                            if tgt:
                                annotation = f"; {dst} = *(0x{got_va:x}) = 0x{tgt:x} [GOT]"
                                got_targets.append((got_va, tgt, dst))
                            else:
                                annotation = f"; {dst} = *({base}+0x{off:x})"
                        except: pass
                    elif len(sp) == 1:
                        annotation = f"; {dst} = *({sp[0]})"
        elif insn.mnemonic.startswith('str') and '[' in insn.op_str:
            annotation = "; *** WRITE ***"
        elif insn.mnemonic == 'stp' and '[' in insn.op_str:
            annotation = "; *** PAIR WRITE ***"
        elif insn.mnemonic == 'blr':
            annotation = ">>> INDIRECT CALL"
        elif insn.mnemonic == 'br':
            annotation = ">>> TAIL CALL"
        elif insn.mnemonic == 'ret':
            annotation = "<<< RETURN >>>"

        line = f"  0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
        if annotation:
            line += f"  {annotation}"
        print(line)
        count += 1
        if count >= max_insns or insn.mnemonic == 'ret':
            break
    return got_targets

# ==============================================================
# Resolve thunk chains for vtable[19] and vtable[21]
# ==============================================================
print("=" * 70)
print("THUNK CHAIN RESOLUTION")
print("=" * 70)

# vtable[19] thunks with their GOT slots
vt19_thunks = [
    (0x3741588, 3104, 0x515bb68, "MOST COMMON vtable[19]"),
    (0x4552f98, 961,  0x521f708, "THUNK vtable[19]"),
    (0x434691c, 602,  0x5205d18, "vtable[19] variant"),
    (0x2a36b70, 1713, 0x50b9298, "vtable[19] variant"),
    (0x2e11c2c, 599,  0x50eb3e8, "vtable[19] variant"),
]

print("\nvtable[19] thunk chain resolution:")
vt19_real = []
for thunk_addr, count, got_va, desc in vt19_thunks:
    target = resolve_got(got_va)
    print(f"  0x{thunk_addr:07x} ({desc}, {count} vtables)")
    print(f"    BR -> *(GOT @0x{got_va:x}) = 0x{target:x}")
    vt19_real.append((target, f"{desc} (via 0x{thunk_addr:x})"))

# vtable[21] thunks with their GOT slots
vt21_thunks = [
    (0x3741618, 3074, 0x515bb88, "MOST COMMON vtable[21]"),
    (0x4552fc0, 519,  0x521f728, "THUNK vtable[21]"),
    (0x31027dc, 1217, 0x5116d90, "vtable[21] variant"),
    (0x2e11c4c, 654,  0x50eb408, "vtable[21] variant"),
    (0x30a4628, 267,  0x5111f80, "vtable[21] variant"),
    (0x34a6bf8, 31,   0x5140010, "vtable[21] variant"),
    (0x25a55c0, 4,    0x508fea8, "vtable[21] ALT THUNK"),
]

print("\nvtable[21] thunk chain resolution:")
vt21_real = []
for thunk_addr, count, got_va, desc in vt21_thunks:
    target = resolve_got(got_va)
    print(f"  0x{thunk_addr:07x} ({desc}, {count} vtables)")
    print(f"    BR -> *(GOT @0x{got_va:x}) = 0x{target:x}")
    vt21_real.append((target, f"{desc} (via 0x{thunk_addr:x})"))

# ==============================================================
# Follow second-level thunks (if targets are also thunks)
# ==============================================================
print("\n" + "=" * 70)
print("Second-level thunk resolution")
print("=" * 70)

# Check if real targets are themselves thunks
# A thunk looks like: ADRP + LDR + BR
def check_if_thunk(addr):
    """Check if function at addr is a GOT-thunk (ADRP+LDR+BR pattern)."""
    if not (CODE_START <= addr < CODE_END):
        return False
    func_bytes = get_func_bytes(addr, 16)
    instructions = list(cs.disasm(func_bytes, addr))
    if len(instructions) >= 3:
        i0, i1, i2 = instructions[0], instructions[1], instructions[2]
        return (i0.mnemonic == 'adrp' and i1.mnemonic == 'ldr' and i2.mnemonic == 'br')
    return False

def resolve_thunk_chain(addr, depth=0, max_depth=10):
    """Follow BR chain until we reach a real function."""
    if depth > max_depth:
        return addr
    if not check_if_thunk(addr):
        return addr
    func_bytes = get_func_bytes(addr, 16)
    instructions = list(cs.disasm(func_bytes, addr))
    adrp_reg = None
    adrp_page = 0
    for insn in instructions[:3]:
        if insn.mnemonic == 'adrp':
            parts = insn.op_str.split(', ')
            adrp_reg = parts[0]
            adrp_page = int(parts[1].replace('#', ''), 0)
        elif insn.mnemonic == 'ldr' and adrp_reg:
            parts = insn.op_str.split(', ', 1)
            dst = parts[0]
            src = parts[1]
            if '[' in src and ']' in src:
                inner = src[src.index('[')+1:src.index(']')]
                sp = inner.split(', ')
                if len(sp) == 2 and sp[0] == adrp_reg:
                    off = int(sp[1].replace('#', ''), 0)
                    got_va = adrp_page + off
                    target = resolve_got(got_va)
                    print(f"    {'  ' * depth}0x{addr:x} -> GOT@0x{got_va:x} -> 0x{target:x}")
                    return resolve_thunk_chain(target, depth + 1, max_depth)
    return addr

print("\nvtable[19] full chain resolution:")
vt19_final = set()
for target, desc in vt19_real:
    if target and (CODE_START <= target < CODE_END):
        final = resolve_thunk_chain(target)
        vt19_final.add(final)
        print(f"  {desc}: 0x{target:x} -> FINAL: 0x{final:x}")
    else:
        print(f"  {desc}: 0x{target:x} (not in code or zero)")

print("\nvtable[21] full chain resolution:")
vt21_final = set()
for target, desc in vt21_real:
    if target and (CODE_START <= target < CODE_END):
        final = resolve_thunk_chain(target)
        vt21_final.add(final)
        print(f"  {desc}: 0x{target:x} -> FINAL: 0x{final:x}")

# ==============================================================
# Disassemble ALL final real functions
# ==============================================================
print("\n" + "=" * 70)
print("REAL vtable[19] functions (after thunk chain resolution)")
print("=" * 70)

for addr in sorted(vt19_final):
    if addr and (CODE_START <= addr < CODE_END):
        disasm_func(addr, f"vtable[19] REAL function at 0x{addr:x}")
    else:
        print(f"\n  0x{addr:x}: not in code segment")

print("\n" + "=" * 70)
print("REAL vtable[21] functions (after thunk chain resolution)")
print("=" * 70)

for addr in sorted(vt21_final):
    if addr and (CODE_START <= addr < CODE_END):
        disasm_func(addr, f"vtable[21] REAL function at 0x{addr:x}")
    else:
        print(f"\n  0x{addr:x}: not in code segment")

# ==============================================================
# Summary: which functions write to obj+0x20?
# ==============================================================
print("\n" + "=" * 70)
print("SUMMARY: Write targets in vtable[19]/[21] real functions")
print("=" * 70)

all_real = sorted(vt19_final | vt21_final)
for addr in all_real:
    if not (CODE_START <= addr < CODE_END):
        continue
    is_19 = addr in vt19_final
    is_21 = addr in vt21_final
    slot_info = "vtable[19]" if is_19 else ""
    if is_21:
        slot_info = "vtable[21]" if not slot_info else "vtable[19]+[21]"
    print(f"\n  0x{addr:07x} [{slot_info}]:")

    func_bytes = get_func_bytes(addr, 8192)
    writes = []
    for insn in cs.disasm(func_bytes, addr):
        if insn.mnemonic.startswith('str'):
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                val = parts[0]
                dest = parts[1]
                if '[' in dest and ']' in dest:
                    writes.append((insn.mnemonic, val, dest))
        elif insn.mnemonic.startswith('stp'):
            parts = insn.op_str.split(', ')
            if len(parts) >= 3:
                val = f"{parts[0]},{parts[1]}"
                dest = parts[2]
                if '[' in dest and ']' in dest:
                    writes.append((insn.mnemonic, val, dest))
        elif insn.mnemonic == 'ret':
            break

    if writes:
        for mnem, val, dest in writes:
            # Extract offset
            if '+' in dest:
                offset_str = dest.split('+')[-1].strip()
                if '#' in offset_str:
                    offset_str = offset_str.replace('#', '')
                print(f"    {mnem:6s} {val:20s} -> {dest}")
            else:
                print(f"    {mnem:6s} {val:20s} -> {dest} (register indirect)")
    else:
        print("    (no STR/STP writes found in first 8KB)")
