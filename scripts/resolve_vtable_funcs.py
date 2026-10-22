"""
Resolve the GOT slots used by vtable[19] and vtable[21] thunk functions,
then disassemble the ACTUAL target functions to see what they write.

Key findings from vtable scan:
1. vtable[19]=0x4552f98 (961 vtables) is a THUNK: loads from GOT 0x521f708
2. vtable[21]=0x4552fc0 (519 vtables) is a THUNK: loads from GOT 0x521f728
3. vtable[21]=0x25a55c0 is another THUNK: loads from GOT 0x508fea8
4. MOST COMMON vtable[19]=0x3741588 (3104 vtables) -- likely the real physics update
5. MOST COMMON vtable[21]=0x3741618 (3074 vtables) -- likely the real physics update

Also need to check the "sub_3D29460 (get_physics_subcomp)" second path (tbz branch target).
"""

import lief
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from collections import defaultdict

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

# ==============================================================
# Part 1: Resolve thunk function GOT slots
# ==============================================================
print("=" * 70)
print("THUNK RESOLUTION: vtable[19] and vtable[21] thunk targets")
print("=" * 70)

thunk_slots = {
    0x521f708: "vtable[19]=0x4552f98 thunk",
    0x521f728: "vtable[21]=0x4552fc0 thunk",
    0x508fea8: "vtable[21]=0x25a55c0 thunk",
}

thunk_targets = {}
for got_va, desc in thunk_slots.items():
    target = resolve_got(got_va)
    thunk_targets[got_va] = target
    print(f"  {desc}: GOT @0x{got_va:x} -> 0x{target:x}")

# ==============================================================
# Part 2: Disassemble the top candidates for vtable[19] and vtable[21]
# ==============================================================
print("\n" + "=" * 70)
print("TOP vtable[19] FUNCTIONS (by frequency)")
print("=" * 70)

# vtable[19] top candidates
vt19_top = [
    (0x3741588, 3104, "MOST COMMON vtable[19]"),
    (0x4552f98, 961, "THUNK vtable[19] -> GOT"),
    (0x32dffb58, 99, "vtable[19] variant"),
    (0x434691c, 602, "vtable[19] variant"),
    (0x2a36b70, 1713, "vtable[19] variant"),
    (0x2e11c2c, 599, "vtable[19] variant"),
    (0x33741588, 0, "same as top?"),  # likely typo
]

# Include thunk target
t1 = thunk_targets.get(0x521f708, 0)
if t1:
    vt19_top.append((t1, 0, "THUNK TARGET of vtable[19] thunk"))

print("\nFunction disassembly (first 20 instructions):")
funcs_done = set()
for func_addr, count, desc in vt19_top:
    if func_addr in funcs_done:
        continue
    funcs_done.add(func_addr)
    if not (CODE_START <= func_addr < CODE_END):
        print(f"\n  0x{func_addr:x}: NOT IN CODE SEGMENT ({desc})")
        continue

    print(f"\n--- 0x{func_addr:07x}: {desc} ({count} vtables) ---")
    func_bytes = get_func_bytes(func_addr, 80)
    count_i = 0
    for insn in cs.disasm(func_bytes, func_addr):
        annotation = ""
        if insn.mnemonic == 'adrp':
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                try:
                    page = int(parts[1].replace('#', ''), 0)
                    annotation = f"; -> page 0x{page:x}"
                except: pass
        elif insn.mnemonic == 'ldr' and '[' in insn.op_str:
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                src = parts[1]
                if '[' in src and ']' in src:
                    inner = src[src.index('[')+1:src.index(']')]
                    sp = inner.split(', ')
                    if len(sp) == 2:
                        try:
                            off = int(sp[1].replace('#', ''), 0)
                            annotation = f"; READ offset {off}"
                        except: pass
                    elif len(sp) == 1:
                        annotation = "; READ ptr deref"
        elif insn.mnemonic.startswith('str') and '[' in insn.op_str:
            annotation = "; *** WRITE ***"
        elif insn.mnemonic == 'blr':
            annotation = ">>> INDIRECT CALL"
        elif insn.mnemonic == 'br':
            annotation = ">>> TAIL CALL"
        elif insn.mnemonic == 'ret':
            annotation = "<<< RETURN"

        line = f"  0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
        if annotation:
            line += f"  {annotation}"
        print(line)
        count_i += 1
        if count_i >= 20 or insn.mnemonic == 'ret':
            break

# ==============================================================
# Part 3: TOP vtable[21] functions
# ==============================================================
print("\n" + "=" * 70)
print("TOP vtable[21] FUNCTIONS (by frequency)")
print("=" * 70)

vt21_top = [
    (0x3741618, 3074, "MOST COMMON vtable[21]"),
    (0x4552fc0, 519, "THUNK vtable[21] -> GOT"),
    (0x31027dc, 1217, "vtable[21] variant"),
    (0x2e11c4c, 654, "vtable[21] variant"),
    (0x30a4628, 267, "vtable[21] variant"),
    (0x34a6bf8, 31, "vtable[21] variant"),
    (0x25a55c0, 4, "vtable[21] ALT THUNK"),
]

t2 = thunk_targets.get(0x521f728, 0)
if t2:
    vt21_top.append((t2, 0, "THUNK TARGET of vtable[21] thunk"))
t3 = thunk_targets.get(0x508fea8, 0)
if t3:
    vt21_top.append((t3, 0, "THUNK TARGET of vtable[21] alt thunk"))

print("\nFunction disassembly (first 20 instructions):")
funcs_done2 = set()
for func_addr, count, desc in vt21_top:
    if func_addr in funcs_done2:
        continue
    funcs_done2.add(func_addr)
    if not (CODE_START <= func_addr < CODE_END):
        print(f"\n  0x{func_addr:x}: NOT IN CODE SEGMENT ({desc})")
        continue

    print(f"\n--- 0x{func_addr:07x}: {desc} ({count} vtables) ---")
    func_bytes = get_func_bytes(func_addr, 80)
    count_i = 0
    for insn in cs.disasm(func_bytes, func_addr):
        annotation = ""
        if insn.mnemonic.startswith('str') and '[' in insn.op_str:
            annotation = "; *** WRITE ***"
        elif insn.mnemonic == 'blr':
            annotation = ">>> INDIRECT CALL"
        elif insn.mnemonic == 'br':
            annotation = ">>> TAIL CALL"
        elif insn.mnemonic == 'ret':
            annotation = "<<< RETURN"
        elif insn.mnemonic == 'adrp':
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                try:
                    page = int(parts[1].replace('#', ''), 0)
                    annotation = f"; -> page 0x{page:x}"
                except: pass

        line = f"  0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
        if annotation:
            line += f"  {annotation}"
        print(line)
        count_i += 1
        if count_i >= 20 or insn.mnemonic == 'ret':
            break

# ==============================================================
# Part 4: Full disassembly of the MOST COMMON vtable[19] = 0x3741588
# ==============================================================
print("\n" + "=" * 70)
print("FULL DISASSEMBLY: 0x3741588 (MOST COMMON vtable[19], 3104 vtables)")
print("=" * 70)
print("This is likely the ACTUAL per-frame position update function!")
print()

func_bytes = get_func_bytes(0x3741588, 2048)
adrp_pages = {}
insn_count = 0
for insn in cs.disasm(func_bytes, 0x3741588):
    addr = insn.address
    mnem = insn.mnemonic
    ops = insn.op_str
    annotation = ""

    if mnem == 'adrp':
        parts = ops.split(', ')
        if len(parts) == 2:
            try:
                page = int(parts[1].replace('#', ''), 0)
                adrp_pages[parts[0]] = page
                annotation = f"; {parts[0]} = 0x{page:x}"
            except: pass
    elif mnem == 'add' and ',' in ops:
        parts = ops.split(', ')
        if len(parts) >= 3:
            try:
                imm = int(parts[2].replace('#', '').replace('0x', ''), 16)
                base = adrp_pages.get(parts[1], 0)
                adrp_pages[parts[0]] = base + imm
                annotation = f"; {parts[0]} = 0x{base + imm:x}"
            except: pass
    elif mnem == 'ldr' and '[' in ops:
        parts = ops.split(', ', 1)
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
                        else:
                            annotation = f"; {dst} = *({base}+0x{off:x})"
                    except: pass
                elif len(sp) == 1:
                    annotation = f"; {dst} = *({sp[0]})"
    elif mnem == 'str' and '[' in ops:
        annotation = "; *** WRITE ***"
    elif mnem == 'strb' and '[' in ops:
        annotation = "; *** BYTE WRITE ***"
    elif mnem == 'stp' and '[' in ops:
        annotation = "; *** PAIR WRITE ***"
    elif mnem == 'ldp' and '[' in ops:
        annotation = "; PAIR READ"
    elif mnem == 'blr':
        annotation = ">>> INDIRECT CALL"
    elif mnem == 'br':
        annotation = ">>> TAIL CALL"
    elif mnem == 'b.' or mnem.startswith('b.'):
        try:
            target = int(ops.replace('#', ''), 0)
            annotation = f"; -> 0x{target:x}"
        except: pass
    elif mnem == 'b':
        try:
            target = int(ops.replace('#', ''), 0)
            annotation = f"; -> 0x{target:x}"
        except: pass
    elif mnem == 'ret':
        annotation = "<<< RETURN >>>"

    line = f"  0x{addr:07x}: {mnem:10s} {ops}"
    if annotation:
        line += f"  {annotation}"
    print(line)
    insn_count += 1
    if insn_count > 200 or mnem == 'ret':
        break

# ==============================================================
# Part 5: Full disassembly of 0x3741618 (MOST COMMON vtable[21])
# ==============================================================
print("\n" + "=" * 70)
print("FULL DISASSEMBLY: 0x3741618 (MOST COMMON vtable[21], 3074 vtables)")
print("=" * 70)

func_bytes = get_func_bytes(0x3741618, 2048)
adrp_pages = {}
insn_count = 0
for insn in cs.disasm(func_bytes, 0x3741618):
    addr = insn.address
    mnem = insn.mnemonic
    ops = insn.op_str
    annotation = ""

    if mnem == 'adrp':
        parts = ops.split(', ')
        if len(parts) == 2:
            try:
                page = int(parts[1].replace('#', ''), 0)
                adrp_pages[parts[0]] = page
                annotation = f"; {parts[0]} = 0x{page:x}"
            except: pass
    elif mnem == 'add' and ',' in ops:
        parts = ops.split(', ')
        if len(parts) >= 3:
            try:
                imm = int(parts[2].replace('#', '').replace('0x', ''), 16)
                base = adrp_pages.get(parts[1], 0)
                adrp_pages[parts[0]] = base + imm
                annotation = f"; {parts[0]} = 0x{base + imm:x}"
            except: pass
    elif mnem == 'ldr' and '[' in ops:
        parts = ops.split(', ', 1)
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
                        else:
                            annotation = f"; {dst} = *({base}+0x{off:x})"
                    except: pass
                elif len(sp) == 1:
                    annotation = f"; {dst} = *({sp[0]})"
    elif mnem == 'str' and '[' in ops:
        annotation = "; *** WRITE ***"
    elif mnem == 'strb' and '[' in ops:
        annotation = "; *** BYTE WRITE ***"
    elif mnem == 'stp' and '[' in ops:
        annotation = "; *** PAIR WRITE ***"
    elif mnem == 'ldr' and '[' not in ops:
        # LDR literal (constant pool)
        try:
            target = int(ops.split(', ')[-1].replace('#', ''), 0)
            annotation = f"; = 0x{target:x}"
        except: pass
    elif mnem == 'blr':
        annotation = ">>> INDIRECT CALL"
    elif mnem == 'br':
        annotation = ">>> TAIL CALL"
    elif mnem == 'ret':
        annotation = "<<< RETURN >>>"

    line = f"  0x{addr:07x}: {mnem:10s} {ops}"
    if annotation:
        line += f"  {annotation}"
    print(line)
    insn_count += 1
    if insn_count > 200 or mnem == 'ret':
        break

# ==============================================================
# Part 6: Also resolve sub_3D29460 second branch (the tbz path at 0x3d2948c)
# ==============================================================
print("\n" + "=" * 70)
print("sub_3D29460 second path (tbz target @ 0x3d2948c)")
print("=" * 70)

func_bytes = get_func_bytes(0x3d2948c, 256)
for insn in cs.disasm(func_bytes, 0x3d2948c):
    annotation = ""
    if insn.mnemonic.startswith('str') and '[' in insn.op_str:
        annotation = "; *** WRITE ***"
    elif insn.mnemonic == 'ret':
        annotation = "<<< RETURN >>>"
    elif insn.mnemonic == 'blr':
        annotation = ">>> INDIRECT CALL"

    line = f"  0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
    if annotation:
        line += f"  {annotation}"
    print(line)
    if insn.mnemonic == 'ret':
        break
