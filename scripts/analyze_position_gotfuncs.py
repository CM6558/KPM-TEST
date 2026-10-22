"""
Disassemble and analyze the three key position-related functions:
1. sub_25c0570 (GOT @0x5090dc8) -- position getter from hero+0x10
2. sub_25be3b8 (GOT @0x5090b18) -- position getter from hero+0x20
3. sub_2593820 (GOT @0x508f300) -- position setter to visual object

Also analyze the full sub_36A2B44 function (position sync) to understand
the complete data flow: position source -> hero -> visual object.
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
                off = va - seg.virtual_address
                return content[off:off + max_size]
    return b''

def resolve_got(va):
    for reloc in elf.pltgot_relocations:
        if reloc.address == va:
            return reloc.addend if reloc.addend else (reloc.symbol.value if reloc.has_symbol else 0)
    for reloc in elf.dynamic_relocations:
        if reloc.address == va:
            return reloc.addend if reloc.addend else (reloc.symbol.value if reloc.has_symbol else 0)
    return 0


def disasm_func(addr, label, max_insns=120):
    """Full disassembly with GOT resolution and write annotation."""
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"  Address: 0x{addr:07x}")
    print(f"{'='*70}\n")

    func_bytes = get_func_bytes(addr, max_insns * 4)
    adrp_pages = {}
    insn_count = 0
    got_calls = []

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
        elif insn.mnemonic == 'add' and ',' in insn.op_str and 'sp' not in insn.op_str:
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
                                got_calls.append((insn.address, got_va, tgt, dst))
                            elif 'x19' in base or 'x0' in base or 'x1' in base:
                                annotation = f"; {dst} = *({base}+0x{off:x}) [OBJ READ]"
                            else:
                                annotation = f"; {dst} = *({base}+0x{off:x})"
                        except: pass
                    elif len(sp) == 1:
                        base = sp[0].strip()
                        if base in ('x0', 'x1', 'x19', 'x20', 'x21', 'x22'):
                            annotation = f"; {dst} = *({base}) [PTR DEREF]"
        elif insn.mnemonic == 'ldrb' and '[' in insn.op_str:
            parts = insn.op_str.split(', ', 1)
            if len(parts) == 2:
                dst = parts[0]
                src = parts[1]
                if '[' in src and ']' in src:
                    inner = src[src.index('[')+1:src.index(']')]
                    sp = inner.split(', ')
                    if len(sp) == 2:
                        annotation = f"; {dst} = BYTE at {sp[0]}+{sp[1]}"
                    elif len(sp) == 1:
                        annotation = f"; {dst} = BYTE at {sp[0]}"

        # Annotate writes
        if insn.mnemonic.startswith('str') and '[' in insn.op_str:
            parts = insn.op_str.split(', ', 1)
            if len(parts) == 2:
                val = parts[0]
                dest = parts[1]
                if '[' in dest:
                    inner = dest[dest.index('[')+1:dest.index(']')]
                    sp = inner.split(', ')
                    if 'sp' not in dest.lower():
                        if len(sp) == 2:
                            try:
                                off = int(sp[1].replace('#', ''), 0)
                                annotation = f"; *** WRITE {val} -> {sp[0]}+0x{off:x} ***"
                            except:
                                annotation = f"; *** WRITE {val} -> {dest} ***"
                        elif len(sp) == 1:
                            annotation = f"; *** WRITE {val} -> *{sp[0]} ***"
        elif insn.mnemonic == 'stp' and '[' in insn.op_str:
            if 'sp' not in insn.op_str.lower():
                annotation = "; *** PAIR WRITE (object) ***"

        if insn.mnemonic == 'blr':
            annotation = ">>> INDIRECT CALL"
        elif insn.mnemonic == 'br':
            annotation = ">>> TAIL CALL"
        elif insn.mnemonic == 'ret':
            annotation = "<<< RETURN >>>"
        elif insn.mnemonic == 'b' and '#' in insn.op_str:
            try:
                target = int(insn.op_str.replace('#', ''), 0)
                annotation = f">>> BRANCH to 0x{target:x}"
            except: pass
        elif insn.mnemonic.startswith('b.'):
            try:
                target = int(insn.op_str.replace('#', ''), 0)
                annotation = f">>> COND BRANCH to 0x{target:x}"
            except: pass
        elif insn.mnemonic == 'cbz' or insn.mnemonic == 'cbnz':
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                try:
                    target = int(parts[1].replace('#', ''), 0)
                    annotation = f">>> COND BRANCH to 0x{target:x}"
                except: pass

        line = f"  0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
        if annotation:
            line += f"  {annotation}"
        print(line)
        insn_count += 1
        if insn_count >= max_insns or insn.mnemonic == 'ret':
            break

    if got_calls:
        print(f"\n  GOT calls in this function:")
        for addr, got_va, tgt, dst in got_calls:
            print(f"    0x{addr:07x}: {dst} = *(GOT@0x{got_va:x}) = 0x{tgt:x}")

    return got_calls


# ==============================================================
# Function 1: sub_25c0570 (position getter from hero+0x10)
# ==============================================================
got1 = disasm_func(0x25c0570, "sub_25C0570 (GOT@0x5090dc8): position getter from hero+0x10", 60)

# ==============================================================
# Function 2: sub_25be3b8 (position getter from hero+0x20)
# ==============================================================
got2 = disasm_func(0x25be3b8, "sub_25BE3B8 (GOT@0x5090b18): position getter from hero+0x20", 60)

# ==============================================================
# Function 3: sub_2593820 (position setter to visual object)
# ==============================================================
got3 = disasm_func(0x2593820, "sub_2593820 (GOT@0x508f300): position setter to visual obj", 60)

# ==============================================================
# Function 4: sub_2593664 (GOT@0x508f2c0) -- called with w1 from hero+0x5c
# ==============================================================
got4 = disasm_func(0x2593664, "sub_2593664 (GOT@0x508f2c0): called with hero+0x5c/+0x54/+0x58", 40)

# ==============================================================
# Function 5: sub_25931d8 (GOT@0x508f260) -- another setter
# ==============================================================
got5 = disasm_func(0x25931d8, "sub_25931D8 (GOT@0x508f260): another setter", 40)

# ==============================================================
# Print summary
# ==============================================================
print("\n" + "=" * 70)
print("SUMMARY: Position data flow in sub_36A2B44")
print("=" * 70)
print("""
Data flow in sub_36A2B44 (position sync):

  IF hero+0x1d (is_server_auth flag) IS SET:
    1. Read position from hero+0x10 (ptr) + hero+0x18 (val)
       → x0 = *(hero+0x10), w1 = *(hero+0x18)
    2. Call sub_2593820(visual_obj, &position)  -- SET to visual

  IF hero+0x1d IS NOT SET:
    1. Call sub_25c0570(&hero+0x10)  -- GET position from hero+0x10 sub-obj
    2. Call sub_2593820(visual_obj, &position)  -- SET to visual

  THEN (always):
    3. Read more fields: hero+0x5c, hero+0x54, hero+0x58
    4. Call sub_2593664(visual_obj, hero+0x5c)  -- SET some field
    5. Call sub_2593664(visual_obj, hero+0x54)  -- SET atk_range_factor
    6. Call sub_25931d8(visual_obj, hero+0x58)  -- SET enabled_flag

  THEN (position query for SECOND visual obj):
    IF hero+0x2d (init flag) IS SET:
      7. Read position from hero+0x20/+0x28 directly
         → x0 = *(hero+0x20), w1 = *(hero+0x28)
      8. Call sub_2593820(visual_obj2, &position)  -- SET to visual2

    IF hero+0x2d IS NOT SET:
      7. Call sub_25be3b8(&hero+0x20)  -- GET position from hero+0x20 sub-obj
      8. Call sub_2593820(visual_obj2, &position)  -- SET to visual2

KEY INSIGHT:
  hero+0x10 → ptr to "server-authoritative position" (x,y packed)
  hero+0x20 → "render position" (x in +0x20 as 32-bit, y in +0x28 as 32-bit)
  hero+0x2d → init flag: if set, position is in hero+0x20/+0x28 directly
              if not set, must QUERY via sub_25be3b8(&hero+0x20)

  This means:
  - hero+0x20/+0x28 IS the position (when flag is set)
  - sub_25be3b8 is a GETTER that reads from the hero+0x20 struct
  - sub_25c0570 is a GETTER that reads from the hero+0x10 struct
  - sub_2593820 is a SETTER that writes position to a visual object
""")
