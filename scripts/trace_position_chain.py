"""
Deep-trace the position getter chain:
  sub_25be3b8(&hero+0x20) calls:
    1. sub_28e4f24(x0=hero+0x20)  -- GOT@0x50a5858  [first call]
    2. sub_3edbea4(prev_result)   -- GOT@0x51af3d8  [second call]
    3. sub_3d19bb8(result, &hero+0xc) -- GOT@0x519c260 [third call]
    Then: result = *(result) = vtable_ptr? -> check vtable+0xc0 or +0xd8

This traces the REAL position data source in the game engine.
The pattern (28e4f24 -> 3edbea4 -> 3d19bb8) is a "SceneNode query" chain.
"""

import lief
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ELF_PATH = r"D:\SGANEM\test.so"
elf = lief.parse(ELF_PATH)
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

CODE_START = 0x2185770

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

def disasm_func(addr, label, max_insns=80):
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"  Address: 0x{addr:07x}")
    print(f"{'='*70}\n")

    func_bytes = get_func_bytes(addr, max_insns * 4)
    adrp_pages = {}
    insn_count = 0
    got_calls = []
    obj_reads = []
    obj_writes = []

    for insn in cs.disasm(func_bytes, addr):
        annotation = ""
        # ADRP
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
        elif insn.mnemonic.startswith('ldr') and '[' in insn.op_str:
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
                            elif base in ('x0','x1','x19','x20','x21','x22','x23','x8'):
                                annotation = f"; {dst} = *({base}+0x{off:x})"
                                obj_reads.append((insn.address, dst, base, off))
                            else:
                                annotation = f"; {dst} = *({base}+0x{off:x})"
                        except: pass
                    elif len(sp) == 1:
                        base = sp[0].strip()
                        if base in ('x0','x1','x8','x19','x20','x21'):
                            annotation = f"; {dst} = *({base})"
                            obj_reads.append((insn.address, dst, base, 0))
        elif insn.mnemonic.startswith('str') and '[' in insn.op_str:
            parts = insn.op_str.split(', ', 1)
            if len(parts) == 2:
                val = parts[0]
                dest = parts[1]
                if 'sp' not in dest.lower() and '[' in dest:
                    inner = dest[dest.index('[')+1:dest.index(']')]
                    sp = inner.split(', ')
                    if len(sp) == 2:
                        try:
                            off = int(sp[1].replace('#', ''), 0)
                            annotation = f"; *** WRITE {val} -> {sp[0]}+0x{off:x} ***"
                            obj_writes.append((insn.address, val, sp[0], off))
                        except: pass
        elif insn.mnemonic == 'stp' and '[' in insn.op_str and 'sp' not in insn.op_str.lower():
            annotation = "; *** PAIR WRITE ***"

        if insn.mnemonic == 'blr':
            annotation = ">>> INDIRECT CALL"
        elif insn.mnemonic == 'br':
            annotation = ">>> TAIL CALL"
        elif insn.mnemonic == 'ret':
            annotation = "<<< RETURN >>>"
        elif insn.mnemonic == 'cbz' or insn.mnemonic == 'cbnz':
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                try:
                    target = int(parts[1].replace('#', ''), 0)
                    annotation = f">>> COND BRANCH to 0x{target:x}"
                except: pass
        elif insn.mnemonic.startswith('b.'):
            try:
                target = int(insn.op_str.replace('#', ''), 0)
                annotation = f">>> COND BRANCH to 0x{target:x}"
            except: pass
        elif insn.mnemonic == 'b' and '#' in insn.op_str:
            try:
                target = int(insn.op_str.replace('#', ''), 0)
                annotation = f">>> BRANCH to 0x{target:x}"
            except: pass

        line = f"  0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
        if annotation:
            line += f"  {annotation}"
        print(line)
        insn_count += 1
        if insn_count >= max_insns or insn.mnemonic == 'ret':
            break

    return got_calls, obj_reads, obj_writes


# ==============================================================
# Key function: sub_28e4f24 (first call in position getter chain)
# GOT@0x50a5858. This is called with x0=hero+0x20 (the position struct ptr)
# ==============================================================
g, r, w = disasm_func(0x28e4f24, "sub_28E4F24 (GOT@0x50a5858): first call in position getter chain", 60)

# ==============================================================
# Key function: sub_3edbea4 (second call, GOT@0x51af3d8)
# ==============================================================
g2, r2, w2 = disasm_func(0x3edbea4, "sub_3EDBEA4 (GOT@0x51af3d8): second call in position getter chain", 60)

# ==============================================================
# Key function: sub_3d19bb8 (third call, GOT@0x519c260)
# ==============================================================
g3, r3, w3 = disasm_func(0x3d19bb8, "sub_3D19BB8 (GOT@0x519c260): third call in position getter chain", 60)

# ==============================================================
# Key function: sub_45ce5e0 (fourth call, GOT@0x5228388)
# ==============================================================
g4, r4, w4 = disasm_func(0x45ce5e0, "sub_45CE5E0 (GOT@0x5228388): fourth call, vtable[0]", 40)

# ==============================================================
# Key function: sub_45c8a90 (called via vtable+0xc0 in hero+0x10 path)
# ==============================================================
g5, r5, w5 = disasm_func(0x45c8a90, "sub_45C8A90 (vtable+0xc0): position query via vtable", 40)

# ==============================================================
# Summary
# ==============================================================
print("\n" + "=" * 70)
print("POSITION DATA FLOW ANALYSIS SUMMARY")
print("=" * 70)
print("""
sub_25be3b8(&hero+0x20) -- position getter from hero+0x20:

  Step 1: x0 = sub_28e4f24(hero+0x20)     -- [GOT@0x50a5858]
          Returns some "scene node" or "component" pointer

  Step 2: x0 = sub_3edbea4(prev_x0)       -- [GOT@0x51af3d8]
          Returns another node/transform pointer

  Step 3: x0 = sub_3d19bb8(prev_x0, &hero+0xc)  -- [GOT@0x519c260]
          Uses hero+0xc (hero's config_id?) to look up a specific child

  Step 4: IF result chain is valid:
            x0 = *(result)           -- dereference first field
            Call *(x0)+0xc0             -- vtable call for position (hero+0x10 path)
                      OR
            Call *(x0)+0xd8             -- vtable call for position (hero+0x20 path)

          IF result chain is INVALID (cbz/b.ne to fallback):
            x0 = *(hero+0x20)    -- DIRECT READ from hero+0x20
            w1 = *(hero+0x28)    -- DIRECT READ from hero+0x28
            RETURN (x0, w1)      -- Position directly from hero fields!

  CONCLUSION:
    The fallback path reads hero+0x20 and hero+0x28 directly.
    The "happy path" goes through a SceneNode query chain that reads position
    from the engine's transform system.

    This means the getter can work in TWO modes:
    1. SceneNode query: when the hero has a valid transform in the scene graph
    2. Direct read: when hero+0x20/+0x28 has cached position values

    The fact that it FALLS BACK to reading hero+0x20/+0x28 confirms that
    hero+0x20 IS the position coordinate (mm), and ViewManager's 55000
    IS a position spoof.

    The "real" position in "happy path" comes from sub_45c8a90 (vtable+0xc0)
    or an equivalent vtable call on the SceneNode -- this reads from the
    engine's physics/transform system, NOT from hero+0x20.
""")
