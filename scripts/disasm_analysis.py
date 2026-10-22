"""
Static Disassembly Analysis for sub_3EE11B8 (MovementComponent::UpdateLogic)
==============================================================================
Use capstone to disassemble the function, identify:
1. All BLR call sites (GOT-based vs vtable-based)
2. Conditional branches that gate vtable[19]/vtable[21] calls
3. What values need to be set in fake objects to reach those calls

This prepares us for proper Unicorn emulation.
"""

import lief
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ELF_PATH = r"D:\SGANEM\test.so"
FUNC_ADDR = 0x3EE11B8

# Load ELF
elf = lief.parse(ELF_PATH)

# Get function bytes
def get_func_bytes(va, max_size=4096):
    for seg in elf.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            if seg.virtual_address <= va < seg.virtual_address + len(seg.content):
                offset = va - seg.virtual_address
                content = bytes(seg.content)
                return content[offset:offset + max_size]
    return None

# Read GOT slot value from relocation table
def resolve_got(va):
    for reloc in elf.pltgot_relocations:
        if reloc.address == va:
            if reloc.addend:
                return reloc.addend
            elif reloc.has_symbol:
                return reloc.symbol.value
    for reloc in elf.dynamic_relocations:
        if reloc.address == va:
            if reloc.addend:
                return reloc.addend
            elif reloc.has_symbol:
                return reloc.symbol.value
    return None

func_bytes = get_func_bytes(FUNC_ADDR, 4096)
if not func_bytes:
    print("ERROR: cannot read function bytes")
    exit(1)

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

print("=" * 70)
print(f"Disassembly: sub_3EE11B8 (MovementComponent::UpdateLogic)")
print(f"Address: 0x{FUNC_ADDR:x}, bytes: {len(func_bytes)}")
print("=" * 70)

# Known GOT slots
KNOWN_GOT = {
    0x5090010: ("off_5090010", "direction_normalize", 0x25a6930),
    0x5153CB0: ("off_5153CB0", "per_frame_update", 0x36a2678),
    0x51548E0: ("off_51548E0", "return_a1_plus_16", 0x36b009c),
    0x519D358: ("off_519D358", "get_physics_subcomp", 0x3d29460),
    0x51AF678: ("off_51AF678", "RVO_update", 0x3edf920),
    0x51AF748: ("off_51AF748", "MovementComponent_UpdateLogic", 0x3ee11b8),
    0x5226B10: ("off_5226B10", "per_frame_HeroEntry_lookup", 0x45abe90),
    0x51B7520: ("off_51B7520", "getter_obj+0x60", 0x3f7d028),
    0x51B75B0: ("off_51B75B0", "setter_obj+0x78", 0x3f7d0b4),
}

# Track ADRP+LDR pairs (GOT slot resolution)
adrp_targets = {}  # reg -> page_address
blr_sites = []      # (addr, reg)
ldr_from_adrp = {}   # reg -> (page, offset, got_va, resolved_target)

print("\n--- Instruction-by-instruction ---\n")

for insn in cs.disasm(func_bytes, FUNC_ADDR):
    addr = insn.address
    mnem = insn.mnemonic
    ops = insn.op_str

    annotation = ""

    # ADRP: sets a page address
    if mnem == 'adrp':
        parts = ops.split(', ')
        if len(parts) == 2:
            reg = parts[0]
            try:
                page = int(parts[1].replace('#', ''), 0)
                adrp_targets[reg] = page
                annotation = f"; {reg} = page 0x{page:x}"
            except:
                pass

    # ADD: compute address from ADRP page
    elif mnem == 'add' and 'adrp' not in ops:
        parts = ops.split(', ')
        if len(parts) >= 3 and parts[0] in adrp_targets:
            reg = parts[0]
            try:
                imm = int(parts[2].replace('#', '').replace('0x', ''), 16)
                page = adrp_targets.get(parts[1], 0)
                addr_val = page + imm
                adrp_targets[reg] = addr_val
                annotation = f"; {reg} = 0x{addr_val:x}"
            except:
                pass

    # LDR from computed address (GOT slot read)
    elif mnem == 'ldr' and '[' in ops:
        # Pattern: ldr xN, [xM, #offset] or ldr xN, [xM]
        parts = ops.split(', ')
        if len(parts) == 2:
            dst_reg = parts[0]
            src_part = parts[1]
            # Extract base register and offset
            if '[' in src_part and ']' in src_part:
                src_inner = src_part[src_part.index('[')+1:src_part.index(']')]
                src_parts = src_inner.split(', ')
                if len(src_parts) == 2:
                    base_reg = src_parts[0]
                    offset_str = src_parts[1].replace('#', '')
                    try:
                        offset = int(offset_str, 0)
                        page = adrp_targets.get(base_reg, 0)
                        got_va = page + offset
                        target = resolve_got(got_va)

                        # Is this a known GOT slot?
                        if got_va in KNOWN_GOT:
                            name, desc, expected = KNOWN_GOT[got_va]
                            annotation = f"; {dst_reg} = *({name}@0x{got_va:x}) = 0x{target:x} ({desc})"
                            if target and target != expected:
                                annotation += f" [EXPECT 0x{expected:x}]"
                        elif target:
                            annotation = f"; {dst_reg} = *(0x{got_va:x}) = 0x{target:x}"
                        else:
                            annotation = f"; {dst_reg} = *(0x{got_va:x}) = ???"
                    except:
                        pass
                elif len(src_parts) == 1:
                    # ldr xN, [xM] -- could be vtable load!
                    base_reg = src_parts[0]
                    if base_reg.startswith('x'):
                        annotation = f"; {dst_reg} = *({base_reg}) [vtable?]"

    # BLR: indirect call
    elif mnem == 'blr':
        reg = ops.strip()
        blr_sites.append((addr, reg))
        annotation = f"; >>> BLR {reg} (indirect call)"

    # BL: direct call
    elif mnem == 'bl':
        try:
            target = int(ops.replace('#', ''), 0)
            annotation = f"; call 0x{target:x}"
        except:
            annotation = f"; call {ops}"

    # B.cond: conditional branch
    elif mnem.startswith('b.'):
        try:
            target = int(ops.replace('#', ''), 0)
            direction = "forward" if target > addr else "backward"
            annotation = f"; branch {direction} to 0x{target:x}"
        except:
            annotation = f"; branch to {ops}"

    # B: unconditional branch
    elif mnem == 'b':
        try:
            target = int(ops.replace('#', ''), 0)
            annotation = f"; jump to 0x{target:x}"
        except:
            annotation = f"; jump to {ops}"

    # RET
    elif mnem == 'ret':
        annotation = "; <<< RETURN >>>"

    # STR: memory write
    elif mnem.startswith('str'):
        annotation = f"; *** WRITE ***"

    # STRB: byte write
    elif mnem.startswith('strb'):
        annotation = f"; *** BYTE WRITE ***"

    # Print
    line = f"  0x{addr:07x}: {mnem:10s} {ops}"
    if annotation:
        line += f"  {annotation}"
    print(line)

    # Stop at RET after enough instructions
    if mnem == 'ret':
        print("  --- function end ---")
        break

# Summary
print("\n" + "=" * 70)
print("BLR (indirect call) sites summary:")
print("=" * 70)
for addr, reg in blr_sites:
    print(f"  0x{addr:07x}: BLR {reg}")

print(f"\nTotal BLR sites: {len(blr_sites)}")
print("\nNext step: For each BLR, determine if it's GOT-based or vtable-based")
print("  - GOT-based: preceded by ADRP + LDR (resolved to function pointer)")
print("  - vtable-based: preceded by LDR from object pointer (LDR Xn, [Xobj])")
