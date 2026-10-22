"""
Vtable reconstruction from R_AARCH64_RELATIVE relocations.

In shared libraries, .data.rel.ro is populated at load time by the
dynamic linker via RELATIVE relocations. The file bytes are zero,
but the relocation entries contain the actual target addresses.

We reconstruct vtables by:
1. Collecting all R_AARCH64_RELATIVE relocations targeting .data.rel.ro
2. Grouping consecutive relocated pointers into vtable candidates
3. Checking which candidates have code pointers at offsets 0x98 and 0xA8
   (vtable slots 19 and 21 -- the mystery functions)
"""

import lief
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from collections import defaultdict

ELF_PATH = r"D:\SGANEM\test.so"
elf = lief.parse(ELF_PATH)

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

# Code segment range
CODE_START = 0x2185770
CODE_END = 0x2185770 + 0x29bcbc0

# Build relocation map: address -> target (addend for RELATIVE relocs)
reloc_map = {}
for reloc in elf.pltgot_relocations:
    addr = reloc.address
    if reloc.addend:
        reloc_map[addr] = reloc.addend
    elif reloc.has_symbol and reloc.symbol.value:
        reloc_map[addr] = reloc.symbol.value

for reloc in elf.dynamic_relocations:
    addr = reloc.address
    if reloc.addend:
        reloc_map[addr] = reloc.addend
    elif reloc.has_symbol and reloc.symbol.value:
        reloc_map[addr] = reloc.symbol.value

print(f"Total relocations: {len(reloc_map)}")

# .data.rel.ro range
drr = elf.get_section(".data.rel.ro")
DRR_START = drr.virtual_address if drr else 0x4B43330
DRR_END = (drr.virtual_address + drr.size) if drr else 0x4FF2E70
print(f".data.rel.ro: 0x{DRR_START:x} - 0x{DRR_END:x}")

# Collect all relocations within .data.rel.ro
drr_relocs = {}
for addr, target in reloc_map.items():
    if DRR_START <= addr < DRR_END:
        drr_relocs[addr] = target

print(f"Relocations in .data.rel.ro: {len(drr_relocs)}")

# Count how many targets are code pointers
code_ptrs = {a: t for a, t in drr_relocs.items() if CODE_START <= t < CODE_END}
print(f"Code pointers in .data.rel.ro: {len(code_ptrs)}")

# Group consecutive relocated pointers into vtable candidates
# A vtable is a consecutive array of function pointers
# Group by "8-byte consecutive" addresses
sorted_addrs = sorted(code_ptrs.keys())

# Build runs of consecutive 8-byte aligned pointers
vtable_candidates = []
current_run = []
prev_addr = None

for addr in sorted_addrs:
    if prev_addr is not None and addr == prev_addr + 8:
        current_run.append((addr, code_ptrs[addr]))
    else:
        if len(current_run) >= 3:
            vtable_candidates.append(list(current_run))
        current_run = [(addr, code_ptrs[addr])]
    prev_addr = addr

if len(current_run) >= 3:
    vtable_candidates.append(list(current_run))

print(f"\nVtable candidates (3+ consecutive code pointers): {len(vtable_candidates)}")

# Filter: vtables with entries at offsets 0x98 (slot 19) and/or 0xA8 (slot 21)
# Offset = relative to vtable start
# slot 19 = offset 19*8 = 0x98 = 152
# slot 21 = offset 21*8 = 0xA8 = 168

# But wait -- ARM64 vtable calls use LDR X8, [X0, #offset]
# where offset is the BYTE offset from the vtable base.
# So LDR X8, [X0, #0x98] means slot at byte offset 0x98 = 152
# which is slot 19 (152/8 = 19)
# And LDR X8, [X0, #0xA8] means byte offset 0xA8 = 168
# which is slot 21 (168/8 = 21)

# BUT: in the disassembly of sub_3EE11B8, the actual vtable calls are:
#   0x3ee12b4: ldr  x8, [x8, #0x98]   ; vtable[19] -- wait, x8 was loaded from *(x0) first!
#   0x3ee12ec: ldr  x8, [x8, #0xa8]   ; vtable[21] -- same pattern
#
# Looking at the actual code:
#   0x3ee12a8: ldr  x0, [x0]           ; x0 = *(x0) = vtable ptr from object
#   0x3ee12b0: ldr  x8, [x0]            ; x8 = *(x0) = ??
#   0x3ee12b4: ldr  x8, [x8, #0x98]    ; x8 = *(x8 + 0x98)
#   0x3ee12b8: blr  x8
#
# Wait, that's a DOUBLE indirection! *(x0) then *(x0) then *(x8+0x98)
# Let me re-read:
#   0x3ee12a4: blr x8    ; calls get_physics_subcomp -> returns sub-obj in X0
#   0x3ee12a8: ldr x0, [x0]    ; X0 = *(sub-obj+0) = vtable ptr of sub-obj
#   0x3ee12ac: mov w1, w20    ; w1 = arg (frame number)
#   0x3ee12b0: ldr x8, [x0]    ; X8 = *(vtable+0) = ??
#   0x3ee12b4: ldr x8, [x8, #0x98]  ; X8 = *(vtable[0]+0x98)
#   0x3ee12b8: blr x8
#
# Hmm, that's THREE levels of indirection:
#   sub-obj → *(sub-obj+0) = vtable_base
#   vtable_base → *(vtable_base+0) = ??? (might be RTTI or second-level table)
#   ??? → *(???+0x98) = function?
#
# OR maybe:
#   ldr x0, [x0]  = read first field of returned object (might be object, not vtable)
#   ldr x8, [x0]  = read first field of THAT object (vtable ptr)
#   ldr x8, [x8, #0x98]  = read function from vtable+0x98
#
# Second interpretation makes more sense:
#   get_physics_subcomp returns a pointer to physics sub-component
#   physics_subcomp->vtable = *(physics_subcomp+0)
#   vtable = *(physics_subcomp+0)
#   Hmm no, it's:
#   x0 = *(returned_obj+0) = some_inner_obj_ptr
#   x8 = *(some_inner_obj+0) = vtable_of_inner_obj
#   x8 = *(vtable + 0x98) = vtable[19] function pointer
#
# Wait, that doesn't make sense either. Let me look again:
#
#   0x3ee12a4: blr  x8  ; call get_physics_subcomp(MovementComponent+0x50=....)
#   0x3ee12a8: ldr  x0, [x0]           ; x0 was return value = sub-comp ptr
#                                      ; x0 = *(sub-comp+0) = hmm
#   0x3ee12ac: mov  w1, w20
#   0x3ee12b0: ldr  x8, [x0]           ; x8 = *(x0+0)
#   0x3ee12b4: ldr  x8, [x8, #0x98]   ; x8 = *(x8+0x98)
#   0x3ee12b8: blr  x8
#
# OK so: get_physics_subcomp returns some ptr in X0.
# Then: X0 = *X0 = dereference it (get first field)
# Then: X8 = *X0 = dereference again (get first field of first field)
# Then: X8 = *(X8 + 0x98) = read offset 0x98 from this object
# Then: call X8
#
# This looks like: sub-comp → sub-comp[0] (vtable) → sub-comp[0][0] (RTTI?) → sub-comp[0][0][0x98]
# That doesn't make sense.
#
# OR: get_physics_subcomp returns a HANDLER/object pointer.
#     handler->field_0 = inner_obj_ptr
#     inner_obj->vtable = *(inner_obj+0)
#     *(vtable+0x98) = function pointer (vtable slot 19)
#
# That's: handler.field0 is the actual physics object, and we call
# physics_obj.vtable.slot_19(frame_number)
#
# So the vtable layout is standard: vtable at obj+0, slots at vtable+N*8

# Let's try: vtable slot 0x98 bytes from vtable base = slot 0x98/8 = slot 19
# Since ARM64 vtable doesn't have RTTI offset at [−2] in the same way...
# A vtable at address V:
#   V+0x00 = slot 0
#   V+0x08 = slot 1
#   V+0x98 = slot 19 (0x98/8 = 19)
#   V+0xA8 = slot 21 (0xA8/8 = 21)
#
# So our original scan was correct. The problem was the file bytes are zero.
# Now with relocations, let's find vtables with slots at 0x98 and 0xA8.

# For each vtable candidate, check if it extends far enough to have slots at 0x98 and 0xA8
both_slots = []
has_slot19 = []
has_slot21 = []

for vt in vtable_candidates:
    start_addr = vt[0][0]
    # Build slot map: slot_index -> function_addr
    slots = {}
    for addr, target in vt:
        offset = addr - start_addr
        slot = offset // 8
        slots[slot] = (target, offset)

    if 19 in slots and 21 in slots:
        both_slots.append((start_addr, slots))
    if 19 in slots:
        has_slot19.append((start_addr, slots))
    if 21 in slots:
        has_slot21.append((start_addr, slots))

print(f"\nVtables with slot 19: {len(has_slot19)}")
print(f"Vtables with slot 21: {len(has_slot21)}")
print(f"Vtables with BOTH 19 and 21: {len(both_slots)}")

# Print vtables with both slots
print("\n" + "=" * 70)
print("Vtables with BOTH slot 19 (0x98) and slot 21 (0xA8)")
print("=" * 70)

for vt_addr, slots in both_slots[:30]:
    print(f"\n  VTABLE @ 0x{vt_addr:x} (slots {min(slots.keys())}-{max(slots.keys())}):")
    for s in sorted(slots.keys()):
        target, offset = slots[s]
        marker = " *** VT[19] ***" if s == 19 else (" *** VT[21] ***" if s == 21 else "")
        print(f"    [{s:2d}] offset=0x{offset:03x} -> 0x{target:07x}{marker}")

    # Disassemble slot 19 and slot 21 functions (first 10 instructions each)
    for slot_num in [19, 21]:
        if slot_num in slots:
            func_addr = slots[slot_num][0]
            print(f"\n  --- VTABLE[{slot_num}] = 0x{func_addr:07x} (first 10 instructions):")
            # Read from loaded ELF
            for seg in elf.segments:
                if seg.type == lief.ELF.Segment.TYPE.LOAD:
                    if seg.virtual_address <= func_addr < seg.virtual_address + len(seg.content):
                        offset = func_addr - seg.virtual_address
                        content = bytes(seg.content)
                        func_bytes = content[offset:offset+40]
                        count = 0
                        for insn in cs.disasm(func_bytes, func_addr):
                            print(f"    0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}")
                            count += 1
                            if count >= 10 or insn.mnemonic == 'ret':
                                break
                        break

# Also list unique functions at slot 19 and slot 21
print("\n" + "=" * 70)
print("UNIQUE functions at vtable[19] across all vtables")
print("=" * 70)
unique_s19 = defaultdict(list)
for vt_addr, slots in has_slot19:
    if 19 in slots:
        unique_s19[slots[19][0]].append(vt_addr)
print(f"Unique functions: {len(unique_s19)}")
for func_addr, vt_addrs in sorted(unique_s19.items()):
    print(f"  0x{func_addr:07x} ({len(vt_addrs)} vtables)")

print("\n" + "=" * 70)
print("UNIQUE functions at vtable[21] across all vtables")
print("=" * 70)
unique_s21 = defaultdict(list)
for vt_addr, slots in has_slot21:
    if 21 in slots:
        unique_s21[slots[21][0]].append(vt_addr)
print(f"Unique functions: {len(unique_s21)}")
for func_addr, vt_addrs in sorted(unique_s21.items()):
    print(f"  0x{func_addr:07x} ({len(vt_addrs)} vtables)")

# ==============================================================
# Bonus: also check the SECOND vtable call path in sub_3EE11B8
#    0x3ee12d4: ldr  x0, [x19, #0x80]      ; x0 = *(MovementComponent+0x80)
#    0x3ee12d8: ldr  x8, [x8, #0x358]     ; GOT: off_519D358 = get_physics_subcomp
#    0x3ee12dc: blr  x8                     ; call get_physics_subcomp
#    0x3ee12e0: ldr  x0, [x0]              ; x0 = *(return+0)
#    0x3ee12e4: mov  w1, w20
#    0x3ee12e8: ldr  x8, [x0]              ; x8 = *(x0+0) = vtable
#    0x3ee12ec: ldr  x8, [x8, #0xa8]      ; x8 = *(vtable+0xa8) = vtable[21]
#    0x3ee12f0: blr  x8
#
# So vtable[21] is at offset 0xA8 from vtable base.
# And vtable[19] at 0x98.
# These are consistent.
# ==============================================================

# Print all vtable starts for reference
print("\n" + "=" * 70)
print(f"All vtable candidates ({len(vtable_candidates)} total):")
print("=" * 70)
for vt in vtable_candidates[:50]:
    start = vt[0][0]
    end = vt[-1][0]
    num_slots = len(vt)
    print(f"  0x{start:x}: {num_slots} slots (0x{start:x}-0x{end:x})")
if len(vtable_candidates) > 50:
    print(f"  ... ({len(vtable_candidates)} total)")
