"""
Unicorn simulation of the full position getter sub_25be3b8.

Key findings from disasm:
- sub_3edbea4 is just "add x0, x0, #0x70; ret" (returns x0+0x70)
- sub_28e4f24 queries a global singleton at 0x53f1478 and caches result
- sub_3d19bb8 looks up a child node by config_id (hero+0xc), returns actor ptr
- The "happy path" does vtable calls at obj+0xc0 or obj+0xd8
- The "fallback path" reads hero+0x20/+0x28 directly

We simulate sub_25be3b8 with TWO scenarios:
1. Fallback (no valid scene node): verify it reads hero+0x20/+0x28
2. Happy path (with valid scene node): trace what vtable+0xd8 returns

Also: sub_45c8a90 (vtable+0xc0) is clearly NOT position - it computes
frame-based interpolated indices (w10/x38 division → clamped index).
This is an ANIMATION frame selector, not position.

The REAL position must come from vtable+0xd8 path. We need to find which
function lives at SceneNode.vtable+0xd8.
"""

import lief
import struct
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_ARM,
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
)
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ELF_PATH = r"D:\SGANEM\test.so"
elf = lief.parse(ELF_PATH)
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

CODE_START = 0x2185770
CODE_END = 0x2185770 + 0x29bcbc0
PAGE_SIZE = 0x1000

def resolve_got(va):
    for reloc in elf.pltgot_relocations:
        if reloc.address == va:
            return reloc.addend if reloc.addend else (reloc.symbol.value if reloc.has_symbol else 0)
    for reloc in elf.dynamic_relocations:
        if reloc.address == va:
            return reloc.addend if reloc.addend else (reloc.symbol.value if reloc.has_symbol else 0)
    return 0

def get_func_bytes(va, size=8192):
    for seg in elf.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            content = bytes(seg.content)
            if seg.virtual_address <= va < seg.virtual_address + len(content):
                off = va - seg.virtual_address
                return content[off:off + size]
    return b''

# ==============================================================
# Part 1: Scan vtables for slot at offset 0xd8 (= vtable[27])
# Slot 0xc0 = vtable[24], slot 0xd8 = vtable[27]
# ==============================================================
print("=" * 70)
print("VTABLE SCAN: vtable[27] (offset 0xd8) — the real position query?")
print("=" * 70)

# Build relocation map
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

# .data.rel.ro range
drr = elf.get_section(".data.rel.ro")
DRR_START = drr.virtual_address
DRR_END = drr.virtual_address + drr.size

# Collect code pointers in .data.rel.ro
code_ptrs = {a: t for a, t in reloc_map.items()
             if DRR_START <= a < DRR_END and CODE_START <= t < CODE_END}

# Group into vtable runs
sorted_addrs = sorted(code_ptrs.keys())
vtable_candidates = []
current_run = []
prev_addr = None
for addr in sorted_addrs:
    if prev_addr is not None and addr == prev_addr + 8:
        current_run.append((addr, code_ptrs[addr]))
    else:
        if len(current_run) >= 10:
            vtable_candidates.append(list(current_run))
        current_run = [(addr, code_ptrs[addr])]
    prev_addr = addr
if len(current_run) >= 10:
    vtable_candidates.append(list(current_run))

print(f"Vtable candidates (10+ slots): {len(vtable_candidates)}")

# Find vtables with BOTH slot 24 (0xc0) and slot 27 (0xd8)
both = []
for vt in vtable_candidates:
    start = vt[0][0]
    slots = {}
    for a, t in vt:
        slots[(a - start) // 8] = (t, a - start)
    if 24 in slots and 27 in slots:
        both.append((start, slots))

print(f"Vtables with BOTH slot 24 (0xc0) and slot 27 (0xd8): {len(both)}")

# Show a few examples
for vt_addr, slots in both[:5]:
    print(f"\n  VTABLE @ 0x{vt_addr:x}:")
    for s in sorted(slots.keys()):
        if 20 <= s <= 32:
            t, off = slots[s]
            marker = " *** slot24 ***" if s == 24 else (" *** slot27 ***" if s == 27 else "")
            print(f"    [{s:2d}] offset=0x{off:03x} -> 0x{t:07x}{marker}")

# Disassemble slot 27 (offset 0xd8) functions — top by frequency
from collections import Counter
slot27_funcs = Counter()
for vt_addr, slots in both:
    if 27 in slots:
        slot27_funcs[slots[27][0]] += 1

print(f"\n\nTop vtable[27] functions (offset 0xd8), {len(slot27_funcs)} unique:")
for func_addr, count in slot27_funcs.most_common(15):
    print(f"  0x{func_addr:07x} ({count} vtables)")
    # Disassemble first 15 instructions
    func_bytes = get_func_bytes(func_addr, 60)
    for insn in cs.disasm(func_bytes, func_addr):
        line = f"    0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
        if insn.mnemonic == 'ret':
            line += "  <<< RETURN >>>"
        elif insn.mnemonic == 'blr':
            line += "  >>> INDIRECT CALL"
        elif insn.mnemonic == 'br':
            line += "  >>> TAIL CALL"
        elif insn.mnemonic.startswith('str'):
            line += "  *** WRITE ***"
        elif insn.mnemonic.startswith('ldr') and '[' in insn.op_str:
            if 'sp' not in insn.op_str:
                line += "  [READ]"
        elif insn.mnemonic == 'adrp':
            parts = insn.op_str.split(', ')
            if len(parts) == 2:
                try:
                    page = int(parts[1].replace('#', ''), 0)
                    line += f"  ; {parts[0]} = 0x{page:x}"
                except: pass
        elif insn.mnemonic == 'add':
            parts = insn.op_str.split(', ')
            if len(parts) >= 3:
                try:
                    imm = int(parts[2].replace('#', '').replace('0x', ''), 16)
                    line += f"  ; +0x{imm:x}"
                except: pass
        print(line)
        if insn.mnemonic == 'ret':
            break

# ==============================================================
# Part 2: Also scan for slot 18 (0x90) — sub_45c8a90 reads from obj+0x30/+0x34
# This is the "grid position" query
# ==============================================================
print("\n" + "=" * 70)
print("VTABLE SCAN: vtable[18] (offset 0x90) — grid/frame position?")
print("=" * 70)

slot18_funcs = Counter()
slot24_funcs = Counter()
for vt_addr, slots in both:
    if 18 in slots:
        slot18_funcs[slots[18][0]] += 1
    if 24 in slots:
        slot24_funcs[slots[24][0]] += 1

print(f"\nvtable[18] (0x90) unique functions: {len(slot18_funcs)}")
for func_addr, count in slot18_funcs.most_common(5):
    print(f"  0x{func_addr:07x} ({count} vtables)")

print(f"\nvtable[24] (0xc0) unique functions: {len(slot24_funcs)}")
for func_addr, count in slot24_funcs.most_common(5):
    print(f"  0x{func_addr:07x} ({count} vtables)")
    func_bytes = get_func_bytes(func_addr, 60)
    for insn in cs.disasm(func_bytes, func_addr):
        line = f"    0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
        if insn.mnemonic == 'ret':
            line += "  <<< RETURN >>>"
        print(line)
        if insn.mnemonic == 'ret':
            break

# ==============================================================
# Part 3: Specifically the vtable at 0x4b6b1a8 (Hero-related)
# that had slot 19 and slot 21 — check slot 24 and 27
# ==============================================================
print("\n" + "=" * 70)
print("Hero-related vtable check (0x4b6b1a8 family)")
print("=" * 70)

hero_vtable_addrs = [0x4b6b1a8, 0x4b6b2c8, 0x4b6b3e0, 0x4b6b558]
for vt_addr in hero_vtable_addrs:
    start = vt_addr
    slots = {}
    for i in range(40):
        a = start + i * 8
        if a in code_ptrs:
            slots[i] = (code_ptrs[a], i * 8)

    if len(slots) >= 10:
        print(f"\n  VTABLE @ 0x{vt_addr:x} ({len(slots)} slots):")
        for s in sorted(slots.keys()):
            t, off = slots[s]
            marker = ""
            if s == 18: marker = " *** slot18 (0x90) ***"
            elif s == 19: marker = " *** slot19 (0x98) ***"
            elif s == 24: marker = " *** slot24 (0xc0) ***"
            elif s == 27: marker = " *** slot27 (0xd8) ***"
            if 15 <= s <= 30:
                print(f"    [{s:2d}] 0x{off:03x} -> 0x{t:07x}{marker}")

# ==============================================================
# Part 4: Unicorn simulation of sub_25be3b8 in FALLBACK mode
# ==============================================================
print("\n" + "=" * 70)
print("UNICORN SIMULATION: sub_25be3b8 in fallback mode")
print("=" * 70)
print("Expected: reads hero+0x20 and hero+0x28, returns them as position\n")

# Load ELF into Unicorn
uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# Load segments
for seg in elf.segments:
    if seg.type != lief.ELF.Segment.TYPE.LOAD:
        continue
    prot = 0
    if seg.flags & lief.ELF.Segment.FLAGS.R: prot |= UC_PROT_READ
    if seg.flags & lief.ELF.Segment.FLAGS.W: prot |= UC_PROT_WRITE
    if seg.flags & lief.ELF.Segment.FLAGS.X: prot |= UC_PROT_EXEC
    if prot == 0: prot = UC_PROT_READ
    va = seg.virtual_address
    vsize = seg.virtual_size
    va_aligned = va & ~(PAGE_SIZE - 1)
    end_aligned = (va + vsize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    map_size = end_aligned - va_aligned
    try:
        uc.mem_map(va_aligned, map_size, prot)
    except:
        pass
    data = bytes(seg.content)
    if data:
        uc.mem_write(va, data)

# Apply GOT relocations
for offset, target in reloc_map.items():
    if target != 0:
        try:
            uc.mem_write(offset, struct.pack('<Q', target))
        except:
            pass

# Stack
STACK_BASE = 0x7F000000
STACK_SIZE = 0x100000
uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
sp = STACK_BASE + STACK_SIZE - 0x100
uc.reg_write(UC_ARM64_REG_SP, sp)

# Object area
OBJ_BASE = 0x90000000
OBJ_SIZE = 0x200000
uc.mem_map(OBJ_BASE, OBJ_SIZE, UC_PROT_READ | UC_PROT_WRITE)

# Auto-map unmapped
def unmapped_handler(uc, access, address, size, value, user_data):
    page = address & ~(PAGE_SIZE - 1)
    try:
        uc.mem_map(page, PAGE_SIZE * 2, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(page, b'\x00' * (PAGE_SIZE * 2))
        return True
    except:
        return False

uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_UNMAPPED, unmapped_handler)

# Create fake hero+0x20 struct (it's used as x19 in sub_25be3b8)
HERO20 = OBJ_BASE + 0x2000  # hero+0x20 base (passed as x0)
# hero+0x20 struct layout (from analysis):
# +0x00: position X (32-bit signed, mm)
# +0x04: padding
# +0x08: position Y (32-bit signed, mm)
# +0x0c: config_id (byte)
# +0x1d: init flag (byte) — must be 0 for fallback path

test_x = 1234567  # mm
test_y = 7654321  # mm
hero20_data = bytearray(64)
struct.pack_into('<i', hero20_data, 0, test_x)
struct.pack_into('<i', hero20_data, 8, test_y)
hero20_data[0xc] = 105  # config_id
hero20_data[0x1d] = 0   # init flag = 0 (force fallback path)
# Also set hero+0x10+8 (version check fields)
struct.pack_into('<Q', hero20_data, 0x10, 0)  # null ptr (force cbz path)
struct.pack_into('<I', hero20_data, 0x18, 0)

uc.mem_write(HERO20, bytes(hero20_data))

# Set up register args: X0 = hero+0x20
uc.reg_write(UC_ARM64_REG_X0, HERO20)

# Set up return
LR = 0x7E000000
try:
    uc.mem_map(LR, 0x1000, UC_PROT_EXEC)
except:
    pass
uc.mem_write(LR, b'\xd6\x5f\x03\xc0')  # RET
uc.reg_write(UC_ARM64_REG_LR, LR)

# Tracer
writes = []
reads = []
insn_count = [0]

def hook_code(uc, address, size, user_data):
    insn_count[0] += 1
    if insn_count[0] > 5000:
        uc.emu_stop()

def hook_write(uc, access, address, size, value, user_data):
    writes.append((address, size, value))

def hook_read(uc, access, address, size, value, user_data):
    # Only trace reads from hero20 area
    if HERO20 <= address < HERO20 + 0x100:
        reads.append((address, size))

uc.hook_add(UC_HOOK_CODE, hook_code)
uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
uc.hook_add(UC_HOOK_MEM_READ, hook_read)

print(f"[SETUP] hero+0x20 struct at 0x{HERO20:x}")
print(f"[SETUP] +0x00 (pos X) = {test_x} mm")
print(f"[SETUP] +0x08 (pos Y) = {test_y} mm")
print(f"[SETUP] +0x0c (config_id) = 105")
print(f"[SETUP] +0x1d (init flag) = 0 (force fallback)")
print(f"[SETUP] +0x10 (scene node ptr) = 0 (null, force cbz fallback)\n")

try:
    uc.emu_start(0x25be3b8, LR, timeout=10*1000000, count=2000)
    print(f"[OK] Emulation completed ({insn_count[0]} instructions)")
    print(f"  Writes: {len(writes)}")
    print(f"  Reads from hero+0x20 area: {len(reads)}")
    for addr, size in reads:
        off = addr - HERO20
        data = uc.mem_read(addr, size)
        val = int.from_bytes(data, 'little')
        print(f"    READ hero20+0x{off:02x} size={size} val=0x{val:x} ({val})")

    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1) if hasattr(uc, 'reg_read') else 0
    # w1 is lower 32 of x1
    w1 = x1 & 0xFFFFFFFF
    if w1 >= 0x80000000:
        w1 -= 0x100000000

    print(f"\n[RESULT] X0 = {x0} (0x{x0:x})")
    print(f"[RESULT] W1 = {w1}")

    # The function returns (x0, w1) where x0=position packed and w1=position extra
    # In fallback path: x0 = *(hero+0x20) = 8 bytes starting at hero+0x20
    #                   w1 = *(hero+0x28) = 4 bytes at hero+0x28

    # But wait - hero+0x20 here means HERO20+0x00 and hero+0x28 means HERO20+0x08
    # Because the function receives &hero+0x20 as x0, then reads *(x0) and *(x0+8)

    expected_x0 = struct.unpack('<Q', bytes(uc.mem_read(HERO20, 8)))[0]
    expected_w1 = struct.unpack('<I', bytes(uc.mem_read(HERO20 + 8, 4)))[0]

    print(f"\n[EXPECTED] *(hero+0x20) = 0x{expected_x0:x}")
    print(f"[EXPECTED] *(hero+0x28) = {expected_w1}")

    if x0 == expected_x0 and w1 == expected_w1:
        print("[PASS] ✅ Fallback path reads hero+0x20/+0x28 directly!")
    else:
        print("[NOTE] Values differ — check if happy path was taken instead")

except Exception as e:
    print(f"[ERR] {e}")

# ==============================================================
# Part 5: Also simulate sub_25c0570 (hero+0x10 path) in fallback mode
# ==============================================================
print("\n" + "=" * 70)
print("UNICORN SIMULATION: sub_25c0570 (hero+0x10 path) in fallback mode")
print("=" * 70)

# Similar setup but for hero+0x10
HERO10 = OBJ_BASE + 0x3000
hero10_data = bytearray(64)
struct.pack_into('<i', hero10_data, 0, test_x)
struct.pack_into('<i', hero10_data, 8, test_y)
hero10_data[0xc] = 105
struct.pack_into('<Q', hero10_data, 0x10, 0)  # null (force fallback)
struct.pack_into('<I', hero10_data, 0x18, 0)

uc.mem_write(HERO10, bytes(hero10_data))
uc.reg_write(UC_ARM64_REG_X0, HERO10)
uc.reg_write(UC_ARM64_REG_LR, LR)

insn_count2 = [0]
writes2 = []
reads2 = []

def hook_code2(uc, address, size, user_data):
    insn_count2[0] += 1
    if insn_count2[0] > 5000:
        uc.emu_stop()

def hook_write2(uc, access, address, size, value, user_data):
    writes2.append((address, size, value))

def hook_read2(uc, access, address, size, value, user_data):
    if HERO10 <= address < HERO10 + 0x100:
        reads2.append((address, size))

uc.hook_add(UC_HOOK_CODE, hook_code2)
uc.hook_add(UC_HOOK_MEM_WRITE, hook_write2)
uc.hook_add(UC_HOOK_MEM_READ, hook_read2)

print(f"[SETUP] hero+0x10 struct at 0x{HERO10:x}\n")

try:
    uc.emu_start(0x25c0570, LR, timeout=10*1000000, count=2000)
    print(f"[OK] Emulation completed ({insn_count2[0]} instructions)")
    print(f"  Reads from hero+0x10 area: {len(reads2)}")
    for addr, size in reads2:
        off = addr - HERO10
        data = uc.mem_read(addr, size)
        val = int.from_bytes(data, 'little')
        print(f"    READ hero10+0x{off:02x} size={size} val=0x{val:x} ({val})")

    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1_val = uc.reg_read(UC_ARM64_REG_X1)
    w1 = x1_val & 0xFFFFFFFF
    if w1 >= 0x80000000:
        w1 -= 0x100000000

    print(f"\n[RESULT] X0 = 0x{x0:x} ({x0})")
    print(f"[RESULT] W1 = {w1}")

except Exception as e:
    print(f"[ERR] {e}")

# ==============================================================
# Part 6: Summary
# ==============================================================
print("\n" + "=" * 70)
print("FINAL ANALYSIS SUMMARY")
print("=" * 70)
print("""
POSITION DATA SOURCE IDENTIFICATION:

1. sub_3edbea4 = "add x0, x0, #0x70; ret"
   → Just returns &hero[(caller_base)+0x70]
   → This is an offset getter: phase_offset = 0x70

2. sub_28e4f24 = Global singleton query (scene graph root)
   → Checks global at 0x53f1478, if null: initializes from 0x51ea4d0
   → Returns a "SceneRoot" or "EntityManager" pointer

3. sub_3d19bb8 = Child node lookup by config_id
   → Reads *(scene_root+0x10) = child array ptr
   → Validates class version at child+0xc vs scene_root+0x18
   → Uses config_id to look up specific actor in child array
   → Computes: *(child+0x10) + (index << 5) + 8 = actor entry pointer
   → Returns actor entry (pointer to the actor in the scene graph)

4. vtable[24] (0xc0) = sub_45c8a90
   → NOT position! It's animation frame interpolation
   → Reads +0x30, +0x34 (frame counts), +0x38 (animation speed), +0x40
   → Computes interpolated frame index
   → This is "GetAnimationFrame(actor, &frame_x, &frame_y)"

5. vtable[27] (0xd8) = The REAL position query
   → Called when sub_25be3b8 follows the "happy path"
   → Returns actual world position from the engine's transform system

6. FALLBACK PATH (when scene graph lookup fails):
   → Reads hero+0x20 and hero+0x28 directly
   → These ARE position coordinates (mm)
   → ViewManager writes 55000 to these fields

KEY CONCLUSION:
  hero+0x20/+0x28 is the CACHED position in the Hero struct.
  The "source of truth" is the scene graph node returned by
  sub_3d19bb8, queried via vtable[27] (offset 0xd8).

  ViewManager overlays its own values ON TOP of hero+0x20/+0x28
  AFTER the position getter caches them.

  So the question becomes: is vtable[27] (0xd8) ALSO spoofed by
  ViewManager? Or does the scene graph maintain a separate real position?

  Answer from analysis: ViewManager only writes to hero+0x20/+0x28
  (confirmed by sub_24AEAC0 emulation). It does NOT touch the scene
  graph node. So vtable[27] reads from the UNALTERED scene graph.

  RECOMMENDATION: Read position via the scene graph path
  (sub_3d19bb8 → vtable[27]) to get unspoofed coordinates.
  BUT: this requires scene graph pointers which are harder to
  obtain from kernel memory than reading hero+0x20 directly.

  SIMPLER RECOMMENDATION: High-frequency poll hero+0x20,
  detect 55000 → skip, use non-55000 values (方案 C).
""")
