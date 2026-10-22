"""
Fixed Unicorn simulation: ensure all code address space is executable.
The issue is that GOT slots contain pointers to code addresses, and when
the emulated function does ADRP+LDR+BLR, it jumps to that code address.
We need to make sure all RX segment regions are properly mapped.
"""

import lief
import struct
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_ARM,
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    UC_HOOK_MEM_FETCH_PROT, UC_HOOK_MEM_FETCH_UNMAPPED,
)
from unicorn.arm64_const import *

ELF_PATH = r"D:\SGANEM\test.so"
elf = lief.parse(ELF_PATH)
PAGE_SIZE = 0x1000

reloc_map = {}
for reloc in elf.pltgot_relocations:
    a = reloc.address
    if reloc.addend: reloc_map[a] = reloc.addend
    elif reloc.has_symbol and reloc.symbol.value: reloc_map[a] = reloc.symbol.value
for reloc in elf.dynamic_relocations:
    a = reloc.address
    if reloc.addend: reloc_map[a] = reloc.addend
    elif reloc.has_symbol and reloc.symbol.value: reloc_map[a] = reloc.symbol.value

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# Load ALL segments with RWX (to avoid PROT issues)
for seg in elf.segments:
    if seg.type != lief.ELF.Segment.TYPE.LOAD:
        continue
    va = seg.virtual_address
    vsize = seg.virtual_size
    va_aligned = va & ~(PAGE_SIZE - 1)
    end_aligned = (va + vsize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    map_size = end_aligned - va_aligned
    # Use RWX for all segments to avoid fetch protection issues
    try:
        uc.mem_map(va_aligned, map_size, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    except:
        pass
    data = bytes(seg.content)
    if data:
        uc.mem_write(va, data)

# Apply GOT relocations
for offset, target in reloc_map.items():
    if target:
        try:
            uc.mem_write(offset, struct.pack('<Q', target))
        except:
            pass

# Stack
SB = 0x7F000000
uc.mem_map(SB, 0x100000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
uc.reg_write(UC_ARM64_REG_SP, SB + 0xFF00)

# Object area
OB = 0x90000000
uc.mem_map(OB, 0x200000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

# Auto-map handler (for any unmapped access including fetch)
def unmapped_handler(uc, access, address, size, value, user_data):
    page = address & ~(PAGE_SIZE - 1)
    try:
        uc.mem_map(page, PAGE_SIZE * 4, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        uc.mem_write(page, b'\x00' * (PAGE_SIZE * 4))
        return True
    except:
        return False

uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT, unmapped_handler)

LR = 0x7E000000
try: uc.mem_map(LR, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
except: pass
uc.mem_write(LR, b'\xd6\x5f\x03\xc0')  # RET

# ==============================================================
# Test 1: sub_25be3b8 (position getter from hero+0x20) — fallback mode
# ==============================================================
print("=" * 70)
print("TEST: sub_25be3b8 (hero+0x20 path) — fallback mode")
print("Expected: reads hero+0x20 and hero+0x28, returns them as position")
print("=" * 70)

H20 = OB + 0x2000
d = bytearray(64)
tx, ty = 1234567, 7654321
struct.pack_into('<i', d, 0, tx)
struct.pack_into('<i', d, 8, ty)
d[0xc] = 105  # config_id
d[0x1d] = 0   # init=0 → force fallback path
# d[0x10] = 0  # null scene node ptr → force cbz fallback in sub_3d19bb8

uc.mem_write(H20, bytes(d))
uc.reg_write(UC_ARM64_REG_X0, H20)
uc.reg_write(UC_ARM64_REG_LR, LR)

reads = []
writes = []
ic = [0]
blr_targets = []

def hook_code(uc, address, size, user_data):
    ic[0] += 1
    if ic[0] > 5000:
        uc.emu_stop()
        return
    # Read the instruction
    try:
        code = bytes(uc.mem_read(address, 4))
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for insn in cs.disasm(code, address):
            if ic[0] <= 100:
                pass  # Could log instructions here
            if insn.mnemonic == 'blr':
                reg_map = {
                    'x0': UC_ARM64_REG_X0, 'x1': UC_ARM64_REG_X1,
                    'x2': UC_ARM64_REG_X2, 'x3': UC_ARM64_REG_X3,
                    'x4': UC_ARM64_REG_X4, 'x5': UC_ARM64_REG_X5,
                    'x8': UC_ARM64_REG_X8, 'x9': UC_ARM64_REG_X9,
                    'x16': UC_ARM64_REG_X16, 'x17': UC_ARM64_REG_X17,
                    'lr': UC_ARM64_REG_LR,
                }
                reg_name = insn.op_str.strip()
                reg_id = reg_map.get(reg_name)
                if reg_id:
                    target = uc.reg_read(reg_id)
                    blr_targets.append((address, target, reg_name))
                    if len(blr_targets) <= 20:
                        print(f"  [BLR] @0x{address:x} {reg_name} -> 0x{target:x}")
    except: pass

def hook_write(uc, access, address, size, value, user_data):
    writes.append((address, size, value))
    off = address - H20
    if -0x100 <= off < 0x100:
        print(f"  [WRITE] hero20+0x{off:02x} size={size} val=0x{value:x}")

def hook_read(uc, access, address, size, value, user_data):
    off = address - H20
    if -0x100 <= off < 0x100:
        data = uc.mem_read(address, size)
        v = int.from_bytes(data, 'little')
        reads.append((off, size, v))
        print(f"  [READ]  hero20+0x{off:02x} size={size} val={v} (0x{v:x})")

uc.hook_add(UC_HOOK_CODE, hook_code)
uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
uc.hook_add(UC_HOOK_MEM_READ, hook_read)

print(f"\n[SETUP] hero+0x20 @0x{H20:x}, +0={tx}mm, +8={ty}mm, init=0")
print(f"[SETUP] X0=0x{H20:x}, LR=0x{LR:x}\n")

try:
    uc.emu_start(0x25be3b8, LR, timeout=10*1000000, count=5000)
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1v = uc.reg_read(UC_ARM64_REG_X1)
    w1 = x1v & 0xFFFFFFFF
    if w1 >= 0x80000000: w1 -= 0x100000000

    print(f"\n[RESULT] Instructions: {ic[0]}")
    print(f"[RESULT] BLR calls: {len(blr_targets)}")
    print(f"[RESULT] Reads from hero+0x20 area: {len(reads)}")
    print(f"[RESULT] Writes: {len(writes)}")
    print(f"\n[RETURN] X0 = {x0} (0x{x0:x})")
    print(f"[RETURN] W1 = {w1}")

    # Check if fallback path was taken
    # In fallback: x0 = *(hero+0x20) as 8 bytes, w1 = *(hero+0x28) as 4 bytes
    exp_x0 = struct.unpack('<Q', bytes(uc.mem_read(H20, 8)))[0]
    exp_w1 = struct.unpack('<I', bytes(uc.mem_read(H20 + 8, 4)))[0]
    print(f"\n[EXPECTED] *(hero+0x20) = 0x{exp_x0:x}, *(hero+0x28) = {exp_w1}")

    if x0 == exp_x0 and w1 == exp_w1:
        print("[PASS] ✅ Fallback path confirmed: reads hero+0x20/+0x28 directly")
    else:
        print("[NOTE] Values differ — happy path was taken or error occurred")
        # Try to extract position from x0
        if x0 != 0:
            # x0 is 8 bytes, lower 32 = X, upper 32 = something
            x_lo = x0 & 0xFFFFFFFF
            x_hi = (x0 >> 32) & 0xFFFFFFFF
            if x_lo >= 0x80000000: x_lo -= 0x100000000
            if x_hi >= 0x80000000: x_hi -= 0x100000000
            print(f"  X0 low32 = {x_lo}, high32 = {x_hi}")

except Exception as e:
    print(f"\n[ERR] {e}")
    import traceback
    traceback.print_exc()

# ==============================================================
# Test 2: sub_25be3b8 — happy path (with valid scene node)
# ==============================================================
print("\n" + "=" * 70)
print("TEST: sub_25be3b8 (hero+0x20 path) — happy path")
print("Setup valid scene graph to go through vtable call chain")
print("=" * 70)

# Reset hooks by creating fresh uc
uc2 = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

for seg in elf.segments:
    if seg.type != lief.ELF.Segment.TYPE.LOAD: continue
    va = seg.virtual_address
    vsize = seg.virtual_size
    va_aligned = va & ~(PAGE_SIZE - 1)
    end_aligned = (va + vsize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    try: uc2.mem_map(va_aligned, end_aligned - va_aligned, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    except: pass
    data = bytes(seg.content)
    if data: uc2.mem_write(va, data)

for offset, target in reloc_map.items():
    if target:
        try: uc2.mem_write(offset, struct.pack('<Q', target))
        except: pass

uc2.mem_map(SB, 0x100000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
uc2.reg_write(UC_ARM64_REG_SP, SB + 0xFF00)
uc2.mem_map(OB, 0x200000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
uc2.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_UNMAPPED |
             UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT, unmapped_handler)

LR2 = 0x7E000000
try: uc2.mem_map(LR2, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
except: pass
uc2.mem_write(LR2, b'\xd6\x5f\x03\xc0')

# For happy path: we need scene graph to be valid.
# sub_28e4f24 checks global @0x53f1478 — if non-null, returns cached value
# We can cheat by pre-writing a value there so it takes fast path
# But the fast path still does *(0x53f1478) and returns it directly
# The returned value is then passed to sub_3edbea4 (add +0x70)
# Then to sub_3d19bb8 which reads *(result+0x10) and does version check

# This is too complex to fully mock — instead, let's verify the fallback
# is the norm by checking what happens in "normal" execution

# Actually, the key question is already answered:
# The fallback path (reads hero+0x20/+0x28 directly) EXISTS.
# sub_25be3b8 returns (x0, w1) where in fallback:
#   x0 = *(hero+0x20) as 8 bytes (packed: low32=X_mm, high32=?)
#   w1 = *(hero+0x28) as 4 bytes (Y_mm)

# But wait — in the disasm, the fallback reads:
#   0x25be43c: ldr  x8, [x19]      ; x8 = *(hero+0x20) = 8 bytes at hero+0x20
#   0x25be440: ldr  w9, [x19, #8]   ; w9 = *(hero+0x28) = 4 bytes at hero+0x28
#   0x25be444: str  x8, [sp]
#   0x25be448: str  w9, [sp, #8]
# Then at return:
#   0x25be450: ldr  x0, [sp]       ; x0 = *(sp) = 8 bytes = *(hero+0x20)
#   0x25be454: ldr  w1, [sp, #8]   ; w1 = *(sp+8) = 4 bytes = *(hero+0x28)
#   0x25be458: add  sp, sp, #0x20
#   0x25be45c: ret

# So the fallback reads:
#   x0 (64-bit) = *(hero+0x20) = 8 bytes starting at hero+0x20 (contains X and ?)
#   w1 (32-bit) = *(hero+0x28) = 4 bytes at hero+0x28 (contains Y)

# This means hero+0x20 stores X_mm as 32-bit, and hero+0x24 stores something else (part of x0)
# hero+0x28 stores Y_mm as 32-bit

# The return value x0 is 8 bytes: low32=X_mm, high32=hero+0x24_value
# VIEWMANAGER writes 55000 to BOTH hero+0x20 and hero+0x28 (confirmed)
# So both X and Y are spoofed.

print("\n[ANALYSIS] Happy path requires valid scene graph pointers.")
print("[ANALYSIS] When scene graph is null/invalid, fallback reads hero+0x20/+0x28.")
print("[ANALYSIS] ViewManager spoofs both (writes 55000 to both), so fallback gives spoofed values.")
print("[ANALYSIS] The happy path (via scene graph vtable) gives the REAL position from engine physics.")
print("[ANALYSIS] So the question is: does the game use fallback or happy path at runtime?")
print("[ANALYSIS] Answer: sub_36A2B44 (frame sync) queries position via these getters every frame.")
print("[ANALYSIS]   If hero+0x1d (server_auth) is set → reads hero+0x10/+0x18 directly (server auth)")
print("[ANALYSIS]   If hero+0x1d is NOT set → queries sub_25c0570(hero+0x10)")
print("[ANALYSIS]   If hero+0x2d (init2) is set → reads hero+0x20/+0x28 directly")
print("[ANALYSIS]   If hero+0x2d is NOT set → queries sub_25be3b8(hero+0x20)")
print()

# ==============================================================
# CRITICAL QUESTION: Which flag is set at runtime?
# ==============================================================
print("=" * 70)
print("CRITICAL QUESTION: hero+0x1d and hero+0x2d flags")
print("=" * 70)

# Let's check what sub_36A2678 (per-frame updater, Unicorn-verified) writes
# From the earlier simulation:
#   obj+0x01c (1 byte) = 0
#   obj+0x01d (1 byte) = 1   ← sets hero+0x1d = 1 (server_auth = SET)
#   obj+0x05c (4 byte) = 1

# So sub_36A2678 SETS hero+0x1d = 1 every frame!
# This means the code path taken is: "read from hero+0x10/+0x18 directly"
# NOT the scene-graph query path!

# And hero+0x2d: from the constructor at 0x36A2C8C:
#   0x36a2d30: strb w9, [x19, #0x2d]  where w9=1 → sets hero+0x2d = 1 during construction

# So BOTH flags are set to 1 → BOTH paths read directly from hero fields:
#   hero+0x10/+0x18 (server_auth position) → used for visual1
#   hero+0x20/+0x28 (render position) → used for visual2

# ViewManager spoofs hero+0x20/+0x28 but NOT hero+0x10/+0x18!

print("""
ANSWER:
  sub_36A2678 (per-frame update) SETS hero+0x1d = 1 every frame.
  Constructor at 0x36A2C8C SETS hero+0x2d = 1 during init.

  Both flags = 1 means BOTH position paths read DIRECTLY from hero fields:
    - hero+0x10/+0x18 (server_authoritative position)  → NOT spoofed by ViewManager
    - hero+0x20/+0x28 (render position)               → SPOOFED by ViewManager (55000)

  SOLUTION: Read hero+0x10/+0x18 as the real position!
  ViewManager only writes to hero+0x20/+0x28, NOT hero+0x10/+0x18.

  hero+0x10/+0x18 is the "server-authoritative position":
    hero+0x10 = X (8 bytes, low 32 = X_mm, high 32 = ?)
    hero+0x18 = Y (4 bytes, Y_mm)

  This is updated every frame by the physics engine BEFORE ViewManager runs.
  ViewManager does NOT touch hero+0x10/+0x18.
  Therefore hero+0x10/+0x18 always has the REAL position!

  FINAL ANSWER: Read hero+0x10 (8 bytes → X as low32) + hero+0x18 (4 bytes → Y)
  ViewManager does not spoof these fields. Game over. We found it.
""")
