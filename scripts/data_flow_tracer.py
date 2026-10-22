"""
Data Flow Tracer for libGameCore.so
====================================
Uses Unicorn to emulate critical functions and trace data flow through
virtual function calls (vtable[19]/vtable[21]) that IDA cannot statically resolve.

Key capabilities:
1. Vtable resolver: reads vtable from .data.rel.ro, resolves virtual call targets
2. Deep emulation: follow virtual calls automatically
3. Write tracking: identify ALL offsets written in a full function call chain
4. Pointer-chain emulation: trace Transform chain step by step
5. GOT slot resolution: resolve off_XXX pointers at runtime

This solves the core problem: "who writes hero+0x20 every frame?"
"""

import lief
import struct
import sys
from collections import defaultdict
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_ARM,
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_INSN, UC_HOOK_INTR,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
)
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

# Import the base emulator
sys.path.insert(0, r"D:\SGANEM")
from unicorn_emu import (
    ELFLoader, GOTResolver, MemoryTracer,
    create_emulator, alloc_obj, alloc_heap, write_val, setup_lr,
    PAGE_SIZE, ELF_PATH
)

# ==============================================================
# Capstone disassembler for instruction-level analysis
# ==============================================================
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True


# ==============================================================
# Vtable Resolver
# ==============================================================
class VtableResolver:
    """Resolve ARM64 virtual function calls by reading vtable from memory.

    ARM64 vtable call pattern:
      LDR X8, [X0]           ; X8 = vtable ptr (from object+0)
      LDR X9, [X8, #offset]   ; X9 = function ptr (from vtable+offset)
      BLR X9                   ; call function

    This resolver:
    1. Detects LDR + BLR pattern
    2. Reads object vtable pointer from Unicorn memory
    3. Reads function pointer from vtable
    4. Follows the call
    """

    def __init__(self, uc, loader, got):
        self.uc = uc
        self.loader = loader
        self.got = got
        self.call_chain = []
        self.max_depth = 10

    def read_ptr(self, va):
        """Read 8 bytes as pointer from Unicorn memory."""
        try:
            data = self.uc.mem_read(va, 8)
            return struct.unpack('<Q', data)[0]
        except:
            return 0

    def read_dword(self, va):
        """Read 4 bytes as unsigned 32-bit."""
        try:
            data = self.uc.mem_read(va, 4)
            return struct.unpack('<I', data)[0]
        except:
            return 0

    def resolve_vtable_call(self, obj_ptr, vtable_offset):
        """Resolve a virtual call: obj_ptr->vtable->vtable_offset.

        obj_ptr: pointer to object (vtable ptr is at obj+0)
        vtable_offset: byte offset into vtable (e.g., 0x98 for slot 19)

        Returns: function address or 0 if not resolvable
        """
        # Read vtable pointer from object
        vtable_ptr = self.read_ptr(obj_ptr)
        if vtable_ptr == 0:
            print(f"  [VTABLE] obj=0x{obj_ptr:x} -> vtable=0 (null!)")
            return 0

        # Read function pointer from vtable
        func_ptr = self.read_ptr(vtable_ptr + vtable_offset)
        print(f"  [VTABLE] obj=0x{obj_ptr:x} -> vtable=0x{vtable_ptr:x} +0x{vtable_offset:x} -> func=0x{func_ptr:x}")
        return func_ptr


# ==============================================================
# Deep Emulator -- follows virtual calls
# ==============================================================
class DeepEmulator:
    """Emulate functions and auto-follow virtual calls.

    When a BLR instruction is encountered and the target is a vtable-resolved
    function, automatically emulate that function too.
    """

    def __init__(self, uc, loader, got):
        self.uc = uc
        self.loader = loader
        self.got = got
        self.vt_resolver = VtableResolver(uc, loader, got)
        self.all_writes = []  # (va, size, value, call_depth)
        self.all_reads = []   # (va, size, value, call_depth)
        self.call_depth = 0
        self.max_depth = 5
        self.insn_count = 0
        self.max_insns = 100000
        self.call_stack = []
        self.hook_handles = []

        # Track which addresses we've visited to avoid loops
        self.visited = set()

        # Track GOT-based calls (off_XXX patterns)
        self.got_resolved = {}

        # BLR targets we've seen
        self.blr_targets = []

        # Instruction trace for analysis
        self.insn_trace = []

    def _hook_code(self, uc, address, size, user_data):
        self.insn_count += 1
        if self.insn_count > self.max_insns:
            print(f"  [!] Max instructions ({self.max_insns}), stopping")
            uc.emu_stop()
            return

        # Read 4 bytes of instruction
        try:
            code = bytes(uc.mem_read(address, 4))
        except:
            return

        # Disassemble
        instructions = list(cs.disasm(code, address))
        if not instructions:
            return

        insn = instructions[0]

        # Log BLR (branch to register) -- virtual call
        if insn.mnemonic == 'blr':
            reg_name = insn.op_str.strip()
            reg_map = {
                'x0': UC_ARM64_REG_X0, 'x1': UC_ARM64_REG_X1,
                'x2': UC_ARM64_REG_X2, 'x3': UC_ARM64_REG_X3,
                'x4': UC_ARM64_REG_X4, 'x5': UC_ARM64_REG_X5,
                'x6': UC_ARM64_REG_X6, 'x7': UC_ARM64_REG_X7,
                'x8': UC_ARM64_REG_X8, 'x9': UC_ARM64_REG_X9,
                'x10': UC_ARM64_REG_X10, 'x11': UC_ARM64_REG_X11,
                'x12': UC_ARM64_REG_X12, 'x13': UC_ARM64_REG_X13,
                'x14': UC_ARM64_REG_X14, 'x15': UC_ARM64_REG_X15,
                'x16': UC_ARM64_REG_X16, 'x17': UC_ARM64_REG_X17,
                'x18': UC_ARM64_REG_X18, 'x19': UC_ARM64_REG_X19,
                'x20': UC_ARM64_REG_X20, 'x21': UC_ARM64_REG_X21,
                'x22': UC_ARM64_REG_X22, 'x23': UC_ARM64_REG_X23,
                'x24': UC_ARM64_REG_X24, 'x25': UC_ARM64_REG_X25,
                'x26': UC_ARM64_REG_X26, 'x27': UC_ARM64_REG_X27,
                'x28': UC_ARM64_REG_X28, 'x29': UC_ARM64_REG_X29,
                'lr': UC_ARM64_REG_LR,
            }
            reg_id = reg_map.get(reg_name.lower())
            if reg_id:
                target = uc.reg_read(reg_id)
                self.blr_targets.append((address, target, reg_name))
                if self.insn_count <= 500:
                    print(f"  [BLR] @0x{address:x} {insn.mnemonic} {insn.op_str} -> 0x{target:x}")

        # Log STR (store) -- memory write
        if insn.mnemonic.startswith('str'):
            self.insn_trace.append(('str', address, insn.mnemonic, insn.op_str))

        # LDR from GOT-like pattern (ADRP + LDR)
        if insn.mnemonic == 'ldr' and 'x8' in insn.op_str.lower():
            pass  # could track vtable loads

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        self.all_writes.append((address, size, value, self.call_depth))
        val = value & ((1 << (size * 8)) - 1)
        if self.call_depth <= 2:
            print(f"  [W d{self.call_depth}] 0x{address:x} size={size} val=0x{val:x}")

    def _hook_mem_read(self, uc, access, address, size, value, user_data):
        self.all_reads.append((address, size, value, self.call_depth))

    def install_hooks(self):
        h1 = self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        h2 = self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        h3 = self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)
        self.hook_handles.extend([h1, h2, h3])

    def emulate_function(self, func_addr, args, obj_base=None, label=""):
        """Emulate a function with given arguments.

        args: dict of {UC_ARM64_REG_X0: value, ...}
        obj_base: base address for offset-relative write tracking
        label: description for logging
        """
        print(f"\n{'='*70}")
        print(f"[DEEP EMU] 0x{func_addr:x}: {label}")
        if obj_base:
            print(f"  obj_base = 0x{obj_base:x}")
        print(f"{'='*70}")

        # Reset tracking
        self.all_writes = []
        self.all_reads = []
        self.insn_count = 0
        self.blr_targets = []
        self.insn_trace = []

        # Set up registers
        for reg, val in args.items():
            self.uc.reg_write(reg, val)

        # Set up return address
        LR = setup_lr(self.uc)

        # Install hooks
        self.install_hooks()

        # Emulate
        try:
            self.uc.emu_start(func_addr, LR, timeout=10*1000000, count=self.max_insns)
            print(f"\n[OK] Emulation completed ({self.insn_count} instructions)")
        except Exception as e:
            print(f"\n[ERR] {e}")

        # Analyze results
        self.analyze_writes(obj_base)
        self.analyze_blr_targets()

        return {
            'writes': self.all_writes,
            'reads': self.all_reads,
            'blr_targets': self.blr_targets,
            'insn_count': self.insn_count,
        }

    def analyze_writes(self, obj_base=None):
        """Analyze all writes, group by offset relative to obj_base."""
        print(f"\n[ANALYSIS] Memory writes ({len(self.all_writes)} total):")

        if obj_base:
            obj_writes = defaultdict(list)
            other_writes = []

            for va, size, val, depth in self.all_writes:
                offset = va - obj_base
                if -0x2000 <= offset <= 0x2000:
                    obj_writes[offset].append((size, val, depth))
                else:
                    other_writes.append((va, size, val, depth))

            if obj_writes:
                print(f"\n  Writes to obj (base=0x{obj_base:x}):")
                for off in sorted(obj_writes.keys()):
                    for size, val, depth in obj_writes[off]:
                        sv = val & ((1 << (size * 8)) - 1)
                        sign_val = sv if sv < (1 << (size*8-1)) else sv - (1 << (size*8))
                        print(f"    obj+0x{off:03x} ({'signed' if sign_val != sv else 'unsigned'}): "
                              f"size={size} val=0x{sv:x} ({sign_val}) [depth={depth}]")

            if other_writes:
                print(f"\n  Writes to other addresses ({len(other_writes)} total):")
                # Group by depth
                for va, size, val, depth in other_writes[:50]:
                    sv = val & ((1 << (size * 8)) - 1)
                    print(f"    0x{va:x}: size={size} val=0x{sv:x} [depth={depth}]")
                if len(other_writes) > 50:
                    print(f"    ... ({len(other_writes)} total)")

        # Summary of unique offsets written
        offsets = set(va - obj_base if obj_base else va for va, _, _, _ in self.all_writes)
        print(f"\n  Unique write targets: {len(offsets)}")

    def analyze_blr_targets(self):
        """Analyze all BLR (virtual call) targets seen during emulation."""
        if not self.blr_targets:
            print("\n[ANALYSIS] No BLR (virtual calls) detected")
            return

        print(f"\n[ANALYSIS] BLR (virtual call) targets ({len(self.blr_targets)}):")
        unique_targets = set(t for _, t, _ in self.blr_targets)
        for target in sorted(unique_targets):
            count = sum(1 for _, t, _ in self.blr_targets if t == target)
            # Check if target is in code segment
            in_code = False
            for seg in self.loader.segments:
                if seg['va'] <= target < seg['va'] + seg['fsize'] and (seg['prot'] & UC_PROT_EXEC):
                    in_code = True
                    break
            seg_type = "CODE" if in_code else "DATA/UNKNOWN"
            print(f"  0x{target:x}: called {count}x ({seg_type})")

            # If in code, try to read first few instructions
            if in_code:
                try:
                    code = bytes(self.uc.mem_read(target, 16))
                    instructions = list(cs.disasm(code, target))
                    for ins in instructions[:4]:
                        print(f"    0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
                except:
                    pass


# ==============================================================
# GOT-based function resolver
# ==============================================================
class GOTFunctionResolver:
    """Resolve GOT-based function pointers (off_XXX pattern).

    ARM64 pattern:
      ADRP X8, #page
      LDR  X8, [X8, #offset]    ; X8 = *(GOT_SLOT)
      BLR  X8                    ; call indirect

    We can read the GOT slot from Unicorn memory (already resolved by create_emulator).
    """

    def __init__(self, uc, got):
        self.uc = uc
        self.got = got

    def resolve_got_slot(self, got_va):
        """Read the function pointer stored at a GOT slot."""
        try:
            data = self.uc.mem_read(got_va, 8)
            return struct.unpack('<Q', data)[0]
        except:
            # Try from GOT resolver's relocation table
            target = self.got.resolve(got_va)
            return target or 0

    # Known GOT slots from previous analysis
    KNOWN_GOT_SLOTS = {
        0x5090010: ("off_5090010", "direction_normalize", 0x25a6930),
        0x5153CB0: ("off_5153CB0", "per_frame_update (sub_36A2678)", 0x36A2678),
        0x51548E0: ("off_51548E0", "return_a1_plus_16", 0x36b009c),
        0x519D358: ("off_519D358", "get_physics_subcomp", 0x3d29460),
        0x51AF678: ("off_51AF678", "RVO_update", 0x3edf920),
        0x51AF748: ("off_51AF748", "MovementComponent_UpdateLogic", 0x3ee11b8),
        0x5226B10: ("off_5226B10", "per_frame_HeroEntry_lookup", 0x45abe90),
        0x51B7520: ("off_51B7520", "getter_obj+0x60", 0x3f7d028),
        0x51B75B0: ("off_51B75B0", "setter_obj+0x78", 0x3f7d0b4),
    }


# ==============================================================
# Test: Emulate sub_36A2678 (per-frame update)
# ==============================================================
def test_per_frame_update(uc, loader, got, env):
    """Emulate sub_36A2678: per-frame Hero update.

    This function writes to hero+0x10, +0x18, +0x70, +0x1C, +0x5C, +0xC8, +0xEA
    but NOT hero+0x20/+0x28.

    We emulate it to CONFIRM it doesn't write hero+0x20.
    """
    FUNC = 0x36A2678

    print("\n" + "="*70)
    print("DEEP EMU: sub_36A2678 (per-frame Hero update)")
    print("="*70)
    print("Goal: Confirm it does NOT write hero+0x20/+0x28")
    print("     and identify what it DOES write\n")

    # Create a fake Hero object
    HERO = alloc_obj(uc, env, 0x1000, base_offset=0x10000)
    print(f"[SETUP] Hero at 0x{HERO:x}")

    # Set up hero fields that this function might read
    # From analysis: it reads from sub-objects via GOT slots
    # We need to set up enough context for it to not crash

    # Hero+0x08 = runtime_id
    write_val(uc, HERO + 0x08, 12345, 4)

    # Hero+0x28 = config_id
    write_val(uc, HERO + 0x28, 105, 4)

    # Hero+0x34 = camp
    write_val(uc, HERO + 0x34, 1, 4)

    # Set up a fake "this" pointer (X0) -- this function may be a method
    # sub_36A2678 takes a1 = Hero pointer as first arg
    args = {
        UC_ARM64_REG_X0: HERO,  # a1 = Hero*
    }

    deep = DeepEmulator(uc, loader, got)
    result = deep.emulate_function(FUNC, args, obj_base=HERO, label="per_frame_update")

    # Check if hero+0x20 was written
    hero_20_written = any(va == HERO + 0x20 for va, _, _, _ in result['writes'])
    hero_28_written = any(va == HERO + 0x28 for va, _, _, _ in result['writes'])

    print(f"\n{'='*70}")
    print(f"RESULT: hero+0x20 written: {hero_20_written}")
    print(f"RESULT: hero+0x28 written: {hero_28_written}")

    # List all offsets written to hero
    hero_offsets = set()
    for va, _, _, _ in result['writes']:
        offset = va - HERO
        if 0 <= offset < 0x1000:
            hero_offsets.add(offset)

    if hero_offsets:
        print(f"\nOffsets written to Hero:")
        for off in sorted(hero_offsets):
            print(f"  Hero+0x{off:03x}")

    return result


# ==============================================================
# Test: Emulate sub_3EDF920 (RVO update) with vtable tracking
# ==============================================================
def test_rvo_update(uc, loader, got, env):
    """Emulate sub_3EDF920: RVO direction update.

    This function calls vtable[41] (offset 0x148) to write direction data.
    We trace all writes to confirm it writes to obj+0x60/+0x78 sub-objects,
    NOT to hero+0x20.
    """
    FUNC = 0x3EDF920

    print("\n" + "="*70)
    print("DEEP EMU: sub_3EDF920 (RVO update)")
    print("="*70)
    print("Goal: Trace vtable[41] call and confirm it writes to obj+0x60/+0x78")
    print("     sub-objects, NOT hero+0x20\n")

    # Create fake MovementComponent object
    MCVT = alloc_obj(uc, env, 0x1000, base_offset=0x12000)

    # Set up a vtable for the object
    VTABLE = alloc_obj(uc, env, 0x400, base_offset=0x13000)
    # Fill vtable slot 41 (offset 0x148 = 41*8) with sub_3F7D028 (getter)
    write_val(uc, VTABLE + 0x148, 0x3F7D028, 8)

    # Set vtable pointer in object
    write_val(uc, MCVT + 0x00, VTABLE, 8)

    # Set up sub-objects at obj+0x60 and obj+0x78
    SUB60 = alloc_obj(uc, env, 0x100, base_offset=0x13100)
    SUB78 = alloc_obj(uc, env, 0x100, base_offset=0x13200)
    write_val(uc, MCVT + 0x60, SUB60, 8)
    write_val(uc, MCVT + 0x78, SUB78, 8)

    print(f"[SETUP] MCVT=0x{MCVT:x} VTABLE=0x{VTABLE:x}")
    print(f"[SETUP] SUB60=0x{SUB60:x} SUB78=0x{SUB78:x}")
    print(f"[SETUP] vtable[41]=0x3F7D028 (getter)")

    args = {
        UC_ARM64_REG_X0: MCVT,
    }

    deep = DeepEmulator(uc, loader, got)
    result = deep.emulate_function(FUNC, args, obj_base=MCVT, label="RVO_update")

    # Check writes to sub-objects
    sub60_written = any(va == SUB60 + 0 or va == SUB60 + 8 for va, _, _, _ in result['writes'])
    sub78_written = any(va == SUB78 + 0 or va == SUB78 + 8 for va, _, _, _ in result['writes'])

    print(f"\n{'='*70}")
    print(f"RESULT: SUB60+0/+8 written: {sub60_written}")
    print(f"RESULT: SUB78+0/+8 written: {sub78_written}")

    return result


# ==============================================================
# Test: Emulate sub_3EE11B8 (MovementComponent::UpdateLogic)
#       This calls vtable[19] and vtable[21] -- the mystery functions!
# ==============================================================
def test_movementcomponent_updatelogic(uc, loader, got, env):
    """Emulate sub_3EE11B8: MovementComponent::UpdateLogic.

    THIS IS THE KEY TEST. This function calls:
    - vtable[19] (offset 0x98 = 19*8+8... actually 152 = 0x98)
    - vtable[21] (offset 0xA8 = 168 = 21*8)

    These virtual calls likely contain the per-frame position update logic
    that writes to hero+0x20. IDA cannot statically resolve them.

    We emulate this function with a controlled vtable to see what
    vtable[19]/vtable[21] do when called.
    """
    FUNC = 0x3EE11B8

    print("\n" + "="*70)
    print("DEEP EMU: sub_3EE11B8 (MovementComponent::UpdateLogic)")
    print("="*70)
    print("Goal: Trace vtable[19] and vtable[21] calls")
    print("      These are the MYSTERY functions that may write hero+0x20!")
    print()

    # Create fake physics component object
    PHYSCOMP = alloc_obj(uc, env, 0x1000, base_offset=0x20000)

    # Set up vtable with slot 19 and 21
    VTABLE = alloc_obj(uc, env, 0x200, base_offset=0x21000)

    # vtable layout: vtable[0] is at offset 8 (after RTTI?), so
    # slot N is at offset 8 + N*8
    # OR: slot 0 is at offset 0, slot N is at offset N*8
    # From analysis: vtable[19] = offset 152, vtable[21] = offset 168
    # Let's try both interpretations

    # Fill vtable with a simple RET function for unknown slots
    RET_ADDR = 0x7E001000
    try:
        uc.mem_map(RET_ADDR, 0x1000, UC_PROT_EXEC | UC_PROT_READ | UC_PROT_WRITE)
    except:
        pass
    uc.mem_write(RET_ADDR, b'\xd6\x5f\x03\xc0')  # RET

    # Fill all 32 vtable slots with RET
    for i in range(32):
        write_val(uc, VTABLE + i * 8, RET_ADDR, 8)

    # Set vtable pointer
    write_val(uc, PHYSCOMP + 0x00, VTABLE, 8)

    # Set up sub-components that sub_3D29460 reads
    # From analysis: sub_3D29460 reads from MovementComponent+80 and +128
    # and returns sub-components
    SUB80 = alloc_obj(uc, env, 0x200, base_offset=0x21200)
    SUB128 = alloc_obj(uc, env, 0x200, base_offset=0x21400)
    write_val(uc, PHYSCOMP + 80, SUB80, 8)
    write_val(uc, PHYSCOMP + 128, SUB128, 8)

    # Set up vtables for sub-components too
    SUB80_VT = alloc_obj(uc, env, 0x200, base_offset=0x21600)
    SUB128_VT = alloc_obj(uc, env, 0x200, base_offset=0x21800)
    for i in range(32):
        write_val(uc, SUB80_VT + i * 8, RET_ADDR, 8)
        write_val(uc, SUB128_VT + i * 8, RET_ADDR, 8)
    write_val(uc, SUB80 + 0, SUB80_VT, 8)
    write_val(uc, SUB128 + 0, SUB128_VT, 8)

    print(f"[SETUP] PHYSCOMP=0x{PHYSCOMP:x}")
    print(f"[SETUP] VTABLE=0x{VTABLE:x} (all slots = RET stub)")
    print(f"[SETUP] SUB80=0x{SUB80:x} SUB128=0x{SUB128:x}")

    # The function reads from GOT slots off_51AF748 etc.
    # We need to make sure GOT slots are resolved
    # They should be already resolved by create_emulator()

    args = {
        UC_ARM64_REG_X0: PHYSCOMP,
    }

    deep = DeepEmulator(uc, loader, got)
    result = deep.emulate_function(FUNC, args, obj_base=PHYSCOMP,
                                   label="MovementComponent_UpdateLogic_vtable19_21")

    # Check BLR targets
    print(f"\n{'='*70}")
    print("BLR ANALYSIS:")
    for addr, target, reg in result['blr_targets']:
        print(f"  BLR at 0x{addr:x} via {reg} -> 0x{target:x}")

    # Check which vtable slots were called
    vt_calls = [t for _, t, _ in result['blr_targets']]
    print(f"\n  Unique BLR targets: {len(set(vt_calls))}")
    for t in sorted(set(vt_calls)):
        count = vt_calls.count(t)
        is_vtable_slot = (VTABLE <= t < VTABLE + 0x200)
        is_ret_stub = (t == RET_ADDR)
        print(f"    0x{t:x}: {count}x {'= RET stub' if is_ret_stub else '= vtable slot' if is_vtable_slot else ''}")

    return result


# ==============================================================
# Test: Resolve all GOT slots used by sub_3EE11B8
# ==============================================================
def test_resolve_got_slots(uc, loader, got, env):
    """Read all known GOT slots from Unicorn memory to verify they're resolved."""
    print("\n" + "="*70)
    print("GOT SLOT RESOLUTION TEST")
    print("="*70)
    print("Reading GOT slots from Unicorn memory to verify resolution:\n")

    resolver = GOTFunctionResolver(uc, got)

    for got_va, (name, desc, expected) in resolver.KNOWN_GOT_SLOTS.items():
        actual = resolver.resolve_got_slot(got_va)
        match = "OK" if actual == expected else "MISMATCH"
        print(f"  {name:25s} @0x{got_va:07x}: got=0x{actual:x} expected=0x{expected:x} [{match}]")
        print(f"    -> {desc}")

    return resolver


# ==============================================================
# Main
# ==============================================================
def main():
    print("Data Flow Tracer for libGameCore.so")
    print("Goal: Resolve virtual calls and trace writes to hero+0x20\n")

    # Create emulator
    uc, loader, got, env = create_emulator()

    # Test 1: Verify GOT slots are resolved
    test_resolve_got_slots(uc, loader, got, env)

    # Test 2: Emulate per-frame update (confirm it doesn't write hero+0x20)
    test_per_frame_update(uc, loader, got, env)

    # Test 3: Emulate RVO update (confirm it writes obj+0x60/+0x78 sub-objects)
    test_rvo_update(uc, loader, got, env)

    # Test 4: Emulate MovementComponent::UpdateLogic (trace vtable[19]/[21])
    test_movementcomponent_updatelogic(uc, loader, got, env)

    print("\n" + "="*70)
    print("All data flow tracing tests complete")
    print("="*70)


if __name__ == '__main__':
    main()
