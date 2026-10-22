"""
Unicorn ARM64 Emulator for libGameCore.so
==========================================
Loads ELF segments into Unicorn memory, resolves GOT slots via .rela.dyn,
and emulates target functions with controlled inputs to trace data flow.

Key capabilities:
1. Load all LOAD segments (R/RX/RW) into Unicorn
2. Resolve GOT slots from .rela.dyn relocations
3. Emulate functions with hook-based memory access tracing
4. Track every STR (write) to identify which offsets are written
5. Resolve virtual calls by emulating vtable lookups
"""

import lief
import struct
import sys
import os
from collections import defaultdict
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_ARM,
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_INSN, UC_HOOK_INTR,
    UC_MEM_WRITE, UC_MEM_READ,
    UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    UC_ERR_OK,
)
from unicorn.arm64_const import *

# ==============================================================
# Config
# ==============================================================
ELF_PATH = r"D:\SGANEM\test.so"
PAGE_SIZE = 0x1000

# ==============================================================
# ELF Loader -- load segments into Unicorn
# ==============================================================
class ELFLoader:
    def __init__(self, path):
        self.elf = lief.parse(path)
        self.segments = []

        for seg in self.elf.segments:
            if seg.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            prot = 0
            if seg.flags & lief.ELF.Segment.FLAGS.R: prot |= UC_PROT_READ
            if seg.flags & lief.ELF.Segment.FLAGS.W: prot |= UC_PROT_WRITE
            if seg.flags & lief.ELF.Segment.FLAGS.X: prot |= UC_PROT_EXEC

            data = bytes(seg.content)
            self.segments.append({
                'va': seg.virtual_address,
                'vsize': seg.virtual_size,
                'fsize': len(data),
                'foffset': seg.file_offset,
                'prot': prot,
                'data': data,
            })

        print(f"[ELF] Loaded {len(self.segments)} LOAD segments")
        for i, s in enumerate(self.segments):
            prot_str = ""
            if s['prot'] & UC_PROT_READ: prot_str += "R"
            if s['prot'] & UC_PROT_WRITE: prot_str += "W"
            if s['prot'] & UC_PROT_EXEC: prot_str += "X"
            print(f"  [{i}] VA=0x{s['va']:010x} VSize=0x{s['vsize']:x} FSize=0x{s['fsize']:x} Prot={prot_str}")

    def load_into_unicorn(self, uc):
        for seg in self.segments:
            va = seg['va']
            vsize = seg['vsize']
            va_aligned = va & ~(PAGE_SIZE - 1)
            end_aligned = (va + vsize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
            map_size = end_aligned - va_aligned

            prot = seg['prot']
            if prot == 0:
                prot = UC_PROT_READ

            try:
                uc.mem_map(va_aligned, map_size, prot)
            except Exception:
                pass

            if seg['data']:
                uc.mem_write(va, seg['data'])

        print(f"[ELF] All segments loaded into Unicorn")

    def get_code_bytes(self, va, size):
        for seg in self.segments:
            if seg['va'] <= va < seg['va'] + seg['fsize']:
                offset = va - seg['va']
                return seg['data'][offset:offset + size]
        return None


# ==============================================================
# GOT Resolver -- resolve relocation entries
# ==============================================================
class GOTResolver:
    def __init__(self, elf):
        self.elf = elf
        self.relocations = {}
        self._parse_rela_dyn()
        print(f"[GOT] Resolved {len(self.relocations)} relocations")

    def _parse_rela_dyn(self):
        for reloc in self.elf.pltgot_relocations:
            addr = reloc.address
            if reloc.addend:
                target = reloc.addend
            elif reloc.has_symbol:
                target = reloc.symbol.value
            else:
                target = 0
            self.relocations[addr] = target

        for reloc in self.elf.dynamic_relocations:
            addr = reloc.address
            if reloc.addend:
                target = reloc.addend
            elif reloc.has_symbol:
                target = reloc.symbol.value
            else:
                target = 0
            self.relocations[addr] = target

    def resolve(self, got_offset):
        return self.relocations.get(got_offset, None)


# ==============================================================
# Memory Access Tracer -- track all reads/writes
# ==============================================================
class MemoryTracer:
    def __init__(self, uc, label=""):
        self.uc = uc
        self.label = label
        self.writes = []
        self.reads = []
        self.code_trace = []
        self.insn_count = 0
        self.max_insns = 50000
        self.hook_handles = []
        self.obj_base = 0
        self.trace_regions = []  # list of (start, end) for read tracing

    def set_obj_base(self, base):
        self.obj_base = base
        self.trace_regions.append((base, base + 0x10000))

    def add_trace_region(self, start, end):
        self.trace_regions.append((start, end))

    def _in_trace_region(self, va):
        for s, e in self.trace_regions:
            if s <= va < e:
                return True
        return False

    def _fmt_offset(self, va):
        if self.obj_base and abs(va - self.obj_base) < 0x10000:
            return f"obj+0x{va - self.obj_base:x}"
        for s, e in self.trace_regions:
            if s <= va < e:
                return f"region(0x{s:x})+0x{va - s:x}"
        return f"0x{va:x}"

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        self.writes.append((address, size, value))
        offset_str = self._fmt_offset(address)
        val_fmt = value & ((1 << (size * 8)) - 1)
        if size <= 4:
            print(f"  [WRITE] {offset_str:30s} size={size} val=0x{val_fmt:x} ({val_fmt})")
        elif size == 8:
            print(f"  [WRITE] {offset_str:30s} size={size} val=0x{val_fmt:x}")
        elif size == 16:
            print(f"  [WRITE] {offset_str:30s} size={size} val=0x{val_fmt:016x}")
        else:
            print(f"  [WRITE] {offset_str:30s} size={size} val=0x{val_fmt:x}")

    def _hook_mem_read(self, uc, access, address, size, value, user_data):
        if self._in_trace_region(address):
            offset_str = self._fmt_offset(address)
            data = uc.mem_read(address, size)
            val = int.from_bytes(data, 'little')
            if size <= 4:
                print(f"  [READ]  {offset_str:30s} size={size} val=0x{val:x} ({val})")
            else:
                print(f"  [READ]  {offset_str:30s} size={size} val=0x{val:x}")
            self.reads.append((address, size, val))

    def _hook_code(self, uc, address, size, user_data):
        self.insn_count += 1
        if self.insn_count > self.max_insns:
            print(f"  [!] Max instructions reached ({self.max_insns})")
            uc.emu_stop()
            return
        if self.insn_count <= 200:
            self.code_trace.append(address)

    def install(self, trace_reads=False):
        h1 = self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        self.hook_handles.append(h1)
        if trace_reads:
            h2 = self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)
            self.hook_handles.append(h2)
        h3 = self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.hook_handles.append(h3)

    def summary(self):
        print(f"\n[TRACE] {self.label} Summary:")
        print(f"  Instructions executed: {self.insn_count}")
        print(f"  Memory writes: {len(self.writes)}")
        print(f"  Memory reads (from obj): {len(self.reads)}")

        if self.obj_base:
            offset_writes = defaultdict(list)
            for va, size, val in self.writes:
                if abs(va - self.obj_base) < 0x10000:
                    offset_writes[va - self.obj_base].append((size, val))
            if offset_writes:
                print(f"\n  Writes to obj (base=0x{self.obj_base:x}):")
                for off in sorted(offset_writes.keys()):
                    vals = offset_writes[off]
                    for size, val in vals:
                        print(f"    obj+0x{off:03x}: size={size} val=0x{val:x}")


# ==============================================================
# Unmapped Memory Handler -- auto-map on demand
# ==============================================================
def make_unmapped_handler():
    def handler(uc, access, address, size, value, user_data):
        page = address & ~(PAGE_SIZE - 1)
        try:
            uc.mem_map(page, PAGE_SIZE * 2, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_write(page, b'\x00' * (PAGE_SIZE * 2))
            return True
        except Exception as e:
            print(f"  [AUTO-MAP FAIL] 0x{page:x}: {e}")
            return False
    return handler


# ==============================================================
# Emulator setup
# ==============================================================
def create_emulator():
    print("=" * 70)
    print("Creating Unicorn ARM64 Emulator for libGameCore.so")
    print("=" * 70)

    loader = ELFLoader(ELF_PATH)
    max_va = max(s['va'] + s['vsize'] for s in loader.segments)
    print(f"[EMU] Max VA: 0x{max_va:x}")

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    loader.load_into_unicorn(uc)

    STACK_BASE = 0x7F000000
    STACK_SIZE = 0x100000
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    sp = STACK_BASE + STACK_SIZE - 0x100
    uc.reg_write(UC_ARM64_REG_SP, sp)

    HEAP_BASE = 0x80000000
    HEAP_SIZE = 0x100000
    uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)

    OBJ_BASE = 0x90000000
    OBJ_SIZE = 0x100000
    uc.mem_map(OBJ_BASE, OBJ_SIZE, UC_PROT_READ | UC_PROT_WRITE)

    got = GOTResolver(loader.elf)
    for offset, target in got.relocations.items():
        if target != 0:
            try:
                uc.mem_write(offset, struct.pack('<Q', target))
            except:
                pass

    print(f"[EMU] GOT relocations applied")
    print(f"[EMU] Stack: 0x{STACK_BASE:x} SP=0x{sp:x}")
    print(f"[EMU] Heap:  0x{HEAP_BASE:x}")
    print(f"[EMU] Obj:   0x{OBJ_BASE:x}")

    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_UNMAPPED,
                make_unmapped_handler())

    env = {
        'stack_base': STACK_BASE,
        'heap_base': HEAP_BASE,
        'obj_base': OBJ_BASE,
        'heap_ptr': HEAP_BASE,
    }
    return uc, loader, got, env


# ==============================================================
# Helpers
# ==============================================================
def alloc_obj(uc, env, size, base_offset=0, init_data=None):
    addr = env['obj_base'] + base_offset
    if init_data:
        uc.mem_write(addr, init_data)
    else:
        uc.mem_write(addr, b'\x00' * size)
    return addr

def alloc_heap(uc, env, size):
    addr = env['heap_ptr']
    env['heap_ptr'] += size
    uc.mem_write(addr, b'\x00' * size)
    return addr

def write_val(uc, addr, value, size=4):
    if size == 4:
        uc.mem_write(addr, struct.pack('<I', value & 0xFFFFFFFF))
    elif size == 8:
        uc.mem_write(addr, struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF))
    elif size == 2:
        uc.mem_write(addr, struct.pack('<H', value & 0xFFFF))
    elif size == 1:
        uc.mem_write(addr, struct.pack('<B', value & 0xFF))

def setup_lr(uc, addr=0x7E000000):
    try:
        uc.mem_map(addr, 0x1000, UC_PROT_EXEC)
    except:
        pass
    uc.mem_write(addr, b'\xd6\x5f\x03\xc0')  # RET
    uc.reg_write(UC_ARM64_REG_LR, addr)
    return addr


# ==============================================================
# Tests
# ==============================================================
def test_viewmanager_write55000(uc, env):
    """Emulate sub_24AEAC0: writes 55000 to hero+0x20/+0x28."""
    FUNC = 0x24AEAC0
    print("\n" + "=" * 70)
    print("TEST 1: sub_24AEAC0 (ViewManager write 55000)")
    print("=" * 70)
    print("Expected: writes 55000 to a2+0x20 and a2+0x28\n")

    HERO = alloc_obj(uc, env, 0x1000, base_offset=0x1000)
    VMGR = alloc_obj(uc, env, 0x1000, base_offset=0x2000)
    write_val(uc, VMGR + 0x18, 1, 4)
    print(f"[SETUP] hero=0x{HERO:x} vmgr=0x{VMGR:x} vmgr+0x18(camp)=1")

    uc.reg_write(UC_ARM64_REG_X0, VMGR)
    uc.reg_write(UC_ARM64_REG_X1, HERO)
    LR = setup_lr(uc)

    tracer = MemoryTracer(uc, "ViewManager_write55000")
    tracer.set_obj_base(HERO)
    tracer.install(trace_reads=True)

    try:
        uc.emu_start(FUNC, LR, timeout=5*1000000, count=1000)
        print(f"\n[OK] Done ({tracer.insn_count} insns)")
    except Exception as e:
        print(f"\n[ERR] {e}")

    tracer.summary()
    val20 = struct.unpack('<i', uc.mem_read(HERO + 0x20, 4))[0]
    val28 = struct.unpack('<i', uc.mem_read(HERO + 0x28, 4))[0]
    print(f"\n[VERIFY] hero+0x20={val20} hero+0x28={val28} (expect 55000)")
    ok = val20 == 55000 and val28 == 55000
    print(f"[{'PASS' if ok else 'FAIL'}]")
    return ok


def test_distance_coord_convert(uc, env):
    """Emulate sub_3ADB960: reads a2+0 and a2+8, divides by 100."""
    FUNC = 0x3ADB960
    print("\n" + "=" * 70)
    print("TEST 2: sub_3ADB960 (distance coord /100)")
    print("=" * 70)
    print("Expected: reads a2+0 and a2+8, returns /100 in X0/X1\n")

    COORD = alloc_obj(uc, env, 0x100, base_offset=0x3000)
    test_x = 1500000
    test_y = 2000000
    write_val(uc, COORD + 0, test_x, 4)
    write_val(uc, COORD + 8, test_y, 4)
    print(f"[SETUP] coord=0x{COORD:x} +0={test_x}mm +8={test_y}mm")
    print(f"        expect X0={test_x//100} X1={test_y//100}")

    uc.reg_write(UC_ARM64_REG_X1, COORD)
    uc.reg_write(UC_ARM64_REG_X0, 0)
    LR = setup_lr(uc)

    tracer = MemoryTracer(uc, "distance_coord")
    tracer.set_obj_base(COORD)
    tracer.install(trace_reads=True)

    try:
        uc.emu_start(FUNC, LR, timeout=5*1000000, count=1000)
        print(f"\n[OK] Done ({tracer.insn_count} insns)")
    except Exception as e:
        print(f"\n[ERR] {e}")

    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    print(f"\n[RESULT] X0={x0} (expect {test_x//100})")
    print(f"[RESULT] X1={x1} (expect {test_y//100})")
    ok = x0 == test_x // 100 and x1 == test_y // 100
    print(f"[{'PASS' if ok else 'FAIL'}]")
    return ok


def test_setter_a(uc, env):
    """Emulate sub_3F7D074: writes to (obj+0x60)->+0 and +8."""
    FUNC = 0x3F7D074
    print("\n" + "=" * 70)
    print("TEST 3: sub_3F7D074 (setter A, write obj+0x60 sub-object)")
    print("=" * 70)
    print("Expected: writes source data to (*(obj+0x60))+0 and +8\n")

    OBJ = alloc_obj(uc, env, 0x1000, base_offset=0x5000)
    SUBOBJ = alloc_obj(uc, env, 0x100, base_offset=0x5500)
    write_val(uc, OBJ + 0x60, SUBOBJ, 8)

    SOURCE = alloc_obj(uc, env, 0x20, base_offset=0x5600)
    test_val0 = 0x499602D0
    test_val8 = 0x0000C350
    write_val(uc, SOURCE + 0, test_val0, 8)
    write_val(uc, SOURCE + 8, test_val8, 4)

    print(f"[SETUP] obj=0x{OBJ:x} subobj=0x{SUBOBJ:x} source=0x{SOURCE:x}")

    uc.reg_write(UC_ARM64_REG_X0, OBJ)
    uc.reg_write(UC_ARM64_REG_X1, SOURCE)
    LR = setup_lr(uc)

    tracer = MemoryTracer(uc, "setter_A")
    tracer.set_obj_base(SUBOBJ)
    tracer.install(trace_reads=False)

    try:
        uc.emu_start(FUNC, LR, timeout=5*1000000, count=1000)
        print(f"\n[OK] Done ({tracer.insn_count} insns)")
    except Exception as e:
        print(f"\n[ERR] {e}")

    val0 = struct.unpack('<Q', uc.mem_read(SUBOBJ + 0, 8))[0]
    val8 = struct.unpack('<I', uc.mem_read(SUBOBJ + 8, 4))[0]
    print(f"\n[VERIFY] subobj+0=0x{val0:x} (expect 0x{test_val0:x})")
    print(f"[VERIFY] subobj+8={val8} (expect {test_val8})")
    ok = val0 == test_val0 and val8 == test_val8
    print(f"[{'PASS' if ok else 'FAIL'}]")
    return ok


def test_setter_b(uc, env):
    """Emulate sub_3F7D0B4: writes to (obj+0x78)->+0 and +8."""
    FUNC = 0x3F7D0B4
    print("\n" + "=" * 70)
    print("TEST 4: sub_3F7D0B4 (setter B, write obj+0x78 sub-object)")
    print("=" * 70)
    print("Expected: writes source data to (*(obj+0x78))+0 and +8\n")

    OBJ = alloc_obj(uc, env, 0x1000, base_offset=0x6000)
    SUBOBJ = alloc_obj(uc, env, 0x100, base_offset=0x6500)
    write_val(uc, OBJ + 0x78, SUBOBJ, 8)

    SOURCE = alloc_obj(uc, env, 0x20, base_offset=0x6600)
    test_val0 = 0xDEADBEEFCAFEBABE
    test_val8 = 0x000186A0  # 100000
    write_val(uc, SOURCE + 0, test_val0, 8)
    write_val(uc, SOURCE + 8, test_val8, 4)

    print(f"[SETUP] obj=0x{OBJ:x} subobj=0x{SUBOBJ:x} source=0x{SOURCE:x}")

    uc.reg_write(UC_ARM64_REG_X0, OBJ)
    uc.reg_write(UC_ARM64_REG_X1, SOURCE)
    LR = setup_lr(uc)

    tracer = MemoryTracer(uc, "setter_B")
    tracer.set_obj_base(SUBOBJ)
    tracer.install(trace_reads=False)

    try:
        uc.emu_start(FUNC, LR, timeout=5*1000000, count=1000)
        print(f"\n[OK] Done ({tracer.insn_count} insns)")
    except Exception as e:
        print(f"\n[ERR] {e}")

    val0 = struct.unpack('<Q', uc.mem_read(SUBOBJ + 0, 8))[0]
    val8 = struct.unpack('<I', uc.mem_read(SUBOBJ + 8, 4))[0]
    print(f"\n[VERIFY] subobj+0=0x{val0:x} (expect 0x{test_val0:x})")
    print(f"[VERIFY] subobj+8={val8} (expect {test_val8})")
    ok = val0 == test_val0 and val8 == test_val8
    print(f"[{'PASS' if ok else 'FAIL'}]")
    return ok


# ==============================================================
# Main
# ==============================================================
def main():
    uc, loader, got, env = create_emulator()

    results = {}
    results['VM_write55000'] = test_viewmanager_write55000(uc, env)
    results['dist_div100'] = test_distance_coord_convert(uc, env)
    results['setter_A'] = test_setter_a(uc, env)
    results['setter_B'] = test_setter_b(uc, env)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for name, ok in results.items():
        print(f"  {name}: {'PASS' if ok else 'FAIL'}")

    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed}/{total} tests passed")
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
