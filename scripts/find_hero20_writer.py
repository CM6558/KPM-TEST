"""
Focused analysis: what writes to hero+0x20/+0x28?
Filter the scan results to only show writes to OBJECT registers (not SP).
Then disassemble the function region around 0x36a2d00 to identify the writer.
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

def get_func_bytes(va, size=8192):
    for seg in elf.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            content = bytes(seg.content)
            if seg.virtual_address <= va < seg.virtual_address + len(content):
                off = va - seg.virtual_address
                return content[off:off + size]
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
# Part 1: Disassemble region 0x36a2c00 to 0x36a2e00 (around the hits)
# ==============================================================
print("=" * 70)
print("FOCUSED ANALYSIS: 0x36a2c00 - 0x36a2e00 (writes to obj+0x20/+0x28)")
print("=" * 70)
print("Goal: identify which function writes to hero+0x20/+0x28\n")

chunk = get_func_bytes(0x36a2c00, 0x300)
adrp_pages = {}

for insn in cs.disasm(chunk, 0x36a2c00):
    annotation = ""
    # Highlight STR/STP to non-SP with offset +0x20/+0x28
    if insn.mnemonic.startswith('str') or insn.mnemonic == 'stp':
        if '#0x20]' in insn.op_str or '#0x28]' in insn.op_str or ', #32]' in insn.op_str or ', #40]' in insn.op_str:
            if 'sp' not in insn.op_str.lower().split(']')[1] and '[sp' not in insn.op_str.lower():
                annotation = " *** OBJECT WRITE to +0x20/+0x28 ***"

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
                        else:
                            annotation = f"; {dst} = *({base}+0x{off:x})"
                    except: pass
                elif len(sp) == 1:
                    annotation = f"; {dst} = *({sp[0]})"
    elif insn.mnemonic == 'blr':
        annotation = ">>> INDIRECT CALL"
    elif insn.mnemonic == 'br':
        annotation = ">>> TAIL CALL"
    elif insn.mnemonic == 'ret':
        annotation = "<<< RETURN >>>"
    elif insn.mnemonic.startswith('b.') or (insn.mnemonic == 'b' and '#' in insn.op_str):
        annotation = ">>> BRANCH"

    line = f"  0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
    if annotation:
        line += f"  {annotation}"
    print(line)

# ==============================================================
# Part 2: Find the function start for the 0x36a2d00 region
# ==============================================================
print("\n" + "=" * 70)
print("FINDING FUNCTION START for writes at 0x36a2d28-0x36a2d54")
print("=" * 70)

# Scan backwards from 0x36a2d28 to find function prologue
# Function prologue pattern: STP X30, ... [SP, #-]! or STR X30, [SP, #-]!
print("\nScanning backwards from 0x36a2d28 for function prologue...")
scan_start = 0x36a2d28 - 512
chunk = get_func_bytes(scan_start, 520)
for insn in cs.disasm(chunk, scan_start):
    if insn.address > 0x36a2d28:
        break
    if insn.mnemonic in ('stp', 'str') and ('x30' in insn.op_str or 'x29' in insn.op_str) and 'sp' in insn.op_str.lower():
        print(f"  Likely function start: 0x{insn.address:07x}: {insn.mnemonic} {insn.op_str}")

# ==============================================================
# Part 3: Disassemble 0x36a2900 to 0x36a2e00 more broadly
# ==============================================================
print("\n" + "=" * 70)
print("BROADER VIEW: 0x36a2900 - 0x36a2e00")
print("=" * 70)

chunk = get_func_bytes(0x36a2900, 0x500)
adrp_pages = {}
in_function = False
func_start = 0

for insn in cs.disasm(chunk, 0x36a2900):
    if insn.address > 0x36a2e00:
        break

    annotation = ""

    # Detect function prologue
    if insn.mnemonic in ('stp', 'str') and ('x30' in insn.op_str or 'x29' in insn.op_str) and '#-' in insn.op_str:
        in_function = True
        func_start = insn.address
        annotation = f"=== FUNCTION START ==="

    if insn.mnemonic == 'adrp':
        parts = insn.op_str.split(', ')
        if len(parts) == 2:
            try:
                page = int(parts[1].replace('#', ''), 0)
                adrp_pages[parts[0]] = page
            except: pass
    elif insn.mnemonic == 'add' and ',' in insn.op_str:
        parts = insn.op_str.split(', ')
        if len(parts) >= 3:
            try:
                imm = int(parts[2].replace('#', '').replace('0x', ''), 16)
                base = adrp_pages.get(parts[1], 0)
                adrp_pages[parts[0]] = base + imm
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
                    except: pass
    elif insn.mnemonic.startswith('str'):
        if '#0x20]' in insn.op_str or '#0x28]' in insn.op_str:
            if '[sp' not in insn.op_str and 'sp]' not in insn.op_str:
                annotation = " *** ★★★ OBJECT WRITE to +0x20/+0x28 ★★★ ***"
    elif insn.mnemonic == 'ret':
        annotation = "<<< RETURN >>>"
    elif insn.mnemonic == 'blr':
        annotation = ">>> INDIRECT CALL"

    line = f"  0x{insn.address:07x}: {insn.mnemonic:10s} {insn.op_str}"
    if annotation:
        line += f"  {annotation}"
    print(line)

# ==============================================================
# Part 4: Summary of ALL non-SP writes to +0x20/+0x28 in all scanned ranges
# ==============================================================
print("\n" + "=" * 70)
print("ALL non-SP writes to +0x20/+0x28 (object writes only)")
print("=" * 70)

# Re-scan for non-SP writes only
SCAN_RANGES = [
    (0x2400000, 0x2500000, "ViewManager region"),
    (0x3600000, 0x3700000, "Hero/Actor region"),
    (0x3D00000, 0x3F00000, "Physics/Movement region"),
    (0x4500000, 0x4600000, "ActorManagement region"),
    (0x25A0000, 0x25B0000, "sub_25A region"),
]

obj_writes = []

for scan_start, scan_end, label in SCAN_RANGES:
    for seg in elf.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            content = bytes(seg.content)
            seg_va = seg.virtual_address
            seg_end = seg_va + len(content)
            if seg_va <= scan_start < seg_end:
                data_start = scan_start - seg_va
                data_end = min(scan_end - seg_va, len(content))
                chunk = content[data_start:data_end]
                break
    else:
        continue

    for insn in cs.disasm(chunk, scan_start):
        if (insn.mnemonic.startswith('str') or insn.mnemonic == 'stp'):
            ops = insn.op_str.lower()
            if ('#0x20]' in ops or '#0x28]' in ops or ', #32]' in ops or ', #40]' in ops):
                # Check if this is a stack write (SP)
                if '[sp' in ops or 'sp]' in ops:
                    continue  # skip stack writes
                # This is an object write!
                obj_writes.append((insn.address, insn.mnemonic, insn.op_str, label))

print(f"\nTotal non-SP object writes to +0x20/+0x28: {len(obj_writes)}")
print("\nBy region:")
for label in ["ViewManager region", "Hero/Actor region", "Physics/Movement region", "ActorManagement region", "sub_25A region"]:
    region_writes = [(a, m, o, l) for a, m, o, l in obj_writes if l == label]
    print(f"\n  {label} ({len(region_writes)} writes):")
    for addr, mnem, ops, reg in region_writes[:10]:
        print(f"    0x{addr:07x}: {mnem:6s} {ops}")
    if len(region_writes) > 10:
        print(f"    ... ({len(region_writes)} total)")
