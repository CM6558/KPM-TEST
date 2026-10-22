"""
BROADER SCAN: Find ALL functions that STR to offset +0x20
where the base register could come from a Hero/Actor pointer.

Since vtable[19]/vtable[21] turned out to be trivial stubs,
we need to find hero+0x20's writer through pattern matching:
scan the .text section for STR Wx, [Xy, #0x20] instructions.
"""

import lief
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from collections import defaultdict

ELF_PATH = r"D:\SGANEM\test.so"
elf = lief.parse(ELF_PATH)

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

# Get .text section
text_sec = elf.get_section(".text")
TEXT_START = text_sec.virtual_address
TEXT_END = TEXT_START + text_sec.size
text_data = bytes(text_sec.content)

print(f"Scanning .text: 0x{TEXT_START:x} - 0x{TEXT_END:x} ({len(text_data)} bytes)")

# Scan for STR + STP instructions with offset 0x20 (32 bytes)
# STR Wx, [Xy, #0x20]  -- 32-bit write
# STR Xx, [Xy, #0x20]  -- 64-bit write (might be packed X+Y or pointer)

# ARM64 STR encoding:
# STR Wt, [Xn, #imm12] = 0xB9000000 | (imm12/4 << 10) | (Rn << 5) | Rt
# For imm=0x20, imm12/4 = 8, so bit pattern: 0xB9020000 | (Rn<<5) | Rt
# STR Xt, [Xn, #imm12] = 0xF9000000 | (imm12/8 << 10) | (Rn << 5) | Rt
# For imm=0x20, imm12/8 = 4, so bit pattern: 0xF9010000 | (Rn<<5) | Rt

# Also check STP Wx, Wy, [Xz, #0x20] (store pair at offset 0x20)
# And STRB (byte writes with smaller offsets nearby)

offset_0x20_funcs = defaultdict(list)  # func_addr -> list of (insn_addr, mnemonic, op_str)

# We need to find function boundaries. Simple heuristic:
# Functions start with "STP X30, ..." or "STR X30, [SP, ...]" pattern
# But for a broad scan, let's just collect ALL STR to offset 0x20 and group by nearby function

# Use a window-based approach: disassemble in chunks, find STR [Xn, #0x20] calls
CHUNK_SIZE = 65536
results = []

# More targeted: scan for specific instruction patterns
# STR Wt, [Xn, #0x20]:  0xB9020000 mask 0xFFC00000 == 0xB9000000, imm=0x20
#   encoding: 0xB9020xxx where xxx encodes Rn and Rt
# STR Xt, [Xn, #0x20]:  0xF9010000 mask 0xFFC00000 == 0xF9000000, imm=0x20
#   encoding: 0xF9010xxx where xxx encodes Rn and Rt

# Also STR with offset 0x28: hero+0x28 is the Y coordinate
# STR Wt, [Xn, #0x28]: 0xB9028000 | (Rn<<5) | Rt (imm12/4 = 0x28/4 = 10 = 0xA)
# STR Xt, [Xn, #0x28]: 0xF9014000 | (Rn<<5) | Rt (imm12/8 = 0x28/8 = 5)

# Also STP at offset 0x20 (writes to +0x20 and +0x24 or +0x28)
# STP Wt, Wt2, [Xn, #0x20]: offset 0x20

# We'll use capstone for a focused scan of the first ~4MB of .text
# (scanning all 43MB would take too long, but the Hero-related code is in the 0x24xx-0x3xxx range)

SCAN_RANGES = [
    (0x2400000, 0x2500000),  # ViewManager area
    (0x3600000, 0x3700000),  # Hero/Actor area
    (0x3D00000, 0x3F00000),  # Physics/Movement area
    (0x4500000, 0x4600000),  # ActorManagement area
    (0x25A0000, 0x25B0000),  # sub_25Axxxx area
    (0x3EE0000, 0x3EF0000),  # MovementComponent area
    (0x3ED0000, 0x3EE0000),  # RVO/Movement area
]

# Also do a targeted scan around the known relevant function addresses
ALL_OFFSETS = [0x20, 0x28]  # hero+0x20 (X), hero+0x28 (Y)

for scan_start, scan_end in SCAN_RANGES:
    # Get the bytes for this range
    for seg in elf.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            content = bytes(seg.content)
            seg_va = seg.virtual_address
            seg_end = seg_va + len(content)
            if seg_va <= scan_start < seg_end:
                # Calculate offset in this segment
                data_start = scan_start - seg_va
                data_end = min(scan_end - seg_va, len(content))
                chunk = content[data_start:data_end]
                break
    else:
        continue

    print(f"\nScanning 0x{scan_start:x} - 0x{scan_end:x} ({len(chunk)} bytes)")

    insn_count = 0
    str_0x20_count = 0
    str_0x28_count = 0
    stp_0x20_count = 0

    for insn in cs.disasm(chunk, scan_start):
        insn_count += 1

        # Check for STR with offset 0x20 or 0x28
        if insn.mnemonic in ('str', 'strb', 'strh'):
            ops = insn.op_str
            if '#0x20]' in ops or '#0x28]' in ops or ', #32]' in ops or ', #40]' in ops:
                target_offset = None
                if '#0x20]' in ops: target_offset = 0x20
                elif '#0x28]' in ops: target_offset = 0x28
                elif ', #32]' in ops: target_offset = 0x20
                elif ', #40]' in ops: target_offset = 0x28

                if target_offset:
                    if target_offset == 0x20:
                        str_0x20_count += 1
                    else:
                        str_0x28_count += 1
                    results.append((insn.address, insn.mnemonic, insn.op_str, target_offset))

        # Check for STP with offset 0x20 (writes +0x20 and +0x24 or +0x28)
        elif insn.mnemonic == 'stp':
            ops = insn.op_str
            if '#0x20]' in ops or ', #32]' in ops:
                stp_0x20_count += 1
                results.append((insn.address, insn.mnemonic, insn.op_str, 0x20))

    print(f"  {insn_count} instructions scanned")
    print(f"  STR to +0x20: {str_0x20_count}")
    print(f"  STR to +0x28: {str_0x28_count}")
    print(f"  STP to +0x20: {stp_0x20_count}")

# Group results by nearby function (look for function prologue before each STR)
print("\n" + "=" * 70)
print(f"TOTAL STR/STP to +0x20/+0x28: {len(results)}")
print("=" * 70)

# Group by 4KB page (approximate function grouping)
page_groups = defaultdict(list)
for addr, mnem, ops, offset in results:
    page = addr & ~0xFFF  # 4KB page
    page_groups[page].append((addr, mnem, ops, offset))

for page in sorted(page_groups.keys())[:30]:
    entries = page_groups[page]
    print(f"\n  Page 0x{page:x} ({len(entries)} hits):")
    for addr, mnem, ops, offset in entries[:10]:
        print(f"    0x{addr:07x}: {mnem:6s} {ops} [offset=0x{offset:x}]")
    if len(entries) > 10:
        print(f"    ... ({len(entries)} total)")

# Also print known functions that have STR to +0x20
# Check if any of our known function addresses are in the results
known_funcs = {
    0x24AEAC0: "ViewManager write 55000",
    0x36A2678: "per_frame_update",
    0x36A283C: "SetSpawnPosition",
    0x3EDF920: "RVO_update",
    0x3EE11B8: "MovementComponent_UpdateLogic",
    0x24AD7FC: "ViewManager main",
}

print("\n" + "=" * 70)
print("STR/STP to +0x20/+0x28 in known function ranges:")
print("=" * 70)

for func_addr, func_name in sorted(known_funcs.items()):
    # Check if any results fall within ~2000 bytes of this function
    func_range = range(func_addr, func_addr + 2000)
    hits = [(a, m, o, off) for a, m, o, off in results if a in func_range]
    if hits:
        print(f"\n  0x{func_addr:x} ({func_name}):")
        for addr, mnem, ops, offset in hits:
            print(f"    0x{addr:07x}: {mnem:6s} {ops} [offset=0x{offset:x}]")
