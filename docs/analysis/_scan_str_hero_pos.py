"""
扫描 test.so ARM64 指令,找所有写 hero 实例 +32 / +40 / +44 偏移的 STR 指令
这些偏移是真实坐标 (real_x/y/z)

策略:
1. 用 lief 解析 ELF 拿 .text 段
2. 用 capstone 反汇编 .text(整个扫一遍,86MB 大约几分钟)
3. 找所有 STR/STUR Wn, [Xreg, #32/40/44] 指令
4. 对每个命中点,记录地址 + 前后 5 条指令(辅助判断上下文)
5. 输出 CSV,按地址排序
"""
import lief
import capstone
import sys
import time
from collections import defaultdict

PATH = r"C:\Users\c30080002\AppData\Local\Temp\opencode\uploads\b2dc82db-5a4a-43b0-86c0-31873f23d582\test.so"
TARGET_OFFSETS = {0x20: "real_x_candidate", 0x28: "real_y_candidate", 0x2C: "real_z_candidate"}

print("Parsing ELF...")
t0 = time.time()
binary = lief.parse(PATH)
if binary is None:
    print("ERROR: cannot parse ELF")
    sys.exit(1)

print(f"ELF parsed in {time.time()-t0:.1f}s")
print(f"Architecture: {binary.header.machine_type}")
print(f"Entry: 0x{binary.entrypoint:x}")

# lief 新版本:flags 是枚举,用 (int(seg.flags) & X_FLAG) 或 seg.has()
# ELF segment flags: 1=PF_X(可执行), 2=PF_W, 4=PF_R
# 用 int(seg.flags) 转换
def is_exec(seg):
    try:
        return int(seg.flags) & 1  # PF_X
    except (TypeError, ValueError):
        # 尝试枚举值
        try:
            return int(seg.flags.value) & 1
        except (AttributeError, TypeError):
            return False

# 找可执行段(通常就一个)
exec_segs = []
for seg in binary.segments:
    if seg.type == lief.ELF.Segment.TYPE.LOAD and is_exec(seg):
        exec_segs.append(seg)
        print(f"  Exec segment: vaddr=0x{seg.virtual_address:x} size=0x{seg.physical_size:x} file_off=0x{seg.file_offset:x} flags={seg.flags}")

# 用第一个 exec 段
exec_seg = exec_segs[0]
seg_data = bytes(exec_seg.content)
seg_base = exec_seg.virtual_address
print(f"\nDisassembling exec segment @ 0x{seg_base:x}, size {len(seg_data):,} bytes ({len(seg_data)/1024/1024:.1f} MB)")

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False  # 速度优先
md.skipdata = True  # 跳过无效字节

# 找 STR Wn, [Xreg, #imm12*4] 指令  
# STR Wn, [Xn, #imm12*4]
# capstone 输出 mnemonic='str', op_str='w0, [x19, #0x20]'
# 我们匹配 #0x20 (32), #0x28 (40), #0x2c (44)
TARGET_IMMS = {32, 40, 44}
hits = []  # list of (addr, mnemonic, full_op_str, target_reg, base_reg, imm)

t0 = time.time()
ins_count = 0
total_bytes = len(seg_data)
progress_step = total_bytes // 10  # 10% 进度
next_progress = progress_step

# capstone iter over全段(可能很慢,用 buffer)
# 优化:用 md.disasm 遍历
for ins in md.disasm(seg_data, seg_base):
    ins_count += 1
    if ins_count & 0x100000 == 0 and ins_count > 0:
        # 每 65536 条指令报告进度
        pct = (ins.address - seg_base) * 100 / total_bytes
        elapsed = time.time() - t0
        if pct >= next_progress * 100 / 10:
            print(f"  {pct:.0f}%  ({ins_count:,} instr, {elapsed:.0f}s elapsed, {ins_count/elapsed:.0f} ins/s)")
            next_progress += progress_step
    
    # 匹配 STR Wn, [Xn, #imm]
    if not ins.mnemonic.startswith('str'):
        continue
    op = ins.op_str
    if '[' not in op or ']' not in op:
        continue
    # 提取 [Xn, #imm] 里的 imm
    try:
        # 格式: w10, [x19, #0x20]   或   w10, [x19] (无 imm 走 STUR)
        bracket = op[op.index('[')+1 : op.index(']')]
        # 解析 x19, #0x20 
        parts = [p.strip() for p in bracket.split(',')]
        if len(parts) < 2:
            continue
        base_reg = parts[0].strip()
        imm_str = parts[1].strip()
        if not imm_str.startswith('#'):
            continue
        imm = int(imm_str[1:], 0)  # 支持 0x20 / 32
        if imm in TARGET_IMMS:
            target_reg = op.split(',')[0].strip()
            hits.append((ins.address, ins.mnemonic, op, target_reg, base_reg, imm))
    except (ValueError, IndexError):
        pass

elapsed = time.time() - t0
print(f"\n=== Done ===")
print(f"Scanned {ins_count:,} instructions in {elapsed:.1f}s ({ins_count/elapsed:.0f} ins/s)")
print(f"Hits: {len(hits)} total STR Wn, [Xn, #imm] where imm in {{32,40,44}}")

# 分组统计
from collections import Counter
imm_counter = Counter()
base_reg_counter = Counter()
target_reg_counter = Counter()
for h in hits:
    imm_counter[h[5]] += 1
    base_reg_counter[h[4]] += 1
    target_reg_counter[h[3]] += 1

print(f"\n--- By immediate (offset) ---")
for imm, c in sorted(imm_counter.items()):
    print(f"  +{imm:3d} ({hex(imm):6}): {c} hits")

print(f"\n--- Top 10 base registers (the 'hero pointer' candidates) ---")
for reg, c in base_reg_counter.most_common(10):
    print(f"  {reg}: {c}")

# 保存所有命中
with open(r"D:\SGANEM\test_so_STR_hits.csv", "w", encoding="utf-8") as f:
    f.write("address,offset,base_reg,target_reg,full_op\n")
    for addr, mnem, op, target_reg, base_reg, imm in hits:
        f.write(f"0x{addr:x},{imm},{base_reg},{target_reg},{op}\n")

print(f"\nSaved {len(hits)} hits to D:\\SGANEM\\test_so_STR_hits.csv")
