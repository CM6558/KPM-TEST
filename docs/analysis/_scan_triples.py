"""
第二轮扫描:找"连续写 +32/+40/+44 三件套"的指令位置
hero 真实坐标 (x,y,z) 写入往往是 3 条 STR 指令连续出现
这种模式 100% 是坐标写入(不是普通的 struct field 写)
"""
import lief
import capstone
import sys
import time
from collections import Counter, defaultdict

PATH = r"C:\Users\c30080002\AppData\Local\Temp\opencode\uploads\b2dc82db-5a4a-43b0-86c0-31873f23d582\test.so"

print("Parsing ELF...")
binary = lief.parse(PATH)

# 找可执行段
def is_exec(seg):
    try:
        return int(seg.flags) & 1
    except (TypeError, ValueError):
        try:
            return int(seg.flags.value) & 1
        except (AttributeError, TypeError):
            return False

exec_seg = None
for seg in binary.segments:
    if seg.type == lief.ELF.Segment.TYPE.LOAD and is_exec(seg):
        exec_seg = seg
        break

seg_data = bytes(exec_seg.content)
seg_base = exec_seg.virtual_address
print(f"Exec seg @ 0x{seg_base:x}, size {len(seg_data):,}")

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False
md.skipdata = True

# 扫描全部指令,记录所有 STR 写 +32/+40/+44 配对:
# 一个有效 (x,y,z) 写入 pattern:
#  STR W_a, [Xb, #32]
#  STR W_c, [Xb, #40]   (同一 Xb)
#  STR W_d, [Xb, #44]   (同一 Xb)
# 允许中间有 1-3 条其他指令(可能插 LDR/计算)

# 我们用滑动窗口:对每条 STR Wn,[Xb,#32],看后面 15 条内是否有
#   STR Wm,[Xb,#40] 和 STR Wk,[Xb,#44](Xb 必须相同)
TARGET_32 = 32
TARGET_40 = 40
TARGET_44 = 44

# 第一步:取所有 STR 指令(RX_X 字段也提取)
# 输出:list of (addr, base_reg, imm, target_reg, op_str)
all_str = []  # 全部 str 指令(用滑动窗口前需要预扫)

t0 = time.time()
n = 0
for ins in md.disasm(seg_data, seg_base):
    n += 1
    if n & 0xFFFFFFF == 0:
        print(f"  scanned {n:,} instr, {time.time()-t0:.0f}s")
    if not ins.mnemonic.startswith('str'):
        continue
    op = ins.op_str
    if '[' not in op or ']' not in op:
        continue
    try:
        bracket = op[op.index('[')+1:op.index(']')]
        parts = [p.strip() for p in bracket.split(',')]
        if len(parts) < 2:
            continue
        base_reg = parts[0]
        imm_str = parts[1].strip()
        if not imm_str.startswith('#'):
            continue
        imm = int(imm_str[1:], 0)
        target_reg = op.split(',')[0].strip()
        all_str.append((ins.address, base_reg, imm, target_reg, op))
    except (ValueError, IndexError):
        pass

print(f"\nFirst pass done in {time.time()-t0:.1f}s, total instr={n:,}, str={len(all_str):,}")

# 第二步:对所有 STR +32, 找后续 15 条内的 STR +40/+44 (base_reg 相同)
# all_str 已经按 addr 顺序排列
triple_hits = []  # list of (addr32, addr40, addr44, base_reg, target_regs)

# 用 dict 加速:按 base_reg + imm 分组
from collections import defaultdict
by_base_imm = defaultdict(list)  # (base_reg, imm) -> [(addr, target_reg), ...]
for addr, base_reg, imm, target_reg, _op in all_str:
    if imm in (32, 40, 44):
        by_base_imm[(base_reg, imm)].append((addr, target_reg))

print(f"\nBy (base_reg, imm) counts for candidate offsets:")
print(f"  +32 hit groups: {len([k for k in by_base_imm if k[1]==32])}")
print(f"  +40 hit groups: {len([k for k in by_base_imm if k[1]==40])}")
print(f"  +44 hit groups: {len([k for k in by_base_imm if k[1]==44])}")

# 找 triple 模式: 同一 base_reg 下,+32 和 +40 和 +44 三条指令地址 < 64 字节内(16 条指令内)
# 同时记下窗口大小
common_bases = set()
for (base, imm), lst in by_base_imm.items():
    common_bases.add(base)

triple_count_per_base = Counter()
results = []  # tuples (base_reg, addr32, addr40, addr44, target32, target40, target44, gap_bytes)

for base in common_bases:
    lst32 = by_base_imm.get((base, 32), [])
    lst40 = by_base_imm.get((base, 40), [])
    lst44 = by_base_imm.get((base, 44), [])
    if not (lst32 and lst40 and lst44):
        continue
    
    # 对每个 +32, 试图配对 +40 和 +44 在 64 字节窗口内
    # 三指针:简单办法,每个 32 扫描后续 40 and 44
    # 排除 sp(栈)
    if base == 'sp':
        continue
    
    i40 = 0
    i44 = 0
    for addr32, t32 in lst32:
        # 找下一个 +40,地址大于 addr32,在 64 字节内
        while i40 < len(lst40) and lst40[i40][0] < addr32:
            i40 += 1
        if i40 >= len(lst40):
            break
        addr40, t40 = lst40[i40]
        if addr40 - addr32 > 64:  # 64 字节窗口 = ~16 指令
            continue
        
        # 找下一个 +44,地址大于 addr40,在 64 字节内
        while i44 < len(lst44) and lst44[i44][0] < addr40:
            i44 += 1
        if i44 >= len(lst44):
            break
        addr44, t44 = lst44[i44]
        if addr44 - addr40 > 64:
            continue
        
        triple_count_per_base[base] += 1
        results.append((base, addr32, addr40, addr44, t32, t40, t44, addr44 - addr32))

print(f"\n=== TRIPLE HITS (STR +32; +40; +44 within 64 bytes, same base reg) ===")
print(f"Total triple patterns: {len(results)}")
print(f"\nBy base register:")
for base, c in triple_count_per_base.most_common(20):
    print(f"  {base:5s}: {c}")

print(f"\n=== First 30 triple hits (sorted by gap ===")
# 按窗口 gap 排序,小的更可能是连续写入 (x,y,z)
results.sort(key=lambda r: (r[7], r[1]))
print(f"{'base':6} {'addr32':>12} {'addr40':>12} {'addr44':>12} {'t32':>5} {'t40':>5} {'t44':>5} {'gap':>4}")
for base, a32, a40, a44, t32, t40, t44, gap in results[:30]:
    print(f"{base:6} 0x{a32:010x} 0x{a40:010x} 0x{a44:010x} {t32:5} {t40:5} {t44:5} {gap:4d}")

# 保存全部结果到 CSV
with open(r"D:\SGANEM\test_so_STR_triples.csv", "w", encoding="utf-8") as f:
    f.write("base_reg,addr32,addr40,addr44,t32,t40,t44,gap_bytes\n")
    for base, a32, a40, a44, t32, t40, t44, gap in results:
        f.write(f"{base},0x{a32:x},0x{a40:x},0x{a44:x},{t32},{t40},{t44},{gap}\n")

print(f"\nSaved {len(results)} triples to D:\\SGANEM\\test_so_STR_triples.csv")
print(f"\nTotal time: {time.time()-t0:.1f}s")
