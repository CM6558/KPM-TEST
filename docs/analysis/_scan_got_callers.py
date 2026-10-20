"""
扫描所有 ADRP + LDR 指令对,反查 GOT slot 实际调用点
ARM64 访问全局变量标准模式:
  ADRP Xn, #page_addr       ; 加载 4KB 页基址(load 4KB page base)
  LDR  Xm, [Xn, #page_offset]  ; 加载页内偏移
组合后等价于:加载 *(page_addr + page_offset) — 即从 GOT 拿函数指针

我们要找的 GOT slot 地址:
  off_5153CD0, off_51AF748, off_517F388, off_5156700
  实际上还有一些类似的:
  off_508C790, off_509C070, off_5115E70, off_50B0C90, off_50A5BA0, off_50A5B, off_5090010
  
但本轮先精解关键 4 个。
策略:
1. 用 lief 拿 .text 段
2. capstone 反汇编整个段
3. 对每个 ADRP Xn, #imm 记录 {reg, page_base, insn_addr}
4. 对每个 LDR Xm, [Xn, #imm12*8] 查最近的 ADRP(同寄存器,前 1-3 条指令内)
   组合:target_addr = ADRP_page + LDR_offset
5. 若 target_addr ∈ {5153CD0, 51AF748, 517F388, 5156700},记录调用点
6. 后跟 LDR/B DR/BLR 用法的就是 indirect call(got → function pointer → call)
"""
import lief, capstone, sys
from collections import defaultdict, Counter

PATH = r"C:\Users\c30080002\AppData\Local\Temp\opencode\uploads\b2dc82db-5a4a-43b0-86c0-31873f23d582\test.so"

# 4 个关键 GOT slot 地址
TARGET_GOT = {
    0x5153CD0: "off_5153CD0 (hero位置写入包装)",
    0x51AF748: "off_51AF748 (MovementComponent 真正更新)",
    0x517F388: "off_517F388 (距离计算+坐标读取)",
    0x5156700: "off_5156700 (金币计算)",
    # 另几个之前发现的
    0x5153CC0: "off_5153CC0 (类似 5153CD0)",
    0x5153CB0: "off_5153CB0",
    0x5153D00: "off_5153D00",
    0x5153D00: "off_5153D00",
    0x5153D00: "off_5153D00",
    # 取消重复
}

# 去重
TARGET_GOT = dict(TARGET_GOT)
print(f"Tracking {len(TARGET_GOT)} GOT slots:")
for addr, name in sorted(TARGET_GOT.items()):
    print(f"  0x{addr:09x}  {name}")

# 解析 ELF
binary = lief.parse(PATH)
exec_seg = None
for seg in binary.segments:
    if seg.type == lief.ELF.Segment.TYPE.LOAD:
        try:
            if int(seg.flags) & 1:  # PF_X
                exec_seg = seg
                break
        except:
            try:
                if int(seg.flags.value) & 1:
                    exec_seg = seg
                    break
            except:
                pass

seg_data = bytes(exec_seg.content)
seg_base = exec_seg.virtual_address
print(f"\nExec segment @ 0x{seg_base:x}, size {len(seg_data):,} bytes")

# 反汇编
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True  # 需要 detail 拿到 ops
md.skipdata = True

# 拿 .dynsym + .symtab(若有)符号表 → 函数边界
func_symbols = []
for sym in binary.symbols:
    try:
        if sym.type == lief.ELF.Symbol.TYPE.FUNC and sym.value > 0 and sym.size > 0:
            func_symbols.append((sym.value, sym.value + sym.size, sym.name))
    except:
        pass

# 也从 .dynsym 拿
try:
    for sym in binary.dynamic_symbols:
        try:
            if sym.type == lief.ELF.Symbol.TYPE.FUNC and sym.value > 0 and sym.size > 0:
                func_symbols.append((sym.value, sym.value + sym.size, sym.name))
        except:
            pass
except:
    pass

func_symbols.sort()
print(f"\nFound {len(func_symbols)} function symbols")

# 二分查 addr 在哪个函数
import bisect
func_starts = [f[0] for f in func_symbols]
def find_func(addr):
    i = bisect.bisect_right(func_starts, addr) - 1
    if i < 0: return None
    start, end, name = func_symbols[i]
    if start <= addr < end:
        return (start, end, name)
    return None

# 滑动窗口扫:为每个 ADRP Xn,#imm,记录 reg→(addr, page_base)
# 然后看后续 5 条内 LDR Xm, [Xn, #imm12] — 拿 offset 拼目标地址
# 拼到 GOT 地址就在 TARGET_GOT 内,记录

# 由于函数符号可能不全(很多 sub_xxx 没符号),我们尽量宽匹配
adrp_state = {}  # reg: (insn_addr, page_base)
# 跟踪最近 5 条指令的 ADRP(每个寄存器独立保留最近一次)

hits = []  # list of (got_addr, got_name, callee_addr, callee_xreg, func_addr, func_name, surrounding_5_insns)

import time
t0 = time.time()
n = 0
# 用列表 buf 控制 instruction iteration
# 提前为每个 ADRP 后续 5 条扫一次
window = []  # (addr, mnem, op_str, detail) 最近 5 条

INSN_WINDOW = 5

for ins in md.disasm(seg_data, seg_base):
    n += 1
    if n & 0xFFFFFFF == 0:
        print(f"  scanned {n:,} (1M insns), {time.time()-t0:.0f}s, hits={len(hits)}")
    
    # 检测 LDR Xm, [Xn, #imm] 形式
    if ins.mnemonic == 'ldr':
        ops = ins.operands
        if len(ops) == 2 and ops[0].type == capstone.arm64.ARM64_OP_REG and ops[1].type == capstone.arm64.ARM64_OP_MEM:
            base_reg = ops[1].mem.base
            disp = ops[1].mem.disp
            # 看最近 ADRP 该 reg
            if base_reg in adrp_state:
                adrp_addr, page_base = adrp_state[base_reg]
                target_addr = page_base + disp
                if target_addr in TARGET_GOT:
                    func = find_func(ins.address)
                    func_addr = func[0] if func else None
                    func_name = func[2] if func else f"sub_{ins.address:X}"
                    # 拿周围 5 条
                    surrounding = [(w[0], w[1], w[2]) for w in window[-5:]]
                    hits.append({
                        'got_addr': target_addr,
                        'got_name': TARGET_GOT[target_addr],
                        'callee_addr': ins.address,
                        'callee_reg': ops[0].reg,
                        'adrp_addr': adrp_addr,
                        'func_addr': func_addr,
                        'func_name': func_name,
                        'surrounding': surrounding
                    })
    
    # 检测 ADRP Xn, #imm  更新 adrp_state
    elif ins.mnemonic == 'adrp':
        try:
            ops = ins.operands
            if len(ops) == 2 and ops[0].type == capstone.arm64.ARM64_OP_REG:
                reg = ops[0].reg
                imm = ops[1].imm
                page_base = imm  # ADRP imm 是页基址
                adrp_state[reg] = (ins.address, page_base)
        except:
            pass
    
    # 保持最近窗口
    window.append((ins.address, ins.mnemonic, ins.op_str))
    if len(window) > INSN_WINDOW:
        window.pop(0)

elapsed = time.time() - t0
print(f"\n=== Done ===")
print(f"Scanned {n:,} insns in {elapsed:.1f}s, hits={len(hits)}")

# 按 GOT slot 分组统计
from collections import Counter
got_counter = Counter()
got_by_func = defaultdict(set)
for h in hits:
    got_counter[h['got_name']] += 1
    got_by_func[h['got_name']].add((h['func_addr'], h['func_name']))

print(f"\n=== Hits by GOT slot ===")
for name, c in got_counter.most_common():
    funcs = got_by_func[name]
    print(f"  {name}: {c} hits in {len(funcs)} functions")
    for fa, fn in list(funcs)[:5]:
        print(f"    -> 0x{fa:x} {fn}")
    if len(funcs) > 5:
        print(f"    ... and {len(funcs)-5} more")

print(f"\n=== First 30 hits ===")
for i, h in enumerate(hits[:30]):
    print(f"#{i:2d} {h['got_name']:50s} callee_addr=0x{h['callee_addr']:09x} func={h['func_name']}")

# 保存全部 hits 到 CSV
with open(r"D:\SGANEM\test_so_GOT_callers.csv", "w", encoding="utf-8") as f:
    f.write("got_addr,got_name,callee_addr,adrp_addr,func_addr,func_name,base_reg,target_reg\n")
    for h in hits:
        f.write(f"0x{h['got_addr']:x},{h['got_name']},0x{h['callee_addr']:x},0x{h['adrp_addr']:x},{h['func_addr'] if h['func_addr'] else ''},{h['func_name']},\n")

print(f"\nSaved {len(hits)} hits to D:\\SGANEM\\test_so_GOT_callers.csv")
