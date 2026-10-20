"""
通过 .rela.dyn 重定位表拿 GOT slot 的 symbol name
"""
import lief

PATH = r"C:\Users\c30080002\AppData\Local\Temp\opencode\uploads\b2dc82db-5a4a-43b0-86c0-31873f23d582\test.so"
binary = lief.parse(PATH)

TARGET_GOT = {
    0x5153CD0: "off_5153CD0 (hero位置写入包装)",
    0x51AF748: "off_51AF748 (MovementComponent 真正更新)",
    0x517F388: "off_517F388 (距离计算+坐标读取)",
    0x5156700: "off_5156700 (金币计算)",
    0x5153CB0: "off_5153CB0",
    0x5153CC0: "off_5153CC0",
    0x5153D00: "off_5153D00",
    0x50C0C30: "off_50C0C30 (log)",
    0x50C0C38: "off_50C0C38",
    0x50C0C90: "off_50C0C90",
    0x50B0C90: "off_50B0C90",
    0x51EA4D0: "off_51EA4D0 (GameRoot 单例)",
    0x508C790: "off_508C790",
    0x509C070: "off_509C070",
    0x5115E70: "off_5115E70",
    0x50A5BA0: "off_50A5BA0",
    0x50A0178: "off_50A0178",
    0x5226D00: "off_5226D00",
    0x5226D70: "off_5226D70",
    0x5226DB0: "off_5226DB0",
}

# 构造 GOT 地址 → symbol 映射
got_to_sym = {}

# 通过 PLTREL / DYN RELA
try:
    relocs = list(binary.pltgot_relocations)
    print(f"PLT relocs: {len(relocs)}")
except:
    print("no pltgot_relocations attribute")

try:
    dyn_relocs = list(binary.dynamic_relocations)
    print(f"Dynamic relocs: {len(dyn_relocs)}")
except:
    dyn_relocs = []

# 列举所有重定位记录
print("\n=== 重定位记录(所有 type 的)===")
all_relocs = []
try:
    for r in binary.relocations:
        all_relocs.append(r)
except:
    pass
print(f"Total relocations: {len(all_relocs)}")

# 提取每个 GOT slot 对应的 symbol
print("\n=== Our GOT slots ===")
for got_addr, alias_name in sorted(TARGET_GOT.items()):
    found = None
    found_type = None
    for r in all_relocs:
        try:
            if r.address == got_addr:
                sym = None
                try:
                    if hasattr(r, 'symbol') and r.symbol:
                        sym = r.symbol.name
                    if not sym and hasattr(r, 'addend'):
                        sym = f"addend=0x{r.addend:x}"
                except:
                    pass
                rtype = None
                try:
                    rtype = r.type
                except:
                    pass
                found = sym
                found_type = rtype
                # 拿 first match
                break
        except:
            continue
    print(f"  0x{got_addr:09x}  {alias_name:50s}  -> sym={found or 'NO_MATCH'}  type={found_type}")

# 另一个办法:列出所有重定位及关联 symbol,然后匹配 GOT
print("\n=== Relocations with symbols (looking for our GOTs) ===")
target_set = set(TARGET_GOT.keys())
matched = 0
sample = 0
for r in all_relocs:
    try:
        if r.address in target_set:
            sym = None
            if hasattr(r, 'symbol') and r.symbol:
                sym = r.symbol.name
            matched += 1
            alias = TARGET_GOT[r.address]
            print(f"  0x{r.address:09x}  {alias:50s}  -> {sym}")
    except:
        pass

print(f"\nMatched: {matched}/{len(target_set)} GOT slots to relocations")

# 另外列几个非 target 的样例(看 reloc 长什么样)
print("\n=== Sample relocations (first 10 with symbols) ===")
n_printed = 0
for r in all_relocs:
    try:
        if hasattr(r, 'symbol') and r.symbol and r.symbol.name:
            sym = r.symbol.name
            print(f"  0x{r.address:09x}  type={r.type}  sym={sym[:80]}")
            n_printed += 1
            if n_printed >= 10:
                break
    except:
        pass
