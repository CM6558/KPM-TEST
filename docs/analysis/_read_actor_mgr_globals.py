"""
读 off_50E4630 的真实地址 - 检查这是否是 CActorManager 单例
(之前 ledger §8 说 CActorManager::UpdateLogic 用 qword_53F17D8 作为 fallback,
 但 sub_45AAB64 里 line 23-24 也用 off_50E4630)
同时查其他可能的 actor_mgr 全局
"""
import lief

PATH = r"C:\Users\c30080002\AppData\Local\Temp\opencode\uploads\b2dc82db-5a4a-43b0-86c0-31873f23d582\test.so"
binary = lief.parse(PATH)

# 候选全局(可能含 actor_mgr 单例)
CANDIDATES = {
    0x50E4630: "off_50E4630 (CActorManager::UpdateLogic 用的 fallback,可能就是 g_actor_mgr)",
    0x53F17D8: "qword_53F17D8 (另一个 fallback)",
    0x53F1860: "unk_53F1860 (fallback 2)",
    0x53F1890: "unk_53F1890 (fallback 3)",
    0x53F18A8: "unk_53F18A8 (fallback 4)",
    0x53F14C8: "qword_53F14C8 (fallback 5)",
    0x53F16F0: "unk_53F16F0 (fallback 6)",
    0x52717b0: "off_51EA4D0 (GameRoot 单例)",
    0x53DEF90: "qword_53DEF90 (SGCore::HERO_INFO 单例)",
    0x513C768: "off_513C768",
    0x5218FA0: "off_5218FA0",
}

# 拿所有 LOAD segments
data_segs = []
for seg in binary.segments:
    if seg.type == lief.ELF.Segment.TYPE.LOAD:
        try:
            flags_val = int(seg.flags) & 1
        except:
            try:
                flags_val = int(seg.flags.value) & 1
            except:
                flags_val = -1
        try:
            perms = ""
            if int(seg.flags) & 4: perms += "R"
            if int(seg.flags) & 2: perms += "W"
            if int(seg.flags) & 1: perms += "X"
        except:
            perms = "??"
        data_segs.append((seg.virtual_address, bytes(seg.content), perms))

def read_va(va):
    for base, data, perms in data_segs:
        if base <= va < base + len(data):
            offset = va - base
            if offset + 8 <= len(data):
                return int.from_bytes(data[offset:offset+8], 'little')
    return None

# 由重定位表拿 addend
reloc_map = {}
for r in binary.relocations:
    try:
        if r.address in CANDIDATES:
            try:
                addend = r.addend
            except:
                addend = None
            rtype = str(r.type)
            reloc_map[r.address] = (addend, rtype)
    except:
        pass

print(f"{'Address':12} {'Alias':50} {'Slot Value':12} {'Addend':12} {'Type':25} {'指向含义'}")
print("-" * 130)
for addr, alias in sorted(CANDIDATES.items()):
    val = read_va(addr)
    reloc = reloc_map.get(addr, (None, None))
    addend = reloc[0]
    rtype = reloc[1]
    if val is None and addend is None:
        print(f"0x{addr:09x}  {alias:50s}  N/A          N/A          {rtype or 'N/A':25s}  (无重定位,可能是普通指针)")
    else:
        # 看 addend 是不是数据段(可能是单例全局)还是代码段(可能是函数指针)
        is_data = False
        is_code = False
        target = addend if addend else val
        if target:
            for base, data, perms in data_segs:
                if base <= target < base + len(data):
                    is_data = 'W' in perms
                    is_code = 'X' in perms
                    break
        marker = "Data" if is_data else ("Code" if is_code else "?")
        print(f"0x{addr:09x}  {alias:50s}  0x{val or 0:09x}   0x{addend or 0:09x}   {rtype or 'N/A':25s}  {marker}")

# 特别看 off_50E4630 - 这是个 .data 段地址
# 之前在 sub_45AAB64 line 23-24:
#   v6 = off_50E4630  (a1+68 <= 0x14 用 fallback,否则用 a1+40+480)
# 这其实是另一个东西(不是 actor_mgr 全局),是另一个对象的指针表

print("\n=== 重要观察 ===")
print("CActorManager::UpdateLogic (sub_45AAB64) 里 off_50E4630 是局部 fallback,不是全局单例")
print("真正的全局可能是 53F17D8 / 53F1860 / 53F1890 / 53F18A8 / 53F14C8 / 53F16F0")
print("这些 qword_XXX (.bss/.data 段)有可能是引擎其他管理器单例")
