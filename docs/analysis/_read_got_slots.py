"""
直接读取 4 个关键 GOT slot 的值,看真实指向的函数地址

GOT slot 在 ELF 的 .got 或 .got.plt 段
每个 slot 在 AArch64 是 8 字节(64 位指针)
我们读这些 slot,值就是真实函数的虚拟地址

注意:有些 GOT slot 是动态重定位(运行时填的),静态文件里可能为 0
     但 off_5153CD0 这种 IDA 命名的 slot 通常已经在 .got 段里初始化为某值
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
    0x5153CC0: "off_5153CC0",
    0x5153D00: "off_5153D00",
    0x50C0C30: "off_50C0C30 (log profiler)",
    0x50C0C38: "off_50C0C38 (profiler end)",
    0x50C0C90: "off_50C0C90 (profiler mark)",
    0x50B0C90: "off_50B0C90 (profiler mark v2)",
    0x51EA4D0: "off_51EA4D0 (GameRoot 单例)",
    0x508C790: "off_508C790",
    0x509C070: "off_509C070",
    0x5115E70: "off_5115E70",
}
TARGET_GOT = dict(TARGET_GOT)

# 拿所有 LOAD segments
print("=== LOAD segments ===")
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
        perms = ""
        try:
            if int(seg.flags) & 4: perms += "R"
            if int(seg.flags) & 2: perms += "W"
            if int(seg.flags) & 1: perms += "X"
        except:
            perms = "??"
        print(f"  vaddr=0x{seg.virtual_address:09x} size=0x{seg.physical_size:x} file_off=0x{seg.file_offset:x} flags={perms}")
        data_segs.append((seg.virtual_address, bytes(seg.content), perms))

def read_va(va):
    """读 8 字节 from virtual address"""
    for base, data, perms in data_segs:
        if base <= va < base + len(data):
            offset = va - base
            if offset + 8 <= len(data):
                return int.from_bytes(data[offset:offset+8], 'little')
    return None

print(f"\n=== GOT slot values ===")
for got_addr, name in sorted(TARGET_GOT.items()):
    val = read_va(got_addr)
    if val is None:
        print(f"  0x{got_addr:09x}  {name:50s}  -> NOT MAPPED")
    elif val == 0:
        print(f"  0x{got_addr:09x}  {name:50s}  -> 0 (空,可能动态重定位)")
    else:
        # 看是不是 EXEC 段里的地址(函数地址)
        is_func_addr = False
        for base, data, perms in data_segs:
            if base <= val < base + len(data):
                is_func_addr = 'X' in perms
                break
        marker = "*Function*" if is_func_addr else "Data?"
        print(f"  0x{got_addr:09x}  {name:50s}  -> 0x{val:09x}  {marker}")
