# Hero Reader KPM v3 — 零用户态操作

## 核心设计

```
加载 KPM 后, 用户态什么都不用做:

  1. KPM hook access_process_vm
  2. 游戏启动后, 系统调用 access_process_vm
  3. hook 回调检查被读取的进程 comm 是否含 "sgame"
  4. 命中 → 记录 PID → 遍历 VMA 定位 libil2cpp.so 基址
  5. 启动内核定时器 (每 500ms)
  6. 定时器在内核态读 Actor 数组 → 写内核日志

  查看结果: dmesg | grep hero-reader
  (dmesg 读取内核日志, 不触发 TP 检测)
```

## 数据流

```
内核态 (EL1)
┌──────────────────────────────────────────────┐
│ hero_reader.kpm                              │
│                                              │
│  ① hook access_process_vm                   │
│     ↓ 游戏进程触发                           │
│  ② find_task_by_vpid(pid)                   │
│     ↓                                        │
│  ③ 遍历 VMA → 匹配 "libil2cpp.so"          │
│     ↓ vm_start = 基址                        │
│  ④ base + 0xE340030 → s_domain 指针          │
│     ↓                                        │
│  ⑤ 扫描堆内存 → Actor 数组定位               │
│     ↓                                        │
│  ⑥ 定时器每 500ms 读取坐标                   │
│     ↓                                        │
│  ⑦ pr_info() → 内核日志                      │
│                                              │
│  用户态: dmesg | grep hero-reader            │
│  (只读日志, 不可检测)                        │
└──────────────────────────────────────────────┘

用户态 (EL0)
┌──────────────────────────────────────────────┐
│ 王者荣耀进程                                  │
│  └─ libtersafe.so (TP)  ← 看不到内核操作     │
│                                              │
│ (无任何额外用户态进程/文件/socket)             │
└──────────────────────────────────────────────┘
```

## 部署

```bash
# 1. 编译
git clone https://github.com/bmax121/KernelPatch.git ~/KernelPatch
cd kpm_hero_reader && make

# 2. 推送到设备并加载
adb push hero_reader.kpm /data/local/tmp/
kpmctl load /data/local/tmp/hero_reader.kpm

# 3. 等游戏启动, 查看日志
adb shell dmesg | grep hero-reader
```

## 零用户态体现在

| 操作 | 是否需要用户态进程? | TP 可检测? |
|------|:---:|:---:|
| 捕获游戏进程 PID | ❌ hook 自动捕获 | ❌ |
| 定位 libil2cpp.so 基址 | ❌ 内核遍历 VMA | ❌ |
| 读取 s_domain 指针 | ❌ access_process_vm | ❌ |
| 定位 Actor 数组 | ❌ 内核堆内存扫描 | ❌ |
| 读取英雄坐标 | ❌ 内核定时器+access_process_vm | ❌ |
| 查看结果 | dmesg (可选) | ❌ 只读日志 |

## 待完善部分

1. **VMA 遍历偏移**: `vm_start`/`vm_next`/`vm_file` 在 mm_struct 中的偏移需根据目标设备内核版本确认。KernelPatch 导出 `mm_struct_offset` 和 `task_struct_offset` 可辅助定位。

2. **Actor 数组自动发现**: 当前框架已有堆内存特征扫描 (连续 1008 字节块 + camp_id=1|2), 需要完整实现 VMA 遍历 + 分页扫描逻辑。

3. **IL2CPP 类型系统遍历 (路径B)**: 从 `s_domain` → assemblies → image → classes → static_fields 的完整遍历链, 需要 Il2CppAssembly/Il2CppImage/Il2CppClass 的精确偏移。可通过 IDA 进一步确认。
