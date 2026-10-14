# 内核态读取英雄坐标 — 完整流程 (2026-10-14 更新)

## 架构: 纯内核态, 零用户态, 零 /proc, 零 SELinux 依赖

```
KPM 加载 (内核态)
  │
  ▼ 1. hook access_process_vm
  │   hook_fargs5 拦截所有 access_process_vm 调用
  │   检查 arg0(task_struct) 的 comm 字段
  │   匹配 "sgame"/"tmgp" → 记录 g_target_pid
  │
  ▼ 2. reader_thread (kthread, 每 500ms 循环)
  │
  │   2a. 锁定 mm: get_task_mm(g_target_pid) → g_target_mm
  │       使用 override_creds 切换 cred 绕过 SELinux
  │
  │   2b. 定位基址: try_find_base_elf()  ← 新方案
  │       vma_walk 遍历目标 mm 的所有 VMA
  │       对每个可读 VMA (R, 非 RX) 读首 4 字节
  │       匹配 \x7fELF magic → 候选 base = vm_start
  │       读 base + 0xE344EA0 (s_domain 位置):
  │         → 合法 MTE-tagged 堆指针 (>4GB) → 确认 base ✓
  │         → 0 或垃圾 → 不是 base, 继续 ✗
  │       二次验证: s_domain + 0x18 (assemblies begin) 也是合法指针
  │       ★ 完全不碰 /proc, 不需要文件名, 不需要 vm_file/dentry 偏移
  │       ★ IDA 确认: libil2cpp.so LOAD[0] p_vaddr=0, 所以 base = vm_start
  │
  │   2c. 自动发现 UnitLabel 数组: scan_actor_arrays_vma()
  │       vma_walk 遍历匿名 rw VMA
  │       逐 1MB 读内存, 以 UNIT_LABEL_SIZE(184) 步长扫描
  │       特征匹配:
  │         +0x0C camp_id ∈ {1, 2}    (阵营ID)
  │         +0x14 x_pos              (X坐标, 合理范围)
  │         +0x1C z_pos              (Z坐标, 合理范围)
  │         +0x2C hp ≥ 1             (生命值)
  │       命中 → g_actor_begin / g_actor_end
  │
  │   2d. 读取坐标: read_hero_positions()
  │       for i: label = begin + i*184
  │         rm(&camp, label + 0x0C, 4)  → camp_id
  │         rm(&x, label + 0x14, 4)     → x_pos
  │         rm(&z, label + 0x1C, 4)     → z_pos
  │         rm(&hp, label + 0x2C, 4)   → hp
  │       → pr_info 输出到 dmesg
  │
  ▼ 用户态只需: dmesg | grep hero-reader
    (ctl0 手动设置: /data/adb/ksud kpm control hero-reader "set <pid> <base>")
```

## 为什么去掉 /proc/pid/maps?

| 问题 | 原因 |
|------|------|
| kthread 读 /proc/pid/maps → -ENOENT | SELinux 域隔离: kthread 域 u:r:ksu 无权读 app 的 /proc |
| override_creds 方案 | 依赖 cred 结构体偏移, 随内核版本变化 |
| VMA 遍历找文件名 | 依赖 vm_file/dentry 偏移, __randomize_layout 打乱 |
| **ELF magic 扫描** | **零偏移依赖**, 只需 vm_start/vm_end/vm_flags (固定偏移) |

### ELF magic 扫描的陷阱

真机有两个映射都以 file_off=0 开始:
1. 整文件只读映射 (217MB, R)
2. LOAD[0] 段 (0x3A83A34 字节, R)

两者都有 \x7fELF magic IDA 确认 LOAD[0] 的 p_vaddr=0, 所以 base = vm_start

区分方法: 读 candidate + 0xE344EA0 (s_domain 位置):
- 合法堆指针 (>4GB, MTE-tagged) → 正确 base ✓
- 0 或非指针值 → 整文件映射或非 libil2cpp.so ✗

## IDA 确认的偏移 (全部有反编译证据)

### IL2CPP 结构体 (libil2cpp.so)
| 偏移 | 含义 | 证据 |
|------|------|------|
| base + 0xE344EA0 | s_domain | sub_3ACE6DC return &qword_E344EB8 |
| base + 0xE344EB8 | assemblies vector begin | sub_3ACE6DC |
| s_domain + 0x18 | assemblies begin ptr | il2cpp_domain_get_assemblies |
| image + 0x30 | class list ptr | il2cpp_class_from_name (0x3AE19D8) |
| class + 0x10 | class name | il2cpp_class_get_name |
| class + 0xB8 | static_fields | il2cpp_class_get_static_field_data |

### UnitLabel 坐标布局 (libGameCore.so sub_24B2590)
| 偏移 | 含义 | 证据 |
|------|------|------|
| +0x0C | camp_id (阵营) | ldr w4, [x23, #0xc] ↔ 格式串 camp:%d |
| +0x14 | x_pos (X坐标) | ldr w8, [x23, #0x14] ↔ 格式串 x:%d |
| +0x1C | z_pos (Z坐标) | ldr w9, [x23, #0x1c] ↔ 格式串 z:%d |
| +0x2C | hp (生命值) | ldr w?, [x23, #0x2c] ↔ 格式串 hp=%d |
| 0xB8 | 结构体大小=184 | 遍历步长 add x23, x23, #0xb8 |

### VMA 结构体 (真机探针, Android 16 / 6.6.150)
| 偏移 | 含义 |
|------|------|
| +0x00 | vm_start |
| +0x08 | vm_end |
| +0x10 | vm_mm |
| +0x20 | vm_flags |

## 反检测特性

| TP 检测手段 | 本方案是否可见 | 原因 |
|------------|:---:|------|
| /proc 扫描 | ✗ | 不碰 /proc |
| ptrace 检测 | ✗ | 不调用 ptrace |
| fd 扫描 | ✗ | 不打开任何文件 |
| SELinux 审计 | ✗ | 不触发任何 avc 日志 |
| 进程 comm 扫描 | ✗ | kthread 名 "hero-reader" |
| access_process_vm hook | ✗ | hook 本身不修改返回值, 只读 arg0 |

## 剩余待验证项

1. **堆特征扫描假阳性** — 真机上 Java/Dalvik 区可能巧合匹配, 需验证
2. **static_fields → C++ 对象偏移** — IDA 确认 C++ 对象+0x220=UnitLabelFinder, 但 IL2CPP 类的 static_fields 内部哪个偏移持有 C++ 对象指针需真机 dump
3. **VMA 偏移** — vm_start/vm_end/vm_flags 在目标设备内核版本上需验证
