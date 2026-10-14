# 完整流程文档 (2026-10-14 更新)

## 架构: 纯内核态, 零用户态, 零 /proc, 零 SELinux 依赖

### 主路径: 纯指针链 (libGameCore.so .bss → 坐标)

```
KPM 加载 (内核态)
  │
  ▼ ① hook access_process_vm
  │   hook_fargs5 拦截所有 access_process_vm 调用
  │   读 arg0(task_struct)->comm, 匹配 "sgame"/"tmgp"
  │   → g_target_pid = 游戏PID
  │
  ▼ ② reader_thread (kthread, 每 500ms 循环)
  │
  │   ②a. 锁定 mm: get_task_mm(g_target_pid) → g_target_mm
  │
  │   ②b. 定位 libGameCore.so base: try_find_gc_base()
  │        vma_walk 遍历 mm->mmap 链表
  │        对每个 R(非RX) 的 VMA 读前4字节
  │        匹配 \x7fELF → 候选 gc_base = vm_start
  │        验证: 读 gc_base + 0x53ddb90 → NULL 或合法堆指针 (manager)
  │        二次验证: manager+0x220 也是合法指针 (UnitLabelFinder)
  │        通过 → g_gc_base = vm_start
  │
  │   ②c. 纯指针链读取坐标: read_hero_positions_chain()
  │        gc_base + 0x53ddb90  → GameTacticsManager*   (.bss 全局, capstone 确认)
  │        manager + 0x220       → UnitLabelFinder        (IDA 确认)
  │        ulf + 0xC8           → UnitLabel 数组 begin    (IDA 确认)
  │        ulf + 0xD0           → UnitLabel 数组 end       (IDA 确认)
  │        验证: (end - begin) % 184 == 0                  (IDA 确认步长)
  │        遍历数组:
  │          UnitLabel[i] + 0x0C → camp_id                  (IDA 确认)
  │          UnitLabel[i] + 0x14 → x_pos                    (IDA 确认)
  │          UnitLabel[i] + 0x1C → z_pos                    (IDA 确认)
  │          UnitLabel[i] + 0x2C → hp                       (IDA 确认)
  │        → pr_info → dmesg
  │
  ▼ 用户态: dmesg | grep hero-reader
    手动触发: ctl0 chain
```

### 关键发现: C++ 对象不在 IL2CPP static_fields 中

```
旧路径 (已确认断裂):
  libil2cpp_base + 0xE344EA0 → s_domain → assemblies → classes
  → class + 0xB8 → static_fields + ??? → C++ 对象  ← ❌ 断裂!

新路径 (capstone 确认):
  libGameCore_base + 0x53ddb90 → GameTacticsManager*  ← ✅ .bss 全局指针

根因:
  libGameCore.so 不导入任何 il2cpp_* 函数 (672 个 PLT 导入全部检查)
  C++ 对象由 libGameCore.so 内部 lazy-init 创建, 完全独立于 C# 层

Evidence:
  lazy-init @ vaddr 0x3167510:
    adrp x19, #0x53dd000
    ldr  x0, [x19, #0xb90]      ← x0 = *(0x53ddb90) = GameTacticsManager*
    cbz  x0, init                 ← 未初始化则创建
    ret                            ← 已初始化直接返回
  init:
    mov  w0, #0x38c0              ← malloc(14528 bytes)
    bl   malloc
    str  x0, [x19, #0xb90]       ← 存回 .bss 全局变量
```

## 完整指针链 (零扫描, 全确定性)

| 步骤 | 偏移 | 含义 | 证据来源 |
|------|------|------|---------|
| ① hook | comm 匹配 | 捕获游戏 PID | hook access_process_vm |
| ② 定位 base | ELF magic \x7fELF + manager 验证 | libGameCore.so base | VMA 遍历 (纯内核态) |
| ③ | gc_base + 0x53ddb90 | GameTacticsManager* | capstone: lazy-init 0x3167510 |
| ④ | manager + 0x220 | UnitLabelFinder 子对象 | IDA: Init 0x276a198: add x0, x24, #0x220 |
| ⑤ | ulf + 0xC8 | UnitLabel 数组 begin | IDA: sub_24B2590: ldr [x21, #0xC8] |
| ⑥ | ulf + 0xD0 | UnitLabel 数组 end | IDA: sub_24B2590: ldr [x21, #0xD0] |
| ⑦ | (end-begin) % 184 | 验证数组步长 | IDA: add x23, x23, #0xB8 |
| ⑧ | label + 0x0C | camp_id (阵营) | IDA: ldr w4, [x23, #0xC] ↔ camp:%d |
| ⑨ | label + 0x14 | x_pos (X坐标) | IDA: ldr w8, [x23, #0x14] ↔ x:%d |
| ⑩ | label + 0x1C | z_pos (Z坐标) | IDA: ldr w9, [x23, #0x1C] ↔ z:%d |
| ⑪ | label + 0x2C | hp (生命值) | IDA: ldr w25, [x23, #0x2C] ↔ hp=%d |

**全链路零扫描**: 每一步都有明确的偏移值和反编译证据, 不依赖任何盲扫或猜测。

## ctl0 命令一览

| 命令 | 作用 |
|------|------|
| `chain` | 手动触发纯指针链读取坐标 (主路径) |
| `scan` | 手动触发堆特征扫描 (备用路径) |
| `probe <类名>` | metadata 探测: 解析类型表+字段表, 打印指定类所有字段偏移 |
| `findclass <类名>` | IL2CPP 类型系统: 遍历 VMA 找 class name 匹配 |
| `walk` | IL2CPP 指针链遍历: domain→assemblies→images→classes |
| `dump <地址> <字数>` | dump 指定地址的内存 (16字节/行) |
| `peek <地址> [个数]` | peek 8字节值 |
| `set <pid> <base>` | 手动设置 PID 和 libil2cpp.so base |
| `read` | 手动读取一次坐标 (需先 actors 或 scan) |
| `reset` | 重置所有状态 |

## 备用路径 (保留向后兼容)

如果主路径 (libGameCore.so 指针链) 失败:
1. `try_find_base_elf()` 定位 libil2cpp.so base (ELF magic + s_domain 验证)
2. `scan_actor_arrays()` 堆特征扫描 (184步长 + camp/hp/x/z 判据)
3. `probe ActorManager` metadata 探测 (运行时内存中已解密的 metadata)

## 反检测特性

| TP 检测手段 | 是否可见 | 原因 |
|------------|:---:|------|
| /proc 扫描 | ✗ | 不碰 /proc |
| ptrace 检测 | ✗ | 不调用 ptrace |
| fd 扫描 | ✗ | 不打开任何文件 |
| SELinux 审计 | ✗ | 不触发任何 avc 日志 |
| 进程 comm 扫描 | ✗ | kthread 名 "hero-reader" |
| access_process_vm hook | ✗ | hook 只读 arg0 不修改返回值 |
| 用户态痕迹 | ✗ | 全程内核态 (EL1), 用户态零操作 |

## 诊断工具

### probe 命令 (metadata 探测)

从 `g_base + 0xE340010` (s_metadata 指针) 读取运行时内存中已解密的 metadata:
1. 验证 magic (0xFAB11BAF) + version (29)
2. 解析类型定义表 → 匹配目标类名
3. 解析字段定义表 → 打印所有字段 name + offset
4. 诊断: 打印前 10 个 typedef 类名 (验证结构体大小是否正确)

注意: 磁盘上的 global-metadata.dat 部分加密 (类型表类名是乱码),
但运行时内存中的版本由 il2cpp_init() 解密, probe 读的是内存版本。

## 待真机验证项

1. libGameCore.so 的 .bss 偏移 0x53ddb90 (capstone 静态分析, 需真机确认)
2. manager+0x220 在真机上是否是 UnitLabelFinder (IDA 确认的 Init 函数偏移)
3. ELF magic VMA 扫描在真机上是否正确定位 libGameCore.so (2候选验证)
4. manager 在游戏未进入对局时为 NULL (lazy-init 未触发), 进入对局后才有值
5. probe 命令的 TYPEDEF_SIZE=108 在真机上是否正确 (诊断前10个类名验证)
