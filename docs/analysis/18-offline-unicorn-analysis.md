# 文档 18：离线模拟分析报告 — Unicorn ARM64 模拟 + 数据流追踪

## 日期：2026-10-22
## 分支：analysis/verify-gameroot-hero-chain
## 提交：da2fed7

## 1. 目标

在不依赖真机测试的情况下，通过 Unicorn ARM64 模拟器和 capstone 静态反汇编，追踪 hero+0x20/+0x28 的真实位置写入者，并找到 ViewManager 无法混淆的位置源。

## 2. 工具链

| 工具 | 版本 | 用途 |
|------|------|------|
| Unicorn Engine | 2.1.4 | ARM64 CPU 模拟执行 |
| capstone | 5.0.7 | 静态反汇编 + 数据流追踪 |
| lief | 1.0.0 | ELF 解析 + GOT 重定位解析 |
| Python venv | - | C:\Users\c30080002\.config\opencode\rea-venv\Scripts\python.exe |

## 3. 分析脚本

| 脚本 | 功能 | 结果 |
|------|------|------|
| unicorn_emu.py | ELF 加载 + 基础模拟验证 | 4/4 测试通过 |
| data_flow_tracer.py | 跟踪 BLR 虚函数调用 | 确认 sub_36A2678 不写 hero+0x20 |
| disasm_analysis.py | 逐条反汇编 sub_3EE11B8 | 发现 13 个 BLR 调用点 |
| vtable_scan2.py | 从重定位表重建 vtable | 发现 15953 个 vtable |
| resolve_vtable_funcs.py | 解析 GOT-thunk | 发现 vtable[19]/[21] 全是 stub |
| resolve_thunk_chain.py | 递归追踪 thunk 链 | 5 层 thunk 全到 nop/ret |
| scan_str_offset20.py | 全 .text 扫 STR +0x20 | 3744 处非 SP 写入 |
| find_hero20_writer.py | 定位 hero+0x20 写入者 | 构造函数 0x36A2C8C |
| analyze_position_gotfuncs.py | 位置 getter 全链追踪 | 确认 fallback 读 hero+0x20 |
| trace_position_chain.py | 深入 3 个 GOT 函数 | sub_3edbea4 = add x0,#0x70 |
| unicorn_position_full.py | Unicorn 模拟 + vtable[24]/[27] | slot24 = animation, slot27 = GOT-thunk |
| unicorn_position_fixed.py | 修复权限问题 + 关键分析 | **发现 hero+0x10/+0x18 是答案** |

## 4. 关键发现

### 4.1 Unicorn 模拟验证（4/4 通过）

| 测试 | 函数 | 读取 | 写入 | 结果 |
|------|------|------|------|------|
| 1 | sub_24AEAC0 (ViewManager) | a1+0x18 (camp) | **a2+0x20, a2+0x28 = 55000** | ✅ 7 条指令 |
| 2 | sub_3ADB960 (距离÷100) | a2+0, a2+8 | 无 | ✅ 10 条指令, X0=15000, X1=20000 |
| 3 | sub_3F7D074 (setter A) | a2+0/+8 | (a1+0x60)+0/+8 | ✅ 6 条指令 |
| 4 | sub_3F7D0B4 (setter B) | a2+0/+8 | (a1+0x78)+0/+8 | ✅ 6 条指令 |

### 4.2 sub_36A2678 每帧更新 — 不写 hero+0x20

Unicorn 模拟（81 条指令）确认 sub_36A2678 写入：
- hero+0x10, +0x18, +0x1C (byte), +0x1D (byte=1), +0x54, +0x58, +0x5C, +0xC8, +0xEA (byte)
- **不写 hero+0x20/+0x28**

### 4.3 vtable[19]/vtable[21] 全是 stub

从 15953 个重定位重建 vtable 发现：
- 最常见的 vtable[19] = 0x3741588（3104 个 vtable）→ GOT → 0x3741584 = **`ret`**（空操作）
- 最常见的 vtable[21] = 0x3741618（3074 个 vtable）→ GOT → 0x37415e8 = **调试日志函数**
- 5 层 thunk 链全部解析完毕，没有隐藏的真实位置更新逻辑

### 4.4 vtable[24] (0xc0) 是动画帧选择器

sub_45c8a90 读取 obj+0x30/+0x34（帧计数）+ obj+0x38（动画速度），做整数除法 + clamping。**这不是位置查询，是动画帧选择。**

### 4.5 位置 getter 函数链

```
sub_25be3b8(&hero+0x20) → position getter:
  Step 1: sub_28e4f24(hero+0x20)     → 查全局 SceneRoot 单例
  Step 2: sub_3edbea4(result)         → add x0, x0, #0x70; ret (偏移 +0x70)
  Step 3: sub_3d19bb8(result, &config_id) → 子节点查找（版本校验 + 索引查表）
  Step 4: IF 查到的场景节点有效:
            → vtable+0xd8 调用获取真实世界坐标
          IF 无效 (cbz/b.ne fallback):
            → 直接读 *(hero+0x20) 和 *(hero+0x28) ← 这就是 ViewManager 混淆的字段
```

### 4.6 关键突破：hero+0x1d 和 hero+0x2d 标志

| 标志 | 设置者 | 值 | 影响 |
|------|--------|-----|------|
| hero+0x1d | sub_36A2678 (每帧) | 恒 = 1 | 直接读 hero+0x10/+0x18（不经场景图查询） |
| hero+0x2d | 构造函数 0x36A2C8C | 恒 = 1 | 直接读 hero+0x20/+0x28（不经场景图查询） |

### 4.7 最终数据流图

```
物理引擎 ─每帧更新─→ hero+0x10 (低32位 = X_mm)
                    → hero+0x18 (Y_mm, 4字节)      ← ViewManager 不碰!

ViewManager ─写55000─→ hero+0x20 (X_mm)             ← 被混淆
                    → hero+0x28 (Y_mm)              ← 被混淆

sub_36A2B44 每帧同步:
  if hero+0x1d == 1:  ← 恒为真 (sub_36A2678 每帧设1)
    读 hero+0x10/+0x18 → visual_obj1 (服务器权威位置)
  if hero+0x2d == 1:  ← 恒为真 (构造函数设1)
    读 hero+0x20/+0x28 → visual_obj2 (渲染位置，被ViewManager混淆)
```

## 5. 方案

**读 `hero+0x10`（低32位 = X 毫米）+ `hero+0x18`（4字节 = Y 毫米）**

- ViewManager 只混淆 hero+0x20/+0x28，不碰 hero+0x10/+0x18
- hero+0x10/+0x18 由物理引擎每帧更新，始终是真实坐标
- 不需要高频 poll，不需要 55000 检测
- Transform 链作为 fallback 保留

## 6. 代码修改

`src/modules/hr_actor_chain.c` 的 `get_actor_coords()` 函数：
- **主路径**：读 hero+0x10（X_mm）+ hero+0x18（Y_mm）
- **安全检测**：55000 值检测 → 跳转 fallback
- **回退**：Transform 链（hero+0xA8 → Node → Link → Transform → VInt3）
- **移除**：不再 fallback 到 spawn position
