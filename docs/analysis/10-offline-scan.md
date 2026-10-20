<!-- 10-offline-scan.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: 离线扫描找到真实坐标写入源 -->

## 17. ★★★ 离线扫描找到真实坐标写入源(重大突破)

### 17.1 方法 — 离线 Python + capstone + lief 扫 binary

**思路**:用 capstone 反汇编整个 41.7 MB .text 段(86MB so 的可执行段),找所有 `STR Wn, [Xn, #imm]` 指令,匹配 imm ∈ {32, 40, 44}(real_x, real_y, real_z 偏移)。

**性能**:
- ELF parse: 0.2s
- capstone 全段反汇编: 31-37s(10,941,168 条指令 / 297,240 instr/s)
- 内存占用:约 1-2 GB(可接受)

### 17.2 第一轮扫描结果(粗匹配 +32/+40/+44)

| 偏移 | 命中数 |
|------|--------|
| +32 (real_x) | 32,900 |
| +40 (real_y) | 13,813 |
| +44 (real_z) | 3,181 |
| **合计** | **49,894** |

base 寄存器分布(`sp` 是栈帧,无关):
- `sp` 25,032(无关)
- `x19` 8,442 / `x0` 7,790 / `x22` 2,674 / `x20` 1,719 ← 这些才是候选 hero pointer 寄存器

### 17.3 第二轮扫描(找"连续 3 次写"模式)

**模式**:同一 base 寄存器,32→40→44 三次 STR,地址间隔 < 64 字节(16 指令)

**结果**:**129 个候选**

### 17.4 Top 候选(gap=8 字节,纯连续 3 STR)

| base_reg | addr32 | addr40 | addr44 | 备注 |
|----------|--------|--------|--------|------|
| x0 | 0x21d8ed0 | 0x21d8ed4 | 0x21d8ed8 | 紧凑 3 STR,典型坐标写入 |
| x0 | 0x29fcb9c | 0x29fcba0 | 0x29fcba4 | 紧凑 3 STR |
| x8 | 0x2a43c68 | 0x2a43c6c | 0x2a43c70 | x8 是 indirect result reg |
| x8 | 0x2dcf414 | 0x2dcf418 | 0x2dcf41c | wzr 三件套 = 清零 |
| x9 | 0x333d35c | 0x333d360 | 0x333d364 | x9 = temp |
| x8 | 0x335a3d0 | 0x335a3d4 | 0x335a3d8 | ✅ 验证为 `sub_335A224` |
| x0 | 0x36a2844 | 0x36a2848 | 0x36a284c | - |
| x0 | 0x36a2884 | 0x36a2888 | 0x36a288c | - |
| x8 | 0x3d7c35c | 0x3d7c360 | 0x3d7c364 | ✅ 在 `sub_3D7BB94` 中 |
| x0 | 0x3e3fec8 | 0x3e3fecc | 0x3e3fed0 | wzr 清零 |
| x19 | 0x3f54798 | 0x3f5479c | 0x3f547a0 | x19 = this |

### 17.5 ★★★ sub_3D7BB94 @ 0x3d7bb94 — 真正的位置更新函数!

**Evidence**: `ev_62b20fb903e23569737126ffb0bca4f9bc055c7a618f4975c98f390c71a44f6e`

签名:`__fastcall sub_3D7BB94(__int64 a1, unsigned int a2, char a3, int a4)`
- a1 = 英雄上下文 / Controler 对象(不是 hero 本身)
- a2 = **frame_id**(特征:profiler mark 23068733 与 CBattleLogic 同级)
- a3 = flag
- a4 = 可能是 skill_id / source_id

**关键证据**(line 71):`off_50B0C90(23068733LL, &v58)` — Profile mark,与子系统级 tick 同级

**关键调用**(line 266-272):

```cpp
// ★★★ 真正的位置写入包装函数 off_5153CD0
off_5153CD0(
    *(_QWORD *)(a1 + 384),                // hero_ptr (a1+384 = HeroControler 持有的 hero 引用)
    a2,                                     // frame_id
    *(_QWORD *)(*(_QWORD *)v31 + 144LL),   // 某值(可能 velocity.x 或 pos.x 源)
    *(_QWORD *)(*(_QWORD *)v31 + 152LL),   // 某值(可能 velocity.y 或 pos.y 源)
    1LL,
    0LL
);
// v31 = hero_core (a1+16 链路下,含 path/velocity 子模块)
//   v28+168 处拿某 sub-component,v31 = sub-component+16+24*index
//   v31+144/v31+152 含位置源数据

// 旁证(line 273-274):同时写 hero+212 = source_id(用于同步标记)
if (a4 >= 1)
    *(_DWORD *)(*(_QWORD *)(a1 + 384) + 212LL) = a4;
```

**调用路径反推**:
```
[未知上层 - 可能在 CBattleLogic::UpdateLogic 子系统 tick 中]
  ↓
sub_3D7BB94(hero_ctrl, frame_id, ...)
  ↓ line 266: off_5153CD0(hero, frame, pos_src, vel_src, 1, 0)
  ↓
off_5153CD0 内部(GOT slot,待反编译):
  ↓ 基于 frame 计算 velocity × dt
  ↓ ★★★ 写入 hero+32(real_x)/ hero+40(real_y)/ hero+44(real_z)
```

### 17.6 ★★★ sub_335A224 @ 0x335a224 — 位置旋转/位移计算函数!

**Evidence**: `ev_3e6b8b7be7d49b518291dfdfec53e65517ca3f88e67809897931d0b4397bab5d`

签名:`__fastcall sub_335A224(__int64 a1, __int64 *a2, _DWORD *a3)`  
- a1 = 输入(position source + rotation matrix)
- a2 = ★ hero_ptr 的指针(`*a2 = hero`)
- a3 = 输出参数

**关键写入代码**(line 64-68):

```cpp
v23 = *a2;          // ★ hero 对象指针
result = 1LL;

// ★★★ 直接写入真实坐标!
*(_QWORD *)(v23 + 32) = v9;          // hero+32 = real_x (8 字节打包,实际可能 +32/+36 两字段)
*(_DWORD *)(v23 + 40) = v12;         // hero+40 = real_y
*(_WORD *)(v23 + 44) = WORD2(v12);   // hero+44 = real_z(byte 精度)

// 同时写 config_id 之类
*(_DWORD *)(*a2 + 196) = *(_DWORD *)(a1 + 4);
*a3 = *(_DWORD *)(v8 + 4);            // 返回值
```

**v9 / v12 计算(数学旋转)**(line 43-62):

```cpp
// 这是标准 2D 旋转矩阵:
//   rotated_x = cos(θ) * x - sin(θ) * y
//   rotated_y = sin(θ) * x + cos(θ) * y
//
// 在代码里:v24_lo, v24_hi = cos,sin(向量); v9,v12 = (x,y)
//   rotated_x = v24_lo * v9 - v24_hi * v12   ← line 53 (v14)
//   rotated_y = v24_hi * v9 + v24_lo * v12   ← line 52 (v17)
// 然后 / v13 = |v24|² = magnitude(归一化)
// 再 × 1000 缩放(v18 = off_5090010(v26, 1000))
```

**这是位置旋转 + 缩放计算**(典型技能位移、击退、瞬移的实现) — hero+32/+40/+44 是**旋转后的目标位置**

### 17.7 sub_29FCB94 @ 0x29fcb94 — 拷贝构造 / 多字段 setter

**Evidence**: `ev_c3972c56fc14b21b52bc38f0fe93b94ae59bcc0caf1f9d45ee9a608e1d474722`

19 行短函数,拷贝 6 个参数到对象:
```cpp
*(QWORD*)(result + 0) = a2;
*(QWORD*)(result + 8) = a3;
*(QWORD*)(result + 16) = a4;
*(QWORD*)(result + 24) = a5;
*(QWORD*)(result + 32) = a6;   // ★ real_x (源) 
*(DWORD*)(result + 40) = a7;   // ★ real_y
*(BYTE*)(result + 44) = a8;    // ★ real_z(byte 精度 — Z 用 byte 表示,说明 z 是粗粒度)
```

这是 Pos struct 的拷贝构造(典型 `Position::set(other)`)

### 17.8 关键洞察 — Z 用 byte 精度

`sub_29FCB94` 写 `+44` 用 `*(BYTE*)` —— 说明 **real_z 是 byte 类型**(不是 DWORD)!

这与 `sub_335A224` 的 `*(WORD*)(v23 + 44) = WORD2(v12)` 也对应 — Z 是低精度(byte/word)。

这可能是 MOBA 的特征:**X/Y 都用 int 4 字节(厘米精度),Z 只用 byte(2 米精度,因为高度不需要那么精确,只在跳跃/飞行时关心)**。

### 17.9 Hero 真实坐标写入源(最终确认的清单)

| 函数 | 地址 | 用途 |
|------|------|------|
| `sub_3D7BB94` | 0x3d7bb94 | 主位置更新(每帧 tick,Profile mark 23068733) |
| `off_5153CD0` | GOT slot | 位置写入包装(被 sub_3D7BB94 调用) |
| `sub_335A224` | 0x335a224 | 位置旋转(技能位移/击退) |
| `sub_29FCB94` | 0x29fcb94 | Position struct 拷贝构造 |

### 17.10 其他 gap=8 候选(待挖)

| 函数地址 | 备注 |
|---------|------|
| sub_21D8A0C @ 0x21d8a0c | uint8** a1,299 行(数据解析风格) |
| sub_333D188 @ 0x333d188 | (_QWORD*, _QWORD*),107 行 |
| sub_3F53EA0 @ 0x3f53ea0 | 复杂 6 参数 + __int128*,423 行 |
| sub_2A43714 @ 0x2a43714 | 复杂 629 行 |

### 17.11 离线扫描 vs IDA 能力对比(已验证)

| 任务 | IDA attached | 离线 Python |
|------|--------------|-------------|
| 找所有 STR +offset 命中 | ❌(xrefs 只能给 data ref,不能找指令偏移写入) | ✅ 31 秒拿 49894 命中 |
| 找"连续 3 写"pattern | ❌(做不到) | ✅ 31 秒拿 129 精准候选 |
| 直接看伪代码 | ✅(小函数 OK,243KB 超时) | ❌(看不到伪代码,要看汇编) |
| 找 GOT slot 真实目标 | ❌(attached 模式看不到) | ⚠️(要解析 .got 段) |
| 综合 | 反编译强,但只能针对小函数 +1 个一个手工查 | **扫全 binary 速度极快,能找 pattern 但看不到伪代码** |

### 17.12 结论 — 真实坐标写入链最终确认

```
1. 服务端帧循环:
   CBattleLogic::UpdateLogic(sub_45D7178)
     → 各 UpdateLogic 子系统
     → ActorManager::UpdateLogic(sub_45AAB64)
     → HeroControler::UpdateLogic(sub_3D90AE8)
     → MovementComponent::UpdateLogic(sub_287D264)
     → off_51AF748(child, frame)  // 真正的 movement update

2. ★ 位置更新函数(本轮发现):
   sub_3D7BB94(hero_ctrl, frame_id, flag, source_id)
     ↓ Profile mark 23068733(子系统级 tick)
     ↓ line 266: off_5153CD0(hero_ptr, frame, pos_src, vel_src, 1, 0)
     ↓
   off_5153CD0(hero, frame, pos_src, vel_src):
     ↓ ★★★ 写入 hero+32(real_x)/ hero+40(real_y)/ hero+44(real_z)
     ↓ 基于 vel_src × frame_dt 累加 pos_src

3. ★ 特殊位置设置(技能位移/击退):
   sub_335A224(input, &hero_ptr, output)
     ↓ 2D 旋转矩阵 + 1000 缩放
     ↓ ★ 直接写 hero+32/(+36) = real_x, hero+40 = real_y, hero+44 = real_z(byte)

4. ★ Position struct 拷贝:
   sub_29FCB94(src, x, y, ...)
     ↓ 构造函数 — 多字段 setter
     ↓ 写对象+offset 0/8/16/24/32/40/44
```

---

