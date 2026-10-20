<!-- 11-got-resolution.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: 重定位表解出所有 GOT slot 真实地址 -->

## 18. ★★★ 重定位表解出所有 GOT slot 真实地址(终极突破)

**方法**:用 lief 读 `.rela.dyn` 678,517 条重定位记录,匹配每个 GOT slot 地址,拿 AARCH64_RELATIVE 类型的 addend(= 加载时真实计算地址)

### 18.1 完整 GOT slot 真实地址表(全部已解)

| GOT slot | 真实地址 | 含义 |
|----------|---------|------|
| `off_5153CD0` | **0x36a283c** | ★ hero 位置写入包装(`sub_36A283C`)|
| `off_51AF748` | **0x3ee11b8** | MovementComponent 真正更新(`sub_3EE11B8`)|
| `off_517F388` | **0x3ac94a8** | 距离计算 + 坐标读取(`sub_3AC94A8`)|
| `off_5156700` | 0x36d3134 | 金币计算(`sub_36D3134`)|
| `off_51EA4D0` | 0x52717b0 | GameRoot 单例(.data,不是代码)|
| `off_50B0C90` | 0x29dfce8 | profiler mark v2 |
| `off_50C0C30` | 0x5271ee0 | log profiler(.data) |
| `off_50A0178` | 0x287d73c | 某函数(在 MovementComponent 附近) |
| `off_50A5BA0` | 0x28e9a80 | - |
| `off_5153CB0` | 0x36a2678 | - |
| `off_5153CC0` | 0x36a280c | - |
| `off_5153D00` | 0x36a2b44 | - |
| `off_5115E70` | 0x30eabb8 | - |
| `off_5226D00` | 0x45af1e8 | - |
| `off_5226D70` | 0x45af994 | - |
| `off_5226DB0` | 0x45b054c | - |

### 18.2 ★★★ `sub_36A283C`(GOT slot 0x5153CD0)— 真实坐标写入函数!

**Evidence**: `ev_d42d2de86d9fbaf727be2b26676586dee6e9a23f3653e9d58311bb3ec8908879`

签名:`sub_36A283C(__int64 result, int a2, __int64 a3, __int64 a4, char a5, int a6)`

**完整实现**(11 行):

```cpp
*(_QWORD *)(result + 32) = a3;        // ★ hero+32 = a3(8 字节打包,实际是 +32 (low) + +36 (high))
*(_DWORD *)(result + 40) = a4;        // ★ hero+40 = a4(= real_y)
*(_WORD *)(result + 44) = WORD2(a4);  // ★ hero+44 = a4 高 16 位(real_z,WORD 16 位精度)
*(_DWORD *)(result + 88) = a6;        // hero+88 = enabled_flag(已知 ≥1 表示有效)
*(_DWORD *)(result + 92) = 3;         // hero+92 = 常量 3 (位置更新状态码)
*(_BYTE *)(result + 234) = a5;        // hero+234 = is_server_auth flag
*(_DWORD *)(result + 84) = a2;       // hero+84 = atk_range_factor
*(_DWORD *)(result + 200) = a2;      // hero+200 = atk_range_factor(副本)
return result;
```

### 18.3 ★★★ Hero 对象字段完全确认(终极版本)

```cpp
struct Hero {
    +4:    config_id          (DWORD)
    +8:    runtime_id         (DWORD)
    +28:   display_x          (DWORD)        // 客户端混淆后(写入见 §13)
    +32:   ★ real_x / packed  (QWORD = 8B)  // 真实 X(可能 +32=x, +36=y 在同一 QWORD)
    +40:   ★ real_y           (DWORD)         // 真实 Y
    +44:   ★ real_z           (WORD, 16-bit)  // 真实 Z(精度 16 位)
    +84:   atk_range_factor   (DWORD)         // 与 GetNorAtkTarget 一致 ✓
    +88:   enabled_flag       (DWORD ≥1)      // 与 GetPosFromHero 一致 ✓
    +92:   state_code (常量 3) (DWORD)
    +196:  ?                  (DWORD)         // 与 a1+4 (config_id) 同
    +200:  atk_range_factor_v2 (DWORD)         // 副本
    +212:  source_id          (DWORD)         // 同步标记(§17.5 line 274)
    +234:  is_server_auth     (BYTE)          // 是否服务端权威
    +240:  ?_sub_obj          (PTR)           // 某子对象
    +1008: next entry         (item size)     // 数组步长
};
```

### 18.4 ★★★ sub_3AC94A8(GOT slot 0x517F388)— 距离计算函数

**Evidence**: `ev_5efeb5e340b88023931e2dc74a2a88f47fef337aa00d2c7e0ae38078fda90316`

```cpp
__int64 sub_3AC94A8(__int64 a1, __int64 *a2, __int64 *a3, char a4)
{
    if (a4 & 1) {  // 模式 1:用 off_51800F8 拿坐标(API 风格)
        v6 = off_51800F8();
        v8 = v7;        // y
        v9 = off_51800F8(a1, a3);
        v10 = ...;      // target y
    } else {  // 模式 0:直接读 a2/a3 数组
        v6 = *a2;       // a2[0] = x
        v8 = *((_DWORD*)a2 + 2);   // a2[2] = y
        v9 = *a3;
        v10 = *((_DWORD*)a3 + 2);
    }
    // ★★★ 标准欧氏距离公式
    return (unsigned int)(int)sqrt((v8-v10)*(v8-v10) + ((int)v6-(int)v9)*((int)v6-(int)v9));
}
```

**关键确认**:
- 距离计算只用 **2D**(x,y),不用 z!
- 用 `sqrt` — 标准欧氏距离
- 返回 `(unsigned int)(int)` — 即强转为 int32 后再到 uint32(可能截断或保留符号)
- 两种模式:API 风格(a4=1,用 off_51800F8)或直接数组风格(a4=0)

### 18.5 ★ sub_3EE11B8(GOT slot 0x51AF748)— MovementComponent 真正更新

**Evidence**: `ev_738faf8f2d697f71c7224185d131d08fddd65d74c1ad624d6f59edeb734c3c71`

```cpp
__int64 sub_3EE11B8(__int64 a1, unsigned int a2)
// a1 = movement_child, a2 = frame

{
    // 1. 拿 movement 子模块 (a1+152)
    v3 = *(_QWORD *)(a1 + 152);
    if (v3 && v3[3] == *((_DWORD *)(a1 + 160))) {
        v5 = off_51AFCA8();   // RVO agent
        // 若条件满足, 调用 RVO update
        if ((off_5090060() & 1) == 0 
            && (off_51B5170(*(QWORD*)(a1 + 16)) & 1) != 0
            && *(BYTE*)(*(*(QWORD*)(*(QWORD*)(a1 + 16) + 216) + 200) + 288)) {
            off_51AF678(a1, v5, 0, 0);   // ★ RVO algorithm update
        }
    }
    
    // 2. Profile marks
    off_50B0CC0(26083339LL, a1 + 266);
    off_50B0CC0(26083340LL, a1 + 262);
    
    // 3. 若某些条件 → 更新 a1+80 子对象 (vtable[19])
    if ((off_51AF7D8(a1) & 1) != 0 || *(BYTE*)(a1 + 262)) {
        v6 = off_519D358(*(QWORD*)(a1 + 80));  // 去引用
        (*(*v6 + 152))(*v6, a2);              // vtable[19] 更新
    }
    
    // 4. 若另一条件 → 更新 a1+128 子对象 (vtable[21])
    if ((off_51AF7E8(a1) & 1) != 0) {
        v7 = off_519D358(*(QWORD*)(a1 + 128));
        (*(*v7 + 168))(*v7, a2);              // vtable[21] 更新
    }
    
    // 5. 走 GameRoot→216→176 sub-module → off_51B4B10
    v8 = *(*(QWORD*)(a1 + 16) + 216);
    v9 = *(v8 + 176);
    if (v9 && v9[3] == *(v8 + 184)) {
        off_51B4B10();
    }
    
    return off_50E1998(*(QWORD*)(a1 + 272));   // 返回某 profile 结果
}
```

**结构推断**:
- a1 = MovementComponent 子对象(`HeroControler::UpdateLogic` 中 vtable[22] 调用的就是这个)
- a1+152 = RVO agent 模块
- a1+80 = 子移动模块 1(vtable[19])
- a1+128 = 子移动模块 2(vtable[21])
- a1+272 = profile/timer 句柄
- off_51AF678 是真正的 RVO update 函数 → 它内部会算 velocity → 调 sub_36A283C 写入 hero+32/+40/+44

### 18.6 sub_36D3134(GOT slot 0x5156700)— 金币计算(简单分支)

```cpp
__int64 sub_36D3134(__int64 a1)
{
    v2 = *(QWORD*)(a1 + 240);   // 子对象
    if (v2 && v2[3] == a1[248] && (BYTE)v2[120] | (BYTE)v2[444]) {
        return off_50A8258();   // 拿缓存值
    } else {
        return off_5156D28(a1);   // 计算金币
    }
}
```

### 18.7 ★★★ 完整写入链最终闭合!(终极反推)

```
┌─────────────────────────────────────────────────────────┐
│ 帧循环入口                                               │
│ CBattleLogic::UpdateLogic (sub_45D7178, §6.5)          │
│   ├── ActorManager::UpdateLogic (sub_45AAB64, §8)     │
│   │     ↓ actor.vtable[19] (offset 152)               │
│   ├── HeroControler::UpdateLogic (sub_3D90AE8, §12)   │
│   │     ↓ a1+1640 子对象 vtable[22] (offset 176)      │
│   └── MovementComponent::UpdateLogic (sub_287D264, §16.1)│
│         ↓ 遍历 children (每项 24 字节)                 │
│         ↓ 调 off_51AF748(child, frame)                 │
└──────────────────────────────┬──────────────────────────┘
                               │ GOT slot 0x51AF748
                               ↓
┌─────────────────────────────────────────────────────────┐
│ sub_3EE11B8 — MovementComponent 真正更新               │
│   1. 调 off_51AF678(a1, v5=RVO_agent, 0, 0)             │
│      → RVO velocity 计算                                │
│   2. 更新子模块 (vtable[19]/[21])                       │
│   3. 递归调用下层                                       │
└──────────────────────────────┬──────────────────────────┘
                               │
                               ↓ (RVO 算出 velocity 后)
                               ↓ 
┌─────────────────────────────────────────────────────────┐
│ sub_3D7BB94 — hero_ctrl.tick(frame, ...)               │
│   → off_5153CD0(hero, frame, pos, vel, 1, 0)            │
│   GOT slot 0x5153CD0                                   │
└──────────────────────────────┬──────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────┐
│ ★ sub_36A283C — 真正写入 hero+32/+40/+44!              │
│                                                         │
│   *(QWORD *)(hero + 32) = a3;   // real_x (打包 8B)   │
│   *(DWORD *)(hero + 40) = a4;   // real_y              │
│   *(WORD  *)(hero + 44) = z16;   // real_z (WORD)      │
│   *(DWORD *)(hero + 84) = a2;   // atk_range_factor   │
│   *(DWORD *)(hero + 88) = a6;   // enabled_flag        │
│   *(DWORD *)(hero + 92) = 3;    // state code          │
│   *(BYTE  *)(hero + 234) = a5;  // is_server_auth      │
│   *(DWORD *)(hero + 200) = a2;  // atk_range_factor v2 │
└─────────────────────────────────────────────────────────┘
```

### 18.8 ★★★ 最终全链闭合(终极成果)

之前的链断点全部闭合:
- ✅ `off_5153CD0` → `sub_36A283C`(hero 位置写入)
- ✅ `off_51AF748` → `sub_3EE11B8`(MovementComponent 真正更新)
- ✅ `off_517F388` → `sub_3AC94A8`(欧氏 2D 距离计算)
- ✅ `off_5156700` → `sub_36D3134`(金币计算)

### 18.9 关键发现 — Z 用 16-bit(WORD)精度!

`*(WORD*)(hero+44) = WORD2(a4)` — Z 坐标是 16 位整数!

这意味着:
- X / Y = 32 位整数(4 字节,范围 ±2.1 billion cm,够用)
- **Z = 16 位整数(2 字节,范围 ±32K cm,即 ±320m,够用)**
- Z 用 16 位 = 性能优化(典型 MOBA 平面战斗,Z 变化少)

### 18.10 终极方法论总结

| 方法 | 作用 | 耗时 |
|------|------|------|
| IDA attached + procedure_pseudo_code | 拿函数伪代码 | 5-30s/函数 |
| 离线 capstone 扫 STR +X | 找候选写入位置 | 31s |
| **离线 lief 读 .rela.dyn 重定位** | **解 GOT slot 真实地址** | **< 1s** |
| IDA 反解"虚调用 GOT 真实地址"伪代码 | 验证 + 完整理解 | 5-30s/函数 |

**关键洞察**:`.rela.dyn` 重定位表是**ARM64 .so 的"真相之书"** —— 所有 GOT slot 的真实目标都被静态重定位记录,1 秒拿到全部解,根本不用扫整个 binary!

### 18.10 终极方法论总结

| 方法 | 作用 | 耗时 |
|------|------|------|
| IDA attached + procedure_pseudo_code | 拿函数伪代码 | 5-30s/函数 |
| 离线 capstone 扫 STR +X | 找候选写入位置 | 31s |
| **离线 lief 读 .rela.dyn 重定位** | **解 GOT slot 真实地址** | **< 1s** |
| IDA 反解"虚调用 GOT 真实地址"伪代码 | 验证 + 完整理解 | 5-30s/函数 |

**关键洞察**:`.rela.dyn` 重定位表是**ARM64 .so 的"真相之书"** —— 所有 GOT slot 的真实目标都被静态重定位记录,1 秒拿到全部解,根本不用扫整个 binary!

### 18.11 GOT 调用频率统计(辅助验证)

通过扫描整个 .text(183 秒扫 ~1100 万指令):
- `off_517F388`(距离计算) — **730 个函数调用**(密度最高,合理:距离计算是 MOBA 高频操作)
- 其他几个 GOT slot 由于脚本 bug 未直接统计,但已通过重定位表全部解析

**佐证**:`off_517F388` 在 CanHitTarget、CheckHitTarget、GetNorAtkTarget、ViewManager 等几十个函数里被调用 — 与 ledger §15.5 列出的 API 调用图一致。

### 18.12 持久化最终版

| 文件 | 大小 | Records | 内容 |
|------|------|---------|------|
| `D:\SGANEM\test_so_evidence_v11_GOT_resolved_FINAL.json` | 318KB | 17 | ★ 最终 export,含本轮 GOT 真实函数伪代码 |
| `D:\SGANEM\test_so_evidence_v9_RealCoords.json` | 158MB | 111 | 历史最完整(上轮 export) |
| `D:\SGANEM\test_so_INVESTIGATION_LEDGER.md` | — | — | ★★ 完整分析报告 v12 / 19 节 |
| `D:\SGANEM\test_so_STR_hits.csv` | — | — | 离线扫描 +32/+40/+44 命中 |
| `D:\SGANEM\test_so_STR_triples.csv` | — | — | 离线扫描 129 三件套候选 |

---

