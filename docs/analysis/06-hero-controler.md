<!-- 06-hero-controler.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: HeroControler::UpdateLogic -->

## 12. ★ HeroControler::UpdateLogic(已分析 — 英雄每帧 tick 核心)

**函数地址**: `sub_3D90AE8 @ 0x3d90ae8`  
**Evidence**: `ev_b854aacc93e4b44d5fbf7895f7e4854f11e6d8ad0069551f99ed4119edd3cb3e`

**铁证**:函数内首行 `log("HeroControler::UpdateLogic")` 完全实锤

### 签名
```cpp
__int64 __fastcall sub_3D90AE8(__int64 a1, unsigned int a2)
// a1 = HeroControler* this
// a2 = current_frame_id
```

### 主要调度流程

```cpp
// Line 23: log
log("HeroControler::UpdateLogic");

// Line 25-28: v5 = a1+1640 子对象 → vtable[22](offset 176, 第 22 个虚函数)
v5 = *(DWORD**)(a1 + 1640);     // child component(可能 MovementComponent)
if (v5 && v5[3] == *(DWORD*)(a1+1648))  // ID 校验
    (*v5->vtable[22])(v5, frame);  // 更新该组件

// Line 29: 另一个 tick 函数
off_51A00E8(this, frame);

// Line 30-47: 拿 hero_core.x320 子对象(vtable[14] 类型校验),否则用默认
//   然后 v11 = v9+40+168 (?array), 调 vtable[18] (offset 144, 标准 UpdateLogic 槽)
(*v11->vtable[18])(v11, frame);

// Line 48-64: ★ 金币被动收入逻辑
if (off_51A03F8(a1) & 1) {
    if ((a1[1376] & 0xFFFFFFFE) != 6) {
        a1[1364] += frame;
        if (a1[1364] >= 1000) {
            // ★ 每 1000 帧触发结算(典型 ~16.6 秒一次 @ 60fps)
            v14 = off_51AAFF8(GameRoot+1024, a1[1688] - 1);
            v15 = 1759218605LL * -(off_5156700(core+464, 0, 0) * v14);
            // 1759218605 = 0x68DB8BAD = 除以 1000 的 magic number(整数除法优化)
            off_51A0D88(a1, (v15 >> 44) + (v15 >> 63), 0);
            a1[1364] -= 1000;
        }
    }
}

// Line 66-69: v16 = a1->vtable[69](offset 552) → 拿某 list(Buff 或 Skill)
v16 = (*a1->vtable[69])(a1);
v17 = *v16;
(*v17->vtable[28])(v17, frame);  // update (vtable+224)

// Line 70-76: a1+40+480 子对象 (条件 a1+68<=20 走 fallback)
v19 = *v18;
(*v19->vtable[18])(v19, frame);  // 标准 UpdateLogic

// Line 77-90: a1+1616 计时器(a1+1612 递减)
if (a1[1616] >= 1) {
    v21 = a1[1612] - frame;
    a1[1612] = v21;
    if (v21 <= 0) {
        a1[1612] = 0;
        *(BYTE*)(a1+1336) = 1;  // 触发 end flag(buff/skill 结束)
    }
}

// Line 91-97: a1+40+792 子对象 (条件 a1+68<=33 走 fallback)
v23 = *v22;
(*v23->vtable[18])(v23, frame);
```

### HeroControler 对象布局(已推导)

| 偏移 | 类型 | 含义 |
|------|------|------|
| `a1+16` | PTR | hero_core_ptr_ptr(指向 HeroCore 对象) |
| `a1+40` | PTR | 子对象数组的起点(vtable/索引表) |
| `a1+68` | int | 子对象数量(用于条件:<=0x14/0x21 时走全局 fallback,>阈值时走数组) |
| `a1+1336` | BYTE | 状态 flag(buff/end 到期触发) |
| `a1+1364` | int | **金币被动收入计时器**(每 1000 帧结算一次) |
| `a1+1376` | int | 状态 enum(`!= 6/7` 时走金币逻辑) |
| `a1+1612` | int | **buff/skill 持续计时器**(递减) |
| `a1+1616` | int | 同上的条件判定值 |
| `a1+1640` | PTR | 子组件 1 指针(可能 MovementComponent,vtable[22] 更新) |
| `a1+1648` | int | 该子组件 ID(校验) |
| `a1+1688` | int | 索引号(`-1` 进入 GameRoot+1024 拿配置) |

### HeroControler 子组件 vtable 槽位

- vtable[18] (offset 144) = **标准 UpdateLogic**(引擎基类虚接口)
- vtable[22] (offset 176) = MovementComponent 等子组件 update
- vtable[28] (offset 224) = Buff/Skill list update
- vtable[69] (offset 552) = GetListComponent()(返回某 list 对象)

### 已识别的 HeroControler 子组件(部分)

- `a1+1640` 子对象(可能 MovementComponent,移动物理)
- `a1+40+480` 子对象(vtable[18] 更新,可能是 SkillComponent)
- `a1+40+792` 子对象(vtable[18] 更新,可能是 InventoryComponent 或类似)
- `a1->vtable[69]()` 返回的对象(vtable[28] 更新,可能是 BuffList/SkillList)

### ★ 重大功能发现

1. **金币被动收入** (line 51-60):
   - 每 1000 帧(~16.6 秒 @ 60fps)结算一次
   - 用 `0x68DB8BAD` magic number 整数除法(÷ 1000)—— 这是编译器优化
   - 调用链:`off_5156700(core+464)` × `off_51AAFF8(GameRoot+1024, hero_level)` → money_gain
   - 这是 MOBA 经济系统的"每秒金币"实现!

2. **Buff 计时器递减**(line 77-90):
   - 经典 buff duration 倒计时,= 0 时触发结束 flag(a1+1336 = 1)
   - 这是 buff/skill 持续时间管理核心

3. **子组件聚合**(line 30-90):
   - 通过 a1+40 的数组组织多个子组件,类似 Unity GameObject 的 Component 模型
   - 数组大小 ≤20/≤33 时走 fallback(预分配小数组优化)

### 下一步

- **`off_51A00E8(this, frame)`** (line 29) — 重要子函数(未分析,可能是 AI 决策主入口)
- **`off_5156700(core+464, 0, 0)`** (line 58) — 金币基数计算
- **`a1->vtable[69]()`** (line 66) — 拿 list(SkillList/BuffList)
- **`a1+40` 数组**及其下标的子对象类型(需拿 a1+40 指针所指对象的 vtable 类型)

---

