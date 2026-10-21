# 17 - ViewManager 视野混淆与真实坐标源调查（进行中）

> 状态：**调查中** — 已确认迷雾混淆机制，真实坐标源尚未完全定位
> 日期：2026-10-21
> 分支：`analysis/verify-gameroot-hero-chain`

---

## 1. 真机实测现象汇总

| 场景 | 己方英雄坐标 | 敌方英雄坐标 | 说明 |
|------|-------------|-------------|------|
| 开局（泉水阶段） | ✅ 正确 | ✅ 正确 | 所有人都在出生点，数据一致 |
| 对局中（2分钟后） | ✅ 持续正确 | ❌ 严重偏差 | 敌方显示在错误位置（如泉水/河道） |
| 敌方进入视野 | — | ✅ 恢复正确 | 可见时数据恢复真实 |
| 游戏结束（水晶爆炸） | ✅ 正确 | ✅ 全部正确 | 迷雾系统关闭，全图数据同步 |

**关键用户反馈**：
> "游戏结束时，最后的坐标又会变成真实位置，app里看着也对了"

---

## 2. ViewManager 视野混淆机制（反汇编确认）

### 2.1 核心混淆函数

**函数**: `view_manager::ViewManager::ModifyEnemyInvisibleHeroPosition`
**地址**: `sub_24AD7FC` @ `0x24AD7FC`
**GOT 槽**: `0x508AC10`（`R_AARCH64_RELATIVE → 0x24ad7fc`）

### 2.2 关键日志字符串（格式化证据）

```
0x117F1D6: "view_manager::ViewManager::ModifyEnemyInvisibleHeroPosition"
0x114B500: "hero:%d loc:(%d, %d) invisible2visible change to 55000"
0x11AC06D: "hero config_id: %d, is_in_grass: %d, main_hero config_id: %d, is_in_grass: %d, dist: %d"
```

### 2.3 混淆触发条件（从汇编还原）

```asm
; 0x24AD874: 阵营比对
0x24ad874: ldr  w8, [x21, #0x18]     ; enemy->camp (or similar)
0x24ad878: ldr  w9, [x22, #0x18]     ; main_hero->camp
0x24ad87c: cmp  w8, w9
0x24ad880: b.eq #0x24ad864           ; 同阵营 → 跳过（不混淆己方）

; 0x24AD9CC: 隐身英雄名单匹配
0x24ad9cc: mov  w3, #0xDE8FA         ; 911610 (隐身名单ID #1)
0x24ad9e4: blr  x8                   ; 调用 0x3AD8704 检查是否在名单中
0x24ad9ec: mov  w9, #0xDE8FB         ; 911611 (隐身名单ID #2)
0x24ada0c: tbz  w0, #0, #0x24ada24   ; 不在名单 → 走 grass 判定

; 0x24ADA24: is_in_grass 判定
0x24ada24: ldrb w8, [x21, #0x358]    ; hero->is_in_grass (+856)
0x24ada28: cmp  w8, #0
0x24ada2c: cset w8, eq
0x24ada30: and  w8, w29, w8          ; w29 = 之前的距离判定结果
```

### 2.4 隐身名单匹配函数

**函数**: `0x3AD8704`
```c
// 遍历 [x2 + 0x130] 处的 vector<int>
// 检查 target_id 是否在"需要视野混淆的英雄名单"中
for (i = 0; i < vec.size; i++) {
    if (vec.data[i] == target_id) return 1;  // 在名单中
}
return 0;
```

### 2.5 混淆操作

**效果**: `invisible2visible change to 55000` — 把不可见敌人的显示位置改为 55000（或出生点附近）。

**注意**: ViewManager 修改的是**显示/渲染层**坐标，但真机实测表明，我们通过 Transform 链读取的**也是被混淆后的值**（因为服务端就不下发真实数据）。

---

## 3. 已排除的错误路径

### 3.1 hero+32/+40/+44 ≠ real_x/y/z

**原 §19.5b 文档结论（有误）**:
```
Hero + 32: real_x (int32, cm)
Hero + 40: real_y (int32, cm)
Hero + 44: real_z (int16, cm)
来源: sub_36A283C 写入
```

**反汇编修正**:

`sub_36A283C` (GOT `0x5153CD0`) 的 x2 参数来源：
```asm
; 调用者 0x3D7C198:
0x3d7c104: add  x0, x24, #0x90     ; x0 = actor + 0x90 (组件内联)
0x3d7c10c: mov  w1, #0x3e8         ; w1 = 1000 (缩放因子)
0x3d7c110: blr  x8                  ; 调用 0x25A6930
; x0 返回值作为 x2 传给 sub_36A283C
```

**`0x25A6930` 是方向归一化函数**:
```asm
0x25a693c: ldpsw x8, x10, [x0]     ; 读入 VInt3 (x, y)
0x25a6940: ldrsw x9, [x0, #8]      ; 读入 z
0x25a6944: lsl  x22, x8, #7        ; x * 128
0x25a6950: mul  x8, x22, x22       ; x²
0x25a6954: madd x8, x20, x20, x8   ; x² + y²
0x25a6958: madd x8, x21, x21, x8   ; x² + y² + z²
0x25a6968: blr  x9                  ; sqrt() → 求模长
; 之后: 每个分量 / 模长 * w1(1000) → 单位方向向量 × 1000
```

**结论**: `hero+32/+36` 存储的是**方向/朝向向量**（normalized × 1000），不是位置坐标！

### 3.2 Actor + 0x20/+0x28 不是坐标

真机 Dump 显示敌方英雄 `actor+0x20 = 0`，`actor+0x28 = config_id`。
这两个字段不是位置，直接读取会产生 `(0, config_id)` 的垃圾数据。

### 3.3 Transform 链 (+0xA8) 是渲染层坐标

`Actor + 0xA8 → Node → +0x10 → Link → Transform → +0x60 → VInt3` 是渲染 Transform。
- 己方英雄：渲染坐标 = 逻辑坐标 ✅
- 迷雾中敌方：渲染坐标 = 服务端混淆后的假坐标 ❌

---

## 4. 当前可用数据链路

### 4.1 当前实现（hero_reader.c `read_rootactor_chain`）

```
libGameCore base (Build-ID: 822d2ce92aadfd8a)
  └─ + 0x51EA4D0 → RootSlot*
       └─ + 0x000 → GameRoot*
            └─ + 0x388 → CActorManager*
                 ├─ + 0x2EB0 → flag (计数选择)
                 ├─ + 0x2E8C/0x2EAC → count (flag==0/1)
                 ├─ + 0x2E90 → IndexBuffer* (flag!=0 时使用)
                 └─ + 0x2E70 → HeroEntry pool (步长 0x20)
                      └─ entry + 0x08 → Hero* (1008 bytes)
                           ├─ + 0x28 → config_id (100~700)
                           ├─ + 0x34 → camp (1/2)
                           ├─ + 0x88 → enabled_flag
                           ├─ + 0x5C → state_code
                           ├─ + 0x2C8 → is_in_grass
                           └─ + 0xA8 → Node → Transform → VInt3 (渲染坐标)
```

### 4.2 数据可靠性

| 数据 | 己方 | 可见敌方 | 迷雾敌方 |
|------|------|---------|---------|
| config_id | ✅ | ✅ | ✅ |
| camp | ✅ | ✅ | ✅ |
| alive/dead | ✅ | ✅ | ✅ |
| Transform 坐标 | ✅ 真实 | ✅ 真实 | ❌ 被混淆 |
| is_in_grass | ✅ | ✅ | ✅ |

---

## 5. 未完成方向：定位真实逻辑坐标源

### 5.1 理论依据

王者荣耀是帧同步游戏，以下系统**必须**使用全场真实坐标（否则无法工作）：
- **技能弹道命中**: `CanHitTarget` (0x2801AE4) / `CheckHitTarget` (0x2801828) — 后羿大招、女娲狙击等
- **物理碰撞解算器**: 碰撞体积、地形判定
- **AI 寻路系统**: 敌方 AI 需要知道所有实体位置
- **弹道投射物追踪**: 飞行中的技能必须持续追踪目标

这些系统读取的坐标**不经过 ViewManager 混淆**，是真正的逻辑位置。

### 5.2 下一步排查方向

#### 方向 A: 从 CanHitTarget 反推坐标源
```
CanHitTarget (0x2801AE4)
  └─ 调用 off_517F388 (距离计算)
       └─ sub_3AC94A8 → 读 hero+32/+40 (方向，非位置!)
```
需要找到 CanHitTarget 中**距离计算之前的坐标获取路径**。

#### 方向 B: 从弹道/投射物系统找
搜索创建投射物的函数，追踪其目标坐标参数来源。

#### 方向 C: 从碰撞解算器找
之前分析提到"碰撞解算器的 Shape 记录"，曾被认为是脏数据源。
但 Shape 记录实际上存储的是**物理引擎的真实位置**，需要重新评估。

#### 方向 D: 从 C# 层的 ActorLinker 找
`ActorLinker.position @ 0x4C4 (float x, y, z)` — C# 层的坐标。
但 C# 层也可能被同步混淆。

#### 方向 E: 寻找 ViewManager 的"输入源"
ViewManager 混淆**之前**，一定有某个地方存有真实坐标（否则它无法计算距离和决定是否混淆）。
找到 ViewManager 的输入 = 找到真实坐标。

### 5.3 已识别但未验证的线索

| 线索 | 地址/偏移 | 说明 |
|------|----------|------|
| 碰撞 Shape 记录 | 未定位 | 之前误判为脏数据，实际可能就是真实位置 |
| AI 位置缓存 | 未定位 | AI 系统的全场实体位置表 |
| 投射物目标追踪 | 未定位 | 飞行技能的目标真实坐标 |
| Scene 物理世界 | 未定位 | 物理引擎的全局坐标表 |
| `[actor+0x10]` 管理器 | 已定位指针 | → +0xA8 (node) → +0x30 → 列表 → +0x90 组件 |

---

## 6. 当前 App / 内核模块状态

### 6.1 内核模块 (hero_reader.kpm)
- ✅ GameRoot → CActorManager → HeroEntry 指针链稳定可用
- ✅ 己方英雄坐标精确追踪（Transform 链）
- ✅ 可见敌方坐标正确
- ❌ 迷雾敌方坐标被服务端混淆（无法从客户端获取真实值）
- ✅ heroes.bin 定长二进制输出正常（100ms 周期）

### 6.2 App (hero.apk)
- ✅ 服务状态看板（KPM / WS / 游戏状态）
- ✅ 一键启动/停止
- ✅ 本机英雄锁定（🎯 按钮）
- ✅ 雷达 + 测距 + 方向箭头
- ✅ 标准 45°/225° 视角锁定

### 6.3 桥接 (hero_bridge)
- ✅ WebSocket ws://127.0.0.1:8787/ws
- ✅ mmap 零拷贝读取 heroes.bin
- ✅ seqlock 帧同步

---

## 7. Git 提交历史（本分支）

```
3d3a973 fix(coords): restore pure transform world coordinate pipeline
3f99a00 fix(coords): add ViewManager anti-spoofing coordinate selection
c0bb0d8 fix(coords): lock standard 45/225 deg orientation + alive check
e1f95e0 fix: all 4 root cause fixes in hr_actor_chain.c
4b7d80b docs(analysis): add module architecture + 4 root cause fix summary
ba05d74 refactor: modularize hero_reader.c
22b8c97 feat(all): add bridge service, overlay app, and launch scripts
221cad0 docs(analysis): add device discrepancy verification report
67be5ac docs: add GameRoot pointer chain verification report and updated implementation
```
