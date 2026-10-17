# 指针链完整记录（Hero Reader）

> 适用版本：王者荣耀 `com.tencent.tmgp.sgame`，libGameCore / libil2cpp（2026-10 版本）
> 所有偏移都是**运行时实测**；进程重启后地址会变，但**偏移不变**。

---

## 0. 三个必须记住的约定

### 0.1 单位

| 来源 | 单位 | 例子 |
|---|---|---|
| libGameCore `link+0x2C` | **×1000**（毫米） | `37453` = 37.453 m |
| C# `ActorLinker.position`（float） | 米（float） | 写 bin 时 ×100 |
| `MinimapComponentNew.m_actorPos`（float） | 米（float） | 写 bin 时 ×100 |
| `heroes.bin` / App / 悬浮窗 | **×100**（厘米） | 距离 `/100` = 米 |

### 0.2 C# 指针标签

il2cpp 托管对象指针高 16 位带标签 `0xb4`。

```
raw   = 0xb4000075_5a7b87c0
untag = 0x0000_755a7b87c0      (mask 0x0000FFFFFFFFFFFF)
```

模块里统一用 `untag()`；比较时按 48 位。

### 0.3 合法性校验（防误读）

- 原生坐标：`y == 0`、`|x|,|z| < 300000`、`x != 0 && z != 0`
- 原生 actor：`hero ∈ (0, 4000]`、`camp ∈ {1, 2}`
- 原生指针：`0x10000 < p < 0x800000000000`
- 类名：`name_printable()`（可打印 ASCII）

---

## 1. 原生链（libGameCore）—— 坐标 / HP 的真值来源

### 1.1 链路

```
ELF image base  (VMA 扫描 + ELF magic)
  └─ base + 0x53F1810            // = .bss(0x526F000) + 0x182810
       → p
         └─ p + 0x250
              → roster
                └─ roster[i*0x18]  (i = 0..15)
                     → actor
                       ├─ actor + 0x28   hero cfg id (u32)
                       ├─ actor + 0x34   camp (1/2)
                       ├─ actor + 0xA8 → node
                       │     node + 0x10 → link
                       │       link[0] = transform
                       │       *(transform + 0x60) → (x, 0, z) int32 ×1000   ★ 世界坐标（雾中更新）
                       │       （link + 0x2C 是另一份局部值；训练营里与上面同址，匹配里不是世界坐标）
                       ├─ actor - 0x758 → xyz 指针（备用路径，slot5 等异常时）
                       └─ actor + 0x1D0 → attr component
                             ├─ +0xB4 = 8192
                             ├─ +0xB8 = hp × 8192
                             ├─ +0xC0 = hp
                             └─ +0xC8 = hpmax
```

### 1.2 关键偏移表

| 常量 | 值 | 含义 |
|---|---|---|
| `GC_BSS_VA_OFF` | `0x526F000` | `.bss` 相对 image base 的 VA |
| `GC_ROOT_VA` | `0x53F1810` | root 槽（= .bss + 0x182810） |
| `GC_ROSTER_PTR_OFF` | `0x250` | `p → roster` |
| `GC_ROSTER_STRIDE` | `0x18` | roster 元素步长 |
| `NA_ID` | `0x28` | hero cfg id |
| `NA_CAMP` | `0x34` | camp |
| `NA_NODE` | `0xA8` | actor → node |
| `NODE_LINK` | `0x10` | node → link |
| `LINK_XYZ` | `0x2C` | link → (x,0,z) int32 ×1000 |
| `NA_XYZPTR_DELTA` | `0x758` | 备用：`actor - 0x758` → xyz |
| attr 组件 | `actor + 0x1D0` | 属性组件 |
| hp / hpmax | `+0xC0` / `+0xC8` | 4 字节 int |

### 1.3 为什么信这条链

1. `fullchain` 对 10 条记录逐级打印并校验，9~10 条 OK（slot5 异常由备用路径兜底）。
2. 与 C# `ActorLinker.position` 逐位比对，**可见时完全一致**。
3. **雾中测试**：C# 坐标冻结（不再更新），原生 `link+0x2C` 继续变化 → 证明原生是真值、C# 是"可见时同步"的镜像。
4. `link[0] = transform`，`transform + 0x60` 同地址（双路径校验）。

---

## 2. C# 链（il2cpp）—— 属性 / 技能 / 装备

### 2.1 从 metadata 到类表

```
global-metadata.dat（映射在游戏内存，md_locate 定位）
  ├─ +0x18 stringOffset / +0x1C stringSize
  └─ 用于类名、字段名解析

类型表 s_TypeInfoTable
  ├─ 零扫描快路径: rptr(base + 0xE345028)
  └─ 失败则 .bss 有界扫描 + 类名强对齐校验
```

每个 `Il2CppClass`：

| 偏移 | 字段 |
|---|---|
| `+0x10` | name（char*） |
| `+0x18` | namespace |
| `+0x80` | fields（FieldInfo 数组，元素 0x20） |
| `+0x124` | field count（u16） |
| `+0xB8` | static_fields |
| `0x00` | （FieldInfo）+0x00 name，+0x08 type，+0x18 offset |

### 2.2 主链

```
类表 table[39479]           // 当前版本的 holder 类（稳定）
  └─ +0xB8 → static_fields
       ├─ +0x80 → ActorManager 实例
       │     └─ +0x18 → HeroActors 容器 (TVL)
       │           ├─ +0x08 → items 数组
       │           └─ +0x10 → count
       │                 └─ items[i] → ActorLinker
       └─ +0xE0 → GamePlayerCenter
             └─ +0x40 → hostPlayerID（自己）
```

> `table[39479]` 与 `+0x80` 是版本相关常量。
> 换版本时：`findobj ActorManager` 找到实例 → 遍历类表静态字段找持有者（模块内已有自动回退）。

### 2.3 ActorLinker 字段表（当前版本）

| 偏移 | 字段 | 说明 |
|---|---|---|
| `0x28` | SkillControl | → SkillLinkerComponent |
| `0x30` | EquipComponent | → EquipLinkerComponent |
| `0x38` | resHeroCfgInfo | 低 32 位 = 英雄 id |
| `0x3B8` | ValueComponent | HP/经验/金币/护盾/等级 |
| `0x3C0` | ActorControl | → ObjLinkerWrapper |
| `0x3F0` | miniMap | → MinimapComponentNew（雾中更新） |
| `0x410` | BuffLinkerComponent | buff 列表 |
| `0x480` | groundY | 地面高度 |
| `0x4AC` | objid | 对象 id |
| `0x4B0` | name | 名字 |
| `0x4B8` | forward | float xyz |
| `0x4C4` | position | float Vector3（米） |
| `0x505` | `_logicVisible` | 逻辑可见 |
| `0x506` | `_meshVisible` | 网格可见 |
| `0x507` | `_inCamera` | 受渲染/雾门控（不可用于可见判定） |
| `0x580` | staticData | → BaseAttr（配置值） |
| `0x764` | moveSpeed | 移速 |

### 2.4 ValueComponent（`AL_VALUECOMP 0x3B8`）

| 偏移 | 字段 |
|---|---|
| `0x28` / `0x2C` | exp / expmax |
| `0x30` / `0x34` | gold / incgold |
| `0x38` / `0x3C` | hp / hpmax（C# 镜像，用原生优先） |
| `0x40` / `0x44` | shieldmax / shield |
| `0x48` / `0x4C` | chargemax / charge |
| `0x58` | level |

### 2.5 技能（`AL_SKILLCOMP 0x28`）

```
SkillLinkerComponent
  +0x28 → skillSlotLinkerArray（Il2CppArray）
        +0x20 (ARR_ELEMS) → 元素区
           slot = rptr(elems + i*8)     i = 0..5
             +0x5C  curCD
             +0x60  curCDMax
             +0x38  level
             +0x44  bean
             +0x68  power
             +0x70  powermax
             +0x78  hit
             +0x80  target
             +0x74  ready (byte)
             +0x95  canLevelUp (byte)
```

### 2.6 装备（`AL_EQUIP 0x30`）

```
EquipLinkerComponent
  ├─ +0x40 → common container
  ├─ +0x48 → horizon container
  ├─ +0x50 → lvlX container
  └─ +0x2C buyEquipCount
        container:
          +0x08 → grid 数组
          +0x10 → maxGridCount
        BuffLinkerComponent +0x28 → spawnedBuffList
```

### 2.7 小地图坐标（第二坐标源）

```
AL_MINIMAP (0x3F0) → MinimapComponentNew
  +0x58  m_actorPos  (float Vector3)
```

- 雾里也更新 → 也当"真值"用。
- 原生链无值时，bin 的 `mx/mz` 可回退到这里。

### 2.8 BaseAttr（配置值，不是实时值）

```
AL_STATICDATA (0x580) + 0x08 → BaseAttr
```

含 hp / ad / ap / def / res / moveSpeed，都是**英雄配置**，不能当战斗实时属性用。

### 2.9 合并规则

| 字段 | 优先来源 |
|---|---|
| hero / camp / 坐标 / hp / hpmax | **原生** |
| 等级 / 金币 / 经验 / 护盾 / 技能 / 装备 / 可见性 | C# |
| 坐标兜底 | 原生 → 小地图 → C# |

按 `(hero, camp)` 合并；`620/621` 类非英雄单位保留，不按 id 过滤。

---

## 3. 相机链（已放弃，留档）

```
Moba_Camera 类
  +0xB8 → static_fields
    +0x0 → UnityEngine.Camera 对象        ← 纯指针可拿（已验证）
```

`UnityEngine.Camera` 在本 build **只有 7 个 static 字段**，实例数据在原生层；
`UnityEngine.Object.m_CachedPtr @0x8` 能拿到原生 Camera，但没找到可靠的 world position 字段。

`CameraSystem`（相机系统）字段：

| 偏移 | 字段 |
|---|---|
| `0x18` | MobaCamera |
| `0x20` | bFreeCamera |
| `0x28` | CachedFrustum（视锥平面数组）★ |
| `0x48` | m_mainCamera |
| `0x50` | m_mainCameraTrans |
| `0x58` | m_mainCamVPCache |

- `findstatic` 实测：**没有任何静态字段引用 CameraSystem 实例**。
- 要拿实例只能堆扫描（已明确不做）→ 相机线暂停。
- 若以后重启：`CachedFrustum` 是最有价值的字段，可直接做精确视锥判定。

---

## 4. 写链（已完整追踪，未使用）

```
0x3F49CA0   分发
0x3F7F668   浮点变换 / 缩放（全局 scale = *(0x4FF4000 + 0x610)）
0x3F7F08C
0x3F7CCA0   比较 + 写（脏检查）
0x3F7D040 → 0x3F7D074   setter: str x10,[x8]; str w9,[x8,#8]
另一支 0x3F7C7CC → 0x3F7C3B0
```

分发表 `0x51B7000` 槽位：`+0x460 / +0x4B0 / +0x4C0 / +0x4E0 / +0x540 / +0x5D0`（RELA addend 已解）。
用途：确认"坐标是谁写的、什么时候写"，帮助判断脏检查/冻结行为；不参与最终读取。

---

## 5. 版本兼容性检查清单

换游戏版本后，按顺序验证：

1. `fullchain` → 原生链是否还通（地址常量是否失效）
2. `classinfo ActorLinker` → 字段数是否还是 134
3. `native` 是否有 10 条且坐标合理
4. `nscorr` → 原生字段与 C# 是否仍一致
5. 若 `table[39479]` 失效：`findobj ActorManager` 重新定位持有者
6. 更新本文档的偏移表与 README 的常量
