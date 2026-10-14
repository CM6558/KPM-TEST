# Actor 坐标布局: IDA 反编译最终确认 (2026-10-14)

## 核心突破: 坐标不在 Actor(1008) 里, 而在 UnitLabel(184) 里

之前真机扫描垃圾值的根因: **坐标不在 Actor(1008字节) 数组中, 而在 UnitLabel(184字节) 数组中。**

IDA 反编译 `sub_24B2590` (UnitLabelFinder::GetPosFromMonster) 和 `0x3ac8a68` (TargetFinder)
确认了两个独立的数据结构。

## 数据结构 1: Actor 数组 (步长 0x3F0 = 1008 字节)

来源: `0x3ac8934` / `0x3ac8ea0`: `mov w11, #0x3f0; madd x10, x10, x11, x27`

| 偏移 | 类型 | 字段 | 证据 |
|------|------|------|------|
| +0x18 | u32 | entity_id | `0x3ac893c: ldr w10, [x10, #0x18]` |

Actor 数组不包含坐标。它通过 entity_id (+0x18) 关联到 UnitLabel 数组。

## 数据结构 2: UnitLabel 数组 (步长 0xB8 = 184 字节)

来源: `0x24b2790: add x23, x23, #0xb8`

确认自 `sub_24B2590` 中的日志格式串:
`"frame=%d type=%d hp=%d camp:%d m_camp:%d config:%d runtime:%d max_hp:%d x:%d z:%d x+z:%d"`

| 偏移 | 类型 | 字段 | 格式串对应 | 汇编证据 |
|------|------|------|-----------|---------|
| +0x00 | u32 | type_id | type=%d | `0x24b27c4: ldr w29, [x23]` |
| +0x04 | u32 | runtime | runtime=%d | `0x24b27e8: ldr w10, [x23, #4]` |
| +0x0C | u32 | camp_id | camp:%d | `0x24b27dc: ldr w4, [x23, #0xc]` |
| +0x14 | u32 | **x_pos** | **x:%d** | `0x24b27d0: ldr w8, [x23, #0x14]` |
| +0x1C | u32 | **z_pos** | **z:%d** | `0x24b27d4: ldr w9, [x23, #0x1c]` |
| +0x2C | u32 | hp | hp=%d | `0x24b27c0: ldr w25, [x23, #0x2c]` |
| +0x34 | u32 | max_hp | max_hp:%d | `0x24b27ec: ldr w12, [x23, #0x34]` |

**x+z = w8 + w9** (0x24b27e4: `add w11, w9, w8`)

### 数组遍历入口

```
sub_24B2590:
  x21+0xC8 = UnitLabel array begin
  x21+0xD0 = UnitLabel array end
  遍历: for (x23 = begin; x23 < end; x23 += 0xB8)
  过滤: ldr w9, [x23, #0x2C]; cmp w9, #1; b.lt skip  (hp >= 1 有效)
```

### 有效性检查

```c
// 有效单位: hp (+0x2C) >= 1
if (unit_label.hp < 1) continue;

// x_pos 和 z_pos 是 32位整数, 范围约 0~30000
// x+z 也被记录 (用于距离判断)
```

## 数据结构 3: TargetFinder 中确认的坐标获取路径

来源: `0x3ac8a68` (TargetFinder), 使用格式串 `"hero_id:%d self_pos x:%d y:%d z:%d"`

```c
// 1. 通过 GOT 间接调用获取坐标 (返回 x0=packed(x,y), x1=z)
//    hero_id 从 actor + 0x0C 读取 (不是 +0x08)
//    ldr w3, [x21, #0xc]  ← hero_id

// 2. 坐标通过函数调用返回:
//    x23 = low32(pos_packed) = x
//    x23 >> 32 = y
//    x24 = low32(return2) = z
```

## 旧常量错误根因

| 旧常量 | IDA 确认的正确值 | 错误原因 |
|-------|-----------------|---------|
| ACTOR_SIZE=1008 | 1008 (正确) | 步长对, 但这是 Actor 数组, 不含坐标 |
| ACTOR_CAMP_ID=+0x08 | +0x0C (在 UnitLabel) | Actor+0x08 不是 camp_id |
| ACTOR_POS_X=+0x20 | +0x14 (在 UnitLabel) | Actor+0x20 不是坐标, 坐标在 UnitLabel |
| ACTOR_POS_Z=+0x24 | +0x1C (在 UnitLabel) | 同上 |
| ACTOR_POS_Y=+0x28 | 函数返回值 (不在数组) | y 坐标通过函数调用获取 |

## KPM 代码需要更新的常量

```c
// 旧常量 (错误!)
#define ACTOR_SIZE          1008
#define ACTOR_CAMP_ID       0x08
#define ACTOR_POS_X         0x20
#define ACTOR_POS_Z         0x24
#define ACTOR_POS_Y         0x28

// 正确常量 (IDA 反编译确认)
// 坐标在 UnitLabel(184字节) 数组中, 不在 Actor(1008字节) 数组中
#define UNIT_LABEL_SIZE     0xB8   // 184 字节
#define LABEL_TYPE_ID       0x00   // u32, type_id
#define LABEL_RUNTIME       0x04   // u32, runtime
#define LABEL_CAMP_ID       0x0C   // u32, camp_id (期望 1 或 2)
#define LABEL_POS_X         0x14   // u32, x_pos (整数)
#define LABEL_POS_Z         0x1C   // u32, z_pos (整数)
#define LABEL_HP            0x2C   // u32, hp (有效性检查: >= 1)
#define LABEL_MAX_HP        0x34   // u32, max_hp

// Actor(1008) 的已知字段
#define ACTOR_SIZE          0x3F0  // 1008 字节
#define ACTOR_ENTITY_ID     0x18   // u32, entity_id (关联 UnitLabel)
```

## UnitLabel 数组的定位方法

需要找到持有 UnitLabel 数组的容器对象。

已知: `sub_24B2590` 中 `x21+0xC8` = array_begin, `x21+0xD0` = array_end

x21 是传入参数 (UnitLabelFinder 对象指针), 在 IL2CPP 中可能是 ActorManager 或 ActorDataCenter 的 static_fields。

### 真机验证步骤

```
# 1. findclass ActorManager → 拿到 static_fields 地址
su -c '/data/adb/ksud kpm control hero-reader "findclass ActorManager"'

# 2. dump static_fields 的前 256 字节, 找 begin/end 指针对
su -c '/data/adb/ksud kpm control hero-reader "dump <static_fields> 64"'

# 3. 如果找到 begin/end 指针对, 验证步长 184:
#    读 begin, 检查 +0x2C (hp) >= 1
#    读 begin+184, 同样检查
#    读 begin+184*2, 同样检查

# 4. 确认是 UnitLabel 数组后, 扫描所有元素:
#    for each: read camp(+0x0C), x_pos(+0x14), z_pos(+0x1C), hp(+0x2C)
#    过滤: camp ∈ {1,2}, hp >= 1
#    → 输出坐标
```
