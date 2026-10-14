# IDA 分析完整证据链 (2026-10-14)

分析工具: IDA Pro v9.0 (libil2cpp.so) + Python capstone (libGameCore.so)
目标: libil2cpp.so (217MB, ARM64, IL2CPP v29) + libGameCore.so (82MB, ARM64)

---

## 一、IL2CPP 结构体偏移 (IDA 反编译确认)

### 函数 → 偏移映射

| 导出函数 | 地址 | 实现 | IDA 反编译结果 |
|---------|------|------|--------------|
| il2cpp_class_get_name | 0x3AA3F08 | sub_3AD153C | `return *(QWORD*)(a1 + 16)` |
| il2cpp_class_get_namespace | 0x3AA3F18 | sub_3AD1544 | `return *(QWORD*)(a1 + 24)` |
| il2cpp_class_get_static_field_data | 0x3AA4070 | inline | `return *(QWORD*)(a1 + 184)` |
| il2cpp_domain_get_assemblies | 0x3AA44DC | sub_3ACE6DC | `return &qword_E344EB8` |
| il2cpp_assembly_get_image | 0x3AA3D90 | sub_3ACE740 | `return *(QWORD*)a1` |
| il2cpp_image_get_name | 0x3AA5014 | sub_3AE17EC | `return *(QWORD*)a1` |
| il2cpp_image_get_class_count | 0x3AA5044 | sub_3AE1ED4 | `return *(uint*)(a1 + 24)` |

### s_domain 地址推导

```
sub_3ACE6DC: return &qword_E344EB8
qword_E344EB8 = s_domain + 0x18 (assemblies.begin)
s_domain = 0xE344EB8 - 0x18 = 0xE344EA0
S_DOMAIN_ADDR = base + 0xE344EA0
```

### 偏移汇总

```
s_domain:     base + 0xE344EA0
Domain:       +0x18 = assemblies.begin, +0x20 = end
Assembly:     +0x00 = image
Image:        +0x00 = name, +0x18 = class_count
Class:        +0x10 = name, +0x18 = namespace, +0xB8 = static_fields
```

---

## 二、UnitLabel 坐标布局 (capstone 反汇编确认)

### 核心突破: 坐标不在 Actor(1008) 数组中, 而在 UnitLabel(184) 数组中

### 证据1: sub_24B2590 (UnitLabelFinder::GetPosFromMonster)

字符串: `"frame=%d type=%d hp=%d camp:%d m_camp:%d config:%d runtime:%d max_hp:%d x:%d z:%d x+z:%d"`
位于 vaddr 0x11cb1f3 (libGameCore.so .rodata)

遍历步长:
```
0x24b2790: add x23, x23, #0xb8       ← 步长 0xB8 = 184 字节
```

数组遍历入口:
```
0x24b26e4: ldp x23, x8, [x21, #0xc8] ← x21+0xC8 = begin, x21+0xD0 = end
0x24b278c: ldr x8, [x21, #0xd0]      ← end 指针
0x24b2790: add x23, x23, #0xb8       ← next element
```

字段读取 (直接映射到格式串):
```
0x24b27c4: ldr w29, [x23]            ← +0x00: type_id  → 格式串 type=%d
0x24b27e8: ldr w10, [x23, #4]       ← +0x04: runtime  → 格式串 runtime=%d
0x24b27dc: ldr w4, [x23, #0xc]      ← +0x0C: camp_id  → 格式串 camp:%d
0x24b27d0: ldr w8, [x23, #0x14]     ← +0x14: x_pos    → 格式串 x:%d
0x24b27d4: ldr w9, [x23, #0x1c]     ← +0x1C: z_pos    → 格式串 z:%d
0x24b27e4: add w11, w9, w8          ← x+z 计算
0x24b27c0: ldr w25, [x23, #0x2c]    ← +0x2C: hp      → 格式串 hp=%d
0x24b27ec: ldr w12, [x23, #0x34]    ← +0x34: max_hp  → 格式串 max_hp:%d
```

有效性过滤:
```
0x24b279c: ldr w9, [x23, #0x2c]     ← 读取 hp
0x24b27a0: cmp w9, #1
0x24b27a4: b.lt skip                ← hp >= 1 有效
```

### 证据2: TargetFinder (0x3ac8a68)

格式串: `"hero_id:%d self_pos x:%d y:%d z:%d"` 位于 vaddr 0x114fb81

```
0x3ac8ac4: ldr w3, [x21, #0xc]      ← hero_id 在 actor+0x0C (不是旧的 +0x08)
```

坐标通过函数调用获取 (GOT 间接调用 0x509c000+0x70):
```
0x3ac8ab0: ldr x8, [x8, #0x70]      ← 加载坐标获取函数
0x3ac8ab8: blr x8                   ← 调用, 返回打包的坐标
0x3ac8aa4: mov x24, x1              ← z 坐标
0x3ac8aa8: mov x23, x0              ← packed(x,y) 坐标
```

### 证据3: Actor 数组 (步长 1008, 不含坐标)

```
0x3ac8934: mov w11, #0x3f0          ← ACTOR_SIZE = 1008
0x3ac8938: madd x10, x10, x11, x26  ← index * 1008 + base
0x3ac893c: ldr w10, [x10, #0x18]    ← Actor+0x18 = entity_id (不是坐标!)
```

---

## 三、UnitLabelFinder 容器关系 (capstone 追踪确认)

### UnitLabelFinder 初始化函数: 0x276a198

引用字符串:
- `"TacticsMultiTaskTwoHandAction"` @ 0x276a1c8
- `"[Init] init start"` @ 0x276a1cc
- `"comatk_unit_label_size"` @ 0x276abdc
- `"fail_to_init_unit_label_finder"` @ 0x276ad58

容器对象布局:
```
0x276a1bc: mov x24, x0              ← x24 = 容器对象 (函数参数0)
0x276abc8: add x0, x24, #0x220      ← x24+0x220 = UnitLabelFinder 子对象
0x276abcc: ldr x8, [x8, #0xd30]     ← 初始化函数 (BSS 间接调用)
0x276abd4: blr x8                   ← 初始化 UnitLabelFinder
```

容器对象 (TacticsMultiTaskTwoHandAction) 布局:
- x24+0x220 = UnitLabelFinder 子对象
- x24+0x2E8 = UnitLabelFinder + 0xC8 = UnitLabel array begin
- x24+0x2F0 = UnitLabelFinder + 0xD0 = UnitLabel array end

### C++ 类名确认

- `"UnitLabelFinder::GetPosFromMonster() "` @ 0x11d1bab
- `"UnitLabelFinder::GetPosFromOrgan() "` @ 0x1144ab3
- `"ai_tactics::GameTacticsManager::Init() "` @ 0x11a6c8e
- `"TacticsMultiTaskTwoHandAction::Init() "` @ 0x11b36c9

### 完整指针链 (IL2CPP → C++ 对象 → UnitLabel 数组 → 坐标)

```
base + 0xE344EA0                    → s_domain (Il2CppDomain*)
  s_domain + 0x18                   → assemblies[] (Il2CppAssembly**)
  assemblies[i] + 0x00              → image (Il2CppImage*)
  image (classes via findclass)     → Il2CppClass* (按类名匹配)
  class + 0xB8                      → static_fields (void*)
  static_fields → C++ 对象指针      → GameTacticsManager / TacticsMultiTaskTwoHandAction
  C++ 对象 + 0x220                  → UnitLabelFinder 子对象
  UnitLabelFinder + 0xC8            → UnitLabel array begin
  UnitLabelFinder + 0xD0            → UnitLabel array end
  UnitLabel[i] + 0x0C              → camp_id (u32)
  UnitLabel[i] + 0x14              → x_pos (u32)
  UnitLabel[i] + 0x1C              → z_pos (u32)
  UnitLabel[i] + 0x2C              → hp (u32, 有效性: >= 1)
```

---

## 四、旧常量错误根因

| 旧常量 | 正确值 | 错误原因 |
|-------|--------|---------|
| S_DOMAIN_ADDR=0xE340030 | 0xE344EA0 | sub_3ACE6DC 确认 |
| ACTOR_SIZE=1008 | UNIT_LABEL_SIZE=0xB8(184) | 坐标在 UnitLabel 不在 Actor |
| ACTOR_CAMP_ID=+0x08 | LABEL_CAMP_ID=+0x0C | Actor+0x08 不是 camp |
| ACTOR_POS_X=+0x20 | LABEL_POS_X=+0x14 | Actor+0x20 不是坐标 |
| ACTOR_POS_Z=+0x24 | LABEL_POS_Z=+0x1C | Actor+0x24 不是坐标 |
| ACTOR_POS_Y=+0x28 | 函数返回值 | y 不在数组中 |
