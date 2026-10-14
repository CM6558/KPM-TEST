# IDA 反编译确认的结构体偏移 (2026-10-14 更新)

分析环境: IDA Pro v9.0, libil2cpp.so (217MB, ARM64, IL2CPP v29) + capstone (libGameCore.so)
MD5: 43bc62bd0947e10a0ccf2ff1ac23cdd9

## 一、IL2CPP 结构体偏移 (IDA 反编译导出函数确认)

| 导出函数 | 地址 | 实现函数 | 反编译结果 | 确认的偏移 |
|---------|------|---------|-----------|-----------|
| `il2cpp_class_get_name` | 0x3AA3F08 | sub_3AD153C | `return *(QWORD*)(a1 + 16)` | Class+0x10 = name |
| `il2cpp_class_get_namespace` | 0x3AA3F18 | sub_3AD1544 | `return *(QWORD*)(a1 + 24)` | Class+0x18 = namespace |
| `il2cpp_class_get_static_field_data` | 0x3AA4070 | (inline) | `return *(QWORD*)(a1 + 184)` | Class+0xB8 = static_field_data |
| `il2cpp_domain_get_assemblies` | 0x3AA44DC | sub_3ACE6DC | `return &qword_E344EB8` | Domain+0x18 = assemblies.begin |
| `il2cpp_assembly_get_image` | 0x3AA3D90 | sub_3ACE740 | `return *(QWORD*)a1` | Assembly+0x00 = image |
| `il2cpp_image_get_name` | 0x3AA5014 | sub_3AE17EC | `return *(QWORD*)a1` | Image+0x00 = name |
| `il2cpp_image_get_class_count` | 0x3AA5044 | sub_3AE1ED4 | `return *(uint*)(a1 + 24)` | Image+0x18 = class_count |
| `il2cpp_image_get_class` | 0x3AA5058 | sub_3AE1EDC | 跳转表,无法静态分析 | Image+? = classes (运行时构建) |

### s_domain 全局变量

```
sub_3ACE6DC 返回 &qword_E344EB8 (.bss+0xE344EB8)
qword_E344EB8 = s_domain + 0x18 (assemblies.begin)
→ s_domain = 0xE344EB8 - 0x18 = 0xE344EA0
→ S_DOMAIN_ADDR = base + 0xE344EA0
```

### 所有偏移与真机验证 100% 吻合

| 偏移 | IDA 反编译 | POINTER_CHAIN.md 真机 | 状态 |
|------|-----------|----------------------|------|
| s_domain | base+0xE344EA0 | base+0xE344EA0 | ✓ |
| Domain+0x18 | assemblies.begin | DOMAIN_ASSEMBLIES_PTR=0x18 | ✓ |
| Assembly+0x00 | image | Assembly+0x00 | ✓ |
| Image+0x00 | name | Image+0x00 | ✓ |
| Image+0x18 | class_count | Image+0x18 | ✓ |
| Class+0x10 | name | Class+0x10 | ✓ |
| Class+0x18 | namespace | Class+0x18 | ✓ |
| Class+0xB8 | static_fields | Class+0xB8 | ✓ |

## 二、UnitLabel 坐标布局 (IDA 反编译 + capstone 确认) — 突破

### 核心发现: 坐标不在 Actor(1008) 数组中, 而在 UnitLabel(184) 数组中

**证据1**: `sub_24B2590` (UnitLabelFinder::GetPosFromMonster) @ libGameCore.so

格式串: `"frame=%d type=%d hp=%d camp:%d m_camp:%d config:%d runtime:%d max_hp:%d x:%d z:%d x+z:%d"`
位于 vaddr 0x11cb1f3, 引用代码在 vaddr 0x24b27f4。

遍历步长: `0x24b2790: add x23, x23, #0xb8` (184 字节)

汇编证据 (capstone 反汇编):
```
0x24b27c4: ldr w29, [x23]           ← +0x00: type_id (格式串 type=%d)
0x24b27e8: ldr w10, [x23, #4]       ← +0x04: runtime (格式串 runtime=%d)
0x24b27dc: ldr w4, [x23, #0xc]      ← +0x0C: camp_id (格式串 camp:%d)
0x24b27d0: ldr w8, [x23, #0x14]     ← +0x14: x_pos (格式串 x:%d) ← 坐标X!
0x24b27d4: ldr w9, [x23, #0x1c]     ← +0x1C: z_pos (格式串 z:%d) ← 坐标Z!
0x24b27e4: add w11, w9, w8          ← x+z 计算
0x24b27c0: ldr w25, [x23, #0x2c]    ← +0x2C: hp (格式串 hp=%d)
0x24b27ec: ldr w12, [x23, #0x34]    ← +0x34: max_hp (格式串 max_hp:%d)
```

有效性过滤: `0x24b279c: ldr w9, [x23, #0x2c]; cmp w9, #1; b.lt skip` (hp >= 1)

数组入口: `x21+0xC8` = begin, `x21+0xD0` = end

**证据2**: `0x3ac8a68` (TargetFinder) @ libGameCore.so

格式串: `"hero_id:%d self_pos x:%d y:%d z:%d"` 位于 vaddr 0x114fb81。
引用代码在 vaddr 0x3ac8ac0: `adrp x2, #0x114f000; add x2, x2, #0xb81`

hero_id 读取: `0x3ac8ac4: ldr w3, [x21, #0xc]` (actor+0x0C, 不是旧的 +0x08)

**证据3**: Actor 数组遍历 (步长 1008, 不含坐标)

```
0x3ac8934: mov w11, #0x3f0          ← ACTOR_SIZE = 1008
0x3ac8938: madd x10, x10, x11, x26  ← index * 1008 + base
0x3ac893c: ldr w10, [x10, #0x18]    ← Actor+0x18 = entity_id (不是坐标!)
```

### 旧常量错误根因

| 旧常量 | IDA 确认的正确值 | 错误原因 |
|-------|-----------------|---------|
| S_DOMAIN_ADDR=0xE340030 | 0xE344EA0 | 偏移错误 |
| ACTOR_SIZE=1008 | 1008 (对, 但不含坐标) | 步长对但坐标不在其中 |
| ACTOR_CAMP_ID=+0x08 | +0x0C (在 UnitLabel) | Actor+0x08 不是 camp_id |
| ACTOR_POS_X=+0x20 | +0x14 (在 UnitLabel) | Actor+0x20 不是坐标 |
| ACTOR_POS_Z=+0x24 | +0x1C (在 UnitLabel) | 同上 |
| ACTOR_POS_Y=+0x28 | 函数返回值 | y 不在数组中 |

### 正确的常量

```c
#define S_DOMAIN_ADDR     0xE344EA0UL  // IDA: sub_3ACE6DC
#define UNIT_LABEL_SIZE   0xB8         // 184 字节, IDA: 0x24b2790
#define LABEL_TYPE_ID     0x00         // u32, IDA: ldr w29, [x23]
#define LABEL_RUNTIME     0x04         // u32, IDA: ldr w10, [x23, #4]
#define LABEL_CAMP_ID     0x0C         // u32, IDA: ldr w4, [x23, #0xc]
#define LABEL_POS_X       0x14         // u32, IDA: ldr w8, [x23, #0x14]
#define LABEL_POS_Z       0x1C         // u32, IDA: ldr w9, [x23, #0x1c]
#define LABEL_HP          0x2C         // u32, IDA: ldr w25, [x23, #0x2c]
#define LABEL_MAX_HP      0x34         // u32, IDA: ldr w12, [x23, #0x34]
#define ACTOR_SIZE        0x3F0        // 1008 字节 (不含坐标)
#define ACTOR_ENTITY_ID   0x18         // u32, IDA: ldr w10, [x10, #0x18]
```

## 三、无法从 IDA 静态获取的偏移

1. **Il2CppImage → classes 数组**
   `il2cpp_image_get_class` (sub_3AE1EDC) 是运行时跳转表。
   手动反汇编 @ 0x3AE19D8 发现读取 Image+0x30 (可能是 typeStart/metadata structure)。
   
2. **ActorManager.static_fields 内部布局**
   metadata 被腾讯加密/修改, 标准 v29 解析失败。
   字符串表在文件偏移 0x9a900 处但内容被加密; 可读字符串在 0x2a31fa 处但不在声明范围内。
   需要真机 dump 确认。

3. **UnitLabel 数组在哪个类的 static_fields 中**
   sub_24B2590 中 x21+0xC8 = begin, x21+0xD0 = end。
   x21 可能是 ActorManager/ActorDataCenter/CKdaDataManager 的 static_fields。
   需要真机 findclass + dump 确认。
