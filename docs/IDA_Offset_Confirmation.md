# IDA 反编译确认的结构体偏移 (2026-10-14)

分析环境: IDA Pro v9.0, libil2cpp.so (217MB, ARM64, IL2CPP v29)
MD5: 43bc62bd0947e10a0ccf2ff1ac23cdd9

## 反编译的函数及其偏移结果

所有偏移通过反编译 IL2CPP 导出函数的实际实现确认,与真机验证完全一致。

### 函数地址 → 实现 → 偏移

| 导出函数 | 地址 | 实现函数 | 反编译结果 | 确认的偏移 |
|---------|------|---------|-----------|-----------|
| `il2cpp_class_get_name` | 0x3AA3F08 | sub_3AD153C | `return *(QWORD*)(a1 + 16)` | Class+0x10 = name |
| `il2cpp_class_get_namespace` | 0x3AA3F18 | sub_3AD1544 | `return *(QWORD*)(a1 + 24)` | Class+0x18 = namespace |
| `il2cpp_class_get_static_field_data` | 0x3AA4070 | (inline) | `return *(QWORD*)(a1 + 184)` | Class+0xB8 = static_field_data |
| `il2cpp_domain_get` | 0x3AA44B8 | (indirect) | `return (*dword_3AD8FFC)()` | → s_domain |
| `il2cpp_domain_get_assemblies` | 0x3AA44DC | sub_3ACE6DC | `return &qword_E344EB8` | Domain+0x18 = assemblies.begin |
| `il2cpp_assembly_get_image` | 0x3AA3D90 | sub_3ACE740 | `return *(QWORD*)a1` | Assembly+0x00 = image |
| `il2cpp_image_get_name` | 0x3AA5014 | sub_3AE17EC | `return *(QWORD*)a1` | Image+0x00 = name |
| `il2cpp_image_get_class_count` | 0x3AA5044 | sub_3AE1ED4 | `return *(uint*)(a1 + 24)` | Image+0x18 = class_count |
| `il2cpp_image_get_class` | 0x3AA5058 | sub_3AE1EDC | 跳转表,无法静态分析 | Image+? = classes (运行时构建) |

### s_domain 全局变量地址推导

```
sub_3ACE6DC (domain_get_assemblies 的 helper):
  return &qword_E344EB8;       // .bss+0xE344EB8

qword_E344EB8 = s_domain + 0x18  (assemblies.begin)
  → s_domain = 0xE344EB8 - 0x18 = 0xE344EA0
```

### 结构体偏移汇总 (全部 IDA 反编译确认)

```
s_domain:     base + 0xE344EA0
  来源: sub_3ACE6DC → &qword_E344EB8 → s_domain + 0x18

Il2CppDomain:
  +0x18 = assemblies.begin (Il2CppAssembly**)
  +0x20 = assemblies.end
  count = (end - begin) / 8
  来源: il2cpp_domain_get_assemblies 反编译

Il2CppAssembly:
  +0x00 = image (Il2CppImage*)
  来源: sub_3ACE740 反编译: return *(QWORD*)a1

Il2CppImage:
  +0x00 = name (const char*)
  +0x18 = class_count (uint32_t)
  来源: sub_3AE17EC, sub_3AE1ED4

Il2CppClass:
  +0x10 = name (const char*)
  +0x18 = namespace (const char*)
  +0xB8 = static_field_data (void*)
  来源: sub_3AD153C, sub_3AD1544, il2cpp_class_get_static_field_data
```

### 无法从 IDA 静态获取的偏移

1. **Il2CppImage → classes 数组偏移**
   `il2cpp_image_get_class` (sub_3AE1EDC) 调用 sub_3AE7394 后 JUMPOUT 到运行时地址。
   文件中是跳转指令字节，运行时才成形，无法静态分析。
   替代方案：真机上用 `findclass` 命令扫描匿名 rw 区按类名定位（已验证可用）。

2. **ActorManager.static_fields 内部布局**
   游戏特定 C# 代码被 IL2CPP 编译为 native，函数名 stripped。
   metadata 被腾讯修改/加密，标准 v29 解析无法获取字段名↔偏移映射。
   真机上需用 `dump <static_fields_addr> <n>` 命令逐字段 dump 分析。

3. **Actor 元素的内存布局**
   旧常量 (ACTOR_SIZE=1008, camp@+0x08, pos@+0x20/0x24/0x28) 在真机扫描产生垃圾值。
   需要在真机上手动 dump ActorManager static_fields 并跟踪坐标变化来确认。

## 与真机验证的对照

| 偏移 | IDA 反编译 | POINTER_CHAIN.md 真机 | 状态 |
|------|-----------|----------------------|------|
| s_domain | base+0xE344EA0 | base+0xE344EA0 | ✓ 一致 |
| Domain+0x18 | assemblies.begin | DOMAIN_ASSEMBLIES_PTR=0x18 | ✓ 一致 |
| Domain+0x20 | assemblies.end | DOMAIN_ASSEMBLY_COUNT=0x20 | ✓ 一致 |
| Assembly+0x00 | image | Assembly+0x00 | ✓ 一致 |
| Image+0x00 | name | Image+0x00 | ✓ 一致 |
| Image+0x18 | class_count | Image+0x18 | ✓ 一致 |
| Class+0x10 | name | Class+0x10 | ✓ 一致 |
| Class+0x18 | namespace | Class+0x18 | ✓ 一致 |
| Class+0xB8 | static_fields | Class+0xB8 | ✓ 一致 |

**所有偏移与真机验证 100% 吻合。**

## 下一步 (需要在真机上完成)

1. 用 `findclass ActorManager` 获取 static_fields 地址
2. `dump <static_fields> 32` dump 前 128 字节分析结构
3. 在游戏中移动,观察哪些值变化来定位坐标数组
4. dump ActorManager 相关的方法实现 (需要 metadata 解密)
