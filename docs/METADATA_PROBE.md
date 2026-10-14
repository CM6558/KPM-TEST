# Metadata 探测流程 (2026-10-14)

## 目标

消除 `static_fields + ??? → C++ 对象` 指针链断裂点。
通过运行时内存中已解密的 IL2CPP metadata, 解析字段定义表,
获取 ActorManager 类所有字段的精确偏移。

## 使用方法

```bash
# 在真机上执行 (需要先 KPM 加载, game 运行中):
# 1. 确认 base 已就绪
/data/adb/ksud kpm control hero-reader "status"

# 2. 探测 ActorManager 类的字段偏移
/data/adb/ksud kpm control hero-reader "probe ActorManager"

# 3. 查看结果
dmesg | grep hero-reader | tail -40

# 预期输出:
# [hero-reader] probe: s_metadata=0x7abc123000
# [hero-reader] probe: magic=0xFAB11BAF version=29 ✓
# [hero-reader] probe: typedef count=64125 (合理范围 50K~100K)
# [hero-reader] ★ 找到类 'ActorManager' (namespace='Assets.Scripts.GameLogic', ...)
# [hero-reader]   field[0]: 'instance' offset=0x08
# [hero-reader]   field[1]: 'initialized' offset=0x10
# [hero-reader]   field[2]: 'actorList' offset=0x18
# ...

# 4. 闭环验证: 读 static_fields + 0x08 (= field[0] offset)
#    验证是否合法堆指针 → +0x220 + 0xC8 → UnitLabel 数组
/data/adb/ksud kpm control hero-reader "findclass ActorManager"
# → static_fields=0x7def000000
/data/adb/ksud kpm control hero-reader "dump 0x7def000008 4"
# → 读到的值是堆指针 → dump ptr+0x220+0xC8 → 应是数组 begin
```

## 六层验证链

```
① metadata magic/version
   → 0xFAB11BAF / 29                           ✓ 确认是 IL2CPP metadata
② 表偏移合理范围
   → typedef count 50K~100K, fielddef count合理  ✓ 确认 metadata 完整
③ 字符串表交叉验证
   → 从字符串表读到 "ActorManager"              ✓ 字符串表正确
④ 字段表解析
   → 读出每个字段的 name + offset               ✓ 字段表正确
⑤ 闭环验证: field offset → static_fields → 堆指针
   → static_fields + offset 是合法堆指针          ✓ 偏移可信
⑥ 终极验证: 堆指针 → +0x220 → +0xC8 → UnitLabel 数组
   → (end - begin) % 184 == 0, camp∈{1,2}      ✓ 完整正确
```

## 实现细节

### s_metadata 指针
```
base + 0xE340010  →  s_GlobalMetadataHeader (Il2CppGlobalMetadataHeader*)
```
IDA 确认: il2cpp_init() 将解密后的 metadata 头部指针写入 .bss+0xE340010。

### IL2CPP v29 Metadata Header 布局
```
+0x00  u32  magic         (0xFAB11BAF)
+0x04  u32  version       (29)
+0x08  {offset, count}    stringLiteral table
+0x10  {offset, count}    string table          ← 所有类名/字段名的文本
...
+0x58  {offset, count}    field table           ★ 字段定义表
+0x98  {offset, count}    typeDefinitions table ★ 类型定义表
+0xA0  {offset, count}    images table
```

### TypeDefinition (v29, 108 bytes)
```
+0x00  u32  nameIndex        → string table idx → 类名
+0x04  u32  namespaceIndex   → string table idx → 命名空间
...
+0x4C  u32  fieldsStart      → 字段表起始 index (可能需真机调)
+0x50  u32  fieldCount        → 字段数量
```

### FieldDefinition (v29, 24 bytes)
```
+0x00  u32  nameIndex        → string table idx → 字段名
+0x04  u32  typeIndex        → 类型信息 (Il2CppType*)
+0x0C  u32  offset           → 字段在 static_fields 中的偏移 ★
```

### 注意事项
- TYPEDEF_SIZE=108 和 FIELDDEF_SIZE=24 是 IL2CPP v29 的标准大小
- TD_FIELDS_START=0x4C 在不同 IL2CPP 版本可能不同, 真机上会打印诊断信息
- 如果探测失败, 会打印前 10 个类名验证字符串表是否正常
- 腾讯可能对 metadata 有二次混淆, 真机上需验证

## 失败回退

如果 metadata 探测失败 (magic 不对 / 表偏移异常 / 类名找不到):
1. 方法一: ctl0 `findclass ActorManager` → `dump <sf> 256` 逐偏移手动探测
2. 方法二: 保留现有的 `scan_actor_arrays_vma` 盲扫方案作为兜底
