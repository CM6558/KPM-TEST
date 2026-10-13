# IDA 待分析清单

本文档记录**必须由 IDA 静态分析确认**的项目，以及每项的当前状态、已知证据、
和拿到结果后如何验证。所有"已验证"项都附真机证据；"待分析"项说明卡在哪。

目标二进制：`libil2cpp.so`（sgame，217 MB，SHA/大小见下）。
真机：OnePlus PJZ110 / Android 16 / kernel 6.6.150-android15 / SukiSU ksud kpm 3328。

```
文件: /data/app/~~-8T67XoZputHL8KbagHSMA==/com.tencent.tmgp.sgame-.../lib/arm64/libil2cpp.so
大小: 227661664 字节
MD5 : 见 build/ 或现场 md5sum（分析前请先核对）
```

---

## A. 已完成（无需再分析，已真机验证）

| # | 项目 | 结果 | 证据 |
|---|------|------|------|
| A1 | 装载基址算法 | `base = r-xp映射起点 − 0x3a84000`（maps 里**第二个** file_off=0 的映射） | walk 出 115 个 assembly 名字全对 |
| A2 | MTE 指针标记 | 指针高 16 位是标记，用前 `& 0x0000FFFFFFFFFFFF` | 读出值形如 `0xb400006ecf912c00` |
| A3 | `s_domain` 结构体位置 | `base + 0xe344ea0` | 反汇编 `0x3ace6dc`：`adrp #0xe344000 + add #0xeb8` |
| A4 | `Il2CppDomain.assemblies` begin/end | `+0x18` / `+0x20` | 同上；与仓库 IDA 常量 `DOMAIN_ASSEMBLIES_PTR 0x18` 吻合 |
| A5 | `Il2CppAssembly.image` | `+0x00` | 反汇编 `il2cpp_assembly_get_image` |
| A6 | `Il2CppImage.name` | `+0x00` | 反汇编 `il2cpp_image_get_name` |
| A7 | `Il2CppImage.class_count` | `+0x18` | 反汇编 `il2cpp_image_get_class_count` |
| A8 | `Il2CppClass.name` | `+0x10` | 反汇编 `il2cpp_class_get_name` |
| A9 | `Il2CppClass.namespace` | `+0x18` | 反汇编 `il2cpp_class_get_namespace` |
| A10 | `Il2CppClass.static_field_data` | `+0xB8` | 反汇编 `il2cpp_class_get_static_field_data` |
| A11 | 按类名定位（运行时扫描） | 可用（`findclass`），判据见下 | 命中 62+ 个真实类，image/ns 全对 |

`findclass` 判据（三条同时成立）：`+0x10`→合法类名；`+0x00`→合法 image（其 `+0x00` 以 `.dll` 结尾）；名字匹配。

---

## B. 待 IDA 分析（阻塞项）

### B1. 【最高优先】持有英雄/单位坐标数组的类 + 字段偏移

**为什么需要**：这是从"类表"到"坐标"的最后一跳，运行时可枚举但无法凭猜确定。

**已知**（真机 findclass 结果，都是真实类）：

| 类名 | image | 命名空间 | static_fields |
|------|-------|----------|---------------|
| `ActorManager` | Scripts.GameCore.dll | Assets.Scripts.GameLogic | `0x6d372f6200` |
| `ActorDataCenter` | Scripts.Base.dll | Assets.Scripts.GameLogic.DataCenter | — |
| `ActorDataProviderBase` | Scripts.Base.dll | ...DataCenter | — |
| `CLogicActorInfo` | Scripts.Base.dll | Assets.Scripts.GameLogic | — |
| `ActorInfoParser` | Scripts.Base.dll | Assets.Scripts.GameLogic | `0x6ca633c940` |
| `UnityObjMgr` | Scripts.GameCore.dll | — | `0x6d187dd920` |
| `CKdaDataManager` | Scripts.GameCore.dll | Assets.Scripts.GameLogic | `0x6d6a855280` |

**已知的负面证据**：`ActorManager.static_fields` 里有 `count=5` 的条目（一队 5 个英雄），
`+0x20` 指向一组 0x20 步长的指针记录；但 dump 出来**不是** 1008 字节的坐标结构。

**需要 IDA 给出**：
1. 类名（可能是 `ActorManager` / `ActorDataCenter` / 其他）+ **字段名/偏移**；
2. 该字段的类型（`List<T>` / `Dictionary` / 数组 / 自定义容器）；
3. 若为 `List<T>`：`T` 的元素结构（对应下面 B2）。

**验证方法**（拿到后用现成工具）：
```
su -c '/data/adb/ksud kpm control hero-reader "findclass <类名>"'   # 拿 static_fields
su -c '/data/adb/ksud kpm control hero-reader "dump <static_fields+偏移> 8"'  # 读数组指针
```

### B2. Actor / 单位元素的内存布局

**仓库现有常量（来自旧版 IDA，当前版本未验证）**：

```
ACTOR_SIZE      = 1008
ACTOR_CAMP_ID   = 0x08   (int, 期望 ∈ {1,2})
ACTOR_POS_X     = 0x20
ACTOR_POS_Z     = 0x24
ACTOR_POS_Y     = 0x28
```

**负面证据**：按这组常量做特征扫描，真机命中过"连续 8~10 块、camp∈{1,2}"的区段，
但坐标读数是垃圾（如 `y=-1001643487`、`x=1174738960`）→ **这组常量对当前版本不成立**。

**需要 IDA 给出**：
1. 元素真实大小；
2. camp / 阵营字段的真实偏移与类型（int？enum？）；
3. 坐标三元组的真实偏移（是 int 还是 float？）；
4. 有无可用于唯一辨识的字段（如 actor id、hp、模型指针）。

**验证方法**：`dump <actor_addr> <size/4>` 读原始字，与游戏内实际坐标比对。

### B3. `image → 类数组` 的偏移（可选）

`il2cpp_image_get_class(image, i)` 在文件里是跳转表字节（运行时才成形），静态读不出。
若需按索引枚举类（而非按名扫描），需 IDA 给出 `Il2CppImage` 里类数组的偏移。

**已知**：`Il2CppImage` 布局（真机 dump）：`+0x00` name、`+0x10` assembly、`+0x18` class_count、
`+0x28` 指向一个 0x18 步长的 `{ptr, u32, u32}` 表（**不是**类数组）。

### B4. `Il2CppClass` 其余字段（可选，便于扩展）

已确认 name/namespace/static_fields。若后续要读类的方法表、字段表、instance_size 等，需要：

| 字段 | 用途 |
|------|------|
| `instance_size` | 对象分配大小（辅助判断 1008 是否合理） |
| `fields` / `field_count` | 按字段名遍历（比硬编码偏移更稳） |
| `parent` | 类继承链（定位 `Actor` 基类） |
| `typeHierarchy` | 类型层级 |

---

## C. 运行时工具（模块内已实现，全部内核态）

| 命令 | 作用 |
|------|------|
| `set <pid> [base]` | 设目标；base 可省（内核侧自行定位） |
| `walk` | domain→assemblies→image，打印全部 image 名字与类数 |
| `findclass <词\|词>` | 按类名子串找 Il2CppClass，打印 image / ns / static_fields |
| `classes <image>` | 探测 image 的类数组偏移 |
| `dump <addr> [n]` | 读目标内存 n 个 32 位字（hex） |
| `peek <addr> [n]` | 同上（诊断用） |
| `vma <addr>` | 打印 `find_vma` 返回的 `vm_area_struct` 头部（偏移探测） |
| `scan` | 数组特征扫描（当前判据对不上，待 B2） |
| `actors <起> <止>` | 手动指定数组范围 |
| `read` | 立即读一次 |
| `find` | 放宽判据找候选（诊断） |
| `hunt` | 按结构偏移反查 domain（诊断） |
| `reset` | 清空目标状态 |

---

## D. 真机操作备忘（避免重复踩坑）

1. **推包必须 root**：`adb push` 到 `/sdcard` 后 `su -c 'cp ... /data/local/tmp/'`。
2. **内核读 `/proc/<pid>/maps` 被 SELinux 拦**（`filp_open` 返回 `-ENOENT`）→ 已改用纯内核 VMA 遍历。
3. **游戏会重启**：pid/base 每次都要重新取（`pidof` + `r-xp 起点 − 0x3a84000`）。
4. **VM 偏移**（真机探测，Android16/6.6.150）：`vm_area_struct: +0x00 vm_start, +0x08 vm_end, +0x10 vm_mm, +0x20 vm_flags, +0x78 vm_pgoff`。
5. **加载/卸载**：`/data/adb/ksud kpm load|unload|list|control`；结果看 `dmesg | grep hero-reader`。
