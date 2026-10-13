# 指针链定位：真机验证记录

设备：OnePlus PJZ110 / Android 16 / kernel 6.6.150-android15 / SukiSU (ksud kpm loader 3328)
目标：`com.tencent.tmgp.sgame`（libil2cpp.so 217 MB，启用 ARM MTE）

## 1. 装载基址（关键，容易算错）

maps 里 libil2cpp 有**两处 file_off=0** 的映射：

```
0x6d28745000-0x6d36063000  r--p file_off=0   ← 不是基址（整文件只读映射）
0x6e90035000-0x6e93ab9000  r--p file_off=0   ← 真基址
0x6e93ab9000-0x6e9632c000  r-xp file_off=0x3a83000   ← 与它地址连续
```

**判据**：`base = r-xp 映射起点 − 0x3a84000`（`.text` 的 vaddr）。

- 用错的基址（第一个映射）→ `s_domain` 落在真空隙，读到垃圾。
- 用对的基址 → `base+0xe344ea0` 落在 `[anon:.bss]` 内，读出的 assemblies 向量完全合理。

## 2. ARM MTE：指针带高位标记

读出的指针形如 `0xb400006ecf912c00`。**取址前必须去标记**：

```c
#define PTR_MASK 0x0000FFFFFFFFFFFFUL
addr = ptr & PTR_MASK;
```

## 3. 已验证的偏移（静态反汇编 + 真机读值双向确认）

| 结构 | 字段 | 偏移 | 来源 |
|------|------|------|------|
| Il2CppDomain | assemblies.begin | `+0x18` | 反汇编 `il2cpp_domain_get`→`0x3ace6dc`：`adrp #0xe344000 + add #0xeb8` |
| Il2CppDomain | assemblies.end | `+0x20` | 同上 |
| Il2CppAssembly | image | `+0x00` | 反汇编 `il2cpp_assembly_get_image`（`ldr x0,[x0]`） |
| Il2CppImage | name | `+0x00` | 反汇编 `il2cpp_image_get_name`（`ldr x0,[x0]`） |
| Il2CppImage | class_count | `+0x18` | 反汇编 `il2cpp_image_get_class_count`（`ldr w0,[x0,#0x18]`） |
| Il2CppClass | name | `+0x10` | 反汇编 `il2cpp_class_get_name`（`ldr x0,[x0,#0x10]`） |
| Il2CppClass | namespace | `+0x18` | 反汇编 `il2cpp_class_get_namespace`（`ldr x0,[x0,#0x18]`） |
| Il2CppClass | static_field_data | `+0xB8` | 反汇编 `il2cpp_class_get_static_field_data`（`ldr x0,[x0,#0xb8]`） |
| — | s_domain 结构体 | `base + 0xe344ea0` | 由 `0x3ace6dc` 的 ADRP+ADD 推出；`+0x18` 处的向量与 IDA 的 `DOMAIN_ASSEMBLIES_PTR` 一致 |

与仓库原有 IDA 常量对照：`DOMAIN_ASSEMBLIES_PTR=0x18` ✓、`DOMAIN_ASSEMBLY_COUNT=0x20` ✓ 完全吻合。
`s_domain` 的位置是 `base+0xe344ea0`（不是 0xe340030）。

## 4. 真机输出（指针链前半段完全打通）

```
walk: domain=0x6e9df83ea0  assemblies=0x6ecf912c00-0x6ecf912f98 (115 个)
  asm[0]  image=0x6ff15e2000 classes=12892 name=Scripts.System.dll
  asm[3]  image=0x6ff15e20d8 classes=4067  name=Scripts.GameCore.dll
  asm[5]  image=0x6ff15e2168 classes=1745  name=mscorlib.dll
  ... 115 个 assembly 名字全部正确
```

## 5. 按类名定位（findclass）

`findclass <子串|关键词>` 扫描 rw 区找 Il2CppClass，判据（三条同时成立，假阳性极低）：
1. `+0x10` 指向合法类名字符串；
2. `+0x00` 指向一个 Il2CppImage（该 image 的 `+0x00` 是以 `.dll` 结尾的名字）；
3. 名字匹配目标关键词。

实测命中的真实类（image/命名空间均正确）：

```
ActorManager        Scripts.GameCore.dll  Assets.Scripts.GameLogic   static_fields=0x6d372f6200
ActorDataCenter     Scripts.Base.dll      Assets.Scripts.GameLogic.DataCenter
ActorInfoParser     Scripts.Base.dll      Assets.Scripts.GameLogic   static_fields=0x6ca633c940
CLogicActorInfo     Scripts.Base.dll      Assets.Scripts.GameLogic
CKdaDataManager     Scripts.GameCore.dll  Assets.Scripts.GameLogic   static_fields=0x6d6a855280
CKdaHeroPtr         Scripts.Base.dll      Assets.Scripts.GameLogic
UnityObjMgr         Scripts.GameCore.dll                             static_fields=0x6d187dd920
```

## 6. 未完成：坐标数组的定位

- 扫描（ACTOR_SIZE=1008 + camp@0x08 + 坐标@0x20/0x24/0x28）在真机上**出假阳性**，坐标读数是垃圾值 → 该组布局常量对当前版本不成立或数组在别处。
- `ActorManager` / `ActorDataCenter` / `CKdaDataManager` 的 static_fields 里能找到 count=5 的条目（一队 5 个英雄），但 dump 出来是 0x20 字节的指针记录/战绩结构，**未找到 1008 字节的坐标结构**。

**下一步需要**：持有英雄坐标数组的**类名 + 字段偏移**，以及该数组元素布局（是否仍为 1008 字节 / camp 在 +0x08 / 坐标在 +0x20,0x24,0x28）。

## 7. 工具（模块内已实现，全部内核态）

| 命令 | 作用 |
|------|------|
| `set <pid> [base]` | 设目标；base 可省（内核侧自行定位） |
| `walk` | 遍历 domain→assemblies→image，打印全部 image 名字与类数 |
| `findclass <词\|词>` | 按类名（子串）找 Il2CppClass，打印 image/ns/static_fields |
| `classes <image>` | 探测 image 的类数组偏移 |
| `dump <addr> [n]` | 读目标内存 n 个 32 位字 |
| `peek <addr> [n]` | 读目标内存 n 个 32 位字（诊断） |
| `vma <addr>` | 打印 find_vma 返回的 vm_area_struct 头部 |
| `scan` / `actors` / `read` / `find` / `hunt` / `reset` | 数组扫描 / 手动指定 / 读取 / 候选搜索 / domain 反查 / 复位 |
