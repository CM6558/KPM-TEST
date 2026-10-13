# Hero Reader KPM — 内核态 IL2CPP 指针链读取

一个 KernelPatch Module (`.kpm`)：在**内核态（EL1）**遍历 Unity/IL2CPP 游戏的类型系统
（domain → assemblies → image → classes → static_fields），定位并读取战斗数据，
结果输出到内核日志。用户态不参与任何数据面操作。

**当前进度**：指针链前半段已在真机跑通（115 个 assembly 名字全部正确、按类名可定位
`ActorManager` 等真实类）；**最后一跳（坐标数组）待 IDA 补齐偏移** —— 详见
[`docs/IDA_TODO.md`](docs/IDA_TODO.md) 与 [`docs/POINTER_CHAIN.md`](docs/POINTER_CHAIN.md)。

```
dmesg | grep hero-reader
[hero-reader] 目标 pid=12345
[hero-reader] 已锁定目标 mm (pid=12345)
[hero-reader] base=0x6e90035000 (ctl0)
[hero-reader] walk: domain=0x6e9df83ea0 assemblies=0x6ecf912c00-0x6ecf912f98 (115 个)
[hero-reader]   asm[3] 0x6e859cf108 image=0x6e8d0378d8 classes=4067 name=Scripts.GameCore.dll
[hero-reader] findclass: 'ActorManager' class=0x6d2c431200 image='Scripts.GameCore.dll' \
              ns='Assets.Scripts.GameLogic' static_fields=0x6d372f6200
```

## 真机验证环境

OnePlus PJZ110 / Android 16 / kernel `6.6.150-android15` / SukiSU Ultra（`ksud kpm` loader 3328）。
目标 `com.tencent.tmgp.sgame`，`libil2cpp.so` 227,661,664 字节，启用 ARM MTE。

## 内核态完成的操作

| 环节 | 实现（全部内核态） |
|------|:------------------|
| 捕获游戏进程 pid | inline hook `access_process_vm`，比对 `task_struct->comm` 含 `sgame`/`tmgp` |
| 锁定地址空间 | RCU 临界区内 `find_task_by_vpid` + `get_task_mm` 取 mm 引用（不持有 task_struct） |
| 定位装载基址 | 纯内核 VMA 遍历（`find_vma`），按 `r-xp起点 − .text vaddr` 求 base |
| 遍历类型系统 | domain → assemblies → image → class（偏移由静态反汇编确认） |
| 按类名定位 | 内核扫描 rw 区匹配 Il2CppClass（三条判据，见下） |
| 读目标内存 | `access_remote_vm(mm, …)` |
| 结果输出 | `pr_info` → dmesg |

## 三个真机踩出来的关键机制

1. **装载基址 = maps 里第二处 file_off=0 的映射**。libil2cpp 有两处：整文件只读映射
   和真正装载的那处。判据：`base = r-xp 映射起点 − 0x3a84000`（`.text` 的 vaddr）。
   用错的那处 → `s_domain` 落在真空隙、读出垃圾。
2. **ARM MTE**：指针带高位标记（形如 `0xb400006e…`），取址前必须
   `addr & 0x0000FFFFFFFFFFFF`。
3. **内核读 `/proc/<pid>/maps` 被 SELinux 拦**（`filp_open` 返回 `-ENOENT`）⇒
   基址与数组定位全部改走**纯内核 VMA 遍历**（`find_vma(mm, addr)` 顺序走链表）。

## 已验证的 IL2CPP 结构偏移

| 结构 | 字段 | 偏移 | 验证方式 |
|------|------|------|----------|
| Il2CppDomain | assemblies begin / end | `+0x18` / `+0x20` | 反汇编 `0x3ace6dc`（`adrp #0xe344000 + add #0xeb8`）；与 IDA 常量吻合 |
| Il2CppAssembly | image | `+0x00` | 反汇编 `il2cpp_assembly_get_image` |
| Il2CppImage | name / class_count | `+0x00` / `+0x18` | 反汇编 `il2cpp_image_get_name` / `_class_count` |
| Il2CppClass | name / namespace / static_field_data | `+0x10` / `+0x18` / `+0xB8` | 反汇编 `il2cpp_class_get_*` |
| — | s_domain 结构体 | `base + 0xe344ea0` | 由 `0x3ace6dc` 推出 |

`findclass` 判据（三条同时成立，假阳性极低）：`+0x10`→合法类名；`+0x00`→合法 image
（其 `+0x00` 以 `.dll` 结尾）；名字匹配关键词。

## 关键设计取舍

1. **未定义符号只有两扇门。** loader 对模块内 UND 符号只查 KP 导出表（兜底 SukiSU
   compact 表），**不查普通 kallsyms**。直接引用只能是 KP 导出符号和 `kf_*` kfunc 桩；
   其余内核函数一律 `kallsyms_lookup_name()` 解析成指针并判空。手工 `extern` 内核函数名
   会产出裸符号 → 加载期 `unknown symbol`。`scripts/check_kpm.sh` 就是拦这个的 CI 门。
2. **绝不解析宏 / inline 名。** 6.6 上 `kthread_run` 是宏，`rcu_read_lock`/`get_task_struct`/
   `put_task_struct` 是 static inline —— 都不是符号。改用 `kthread_create_on_node` +
   `wake_up_process`、`__rcu_read_lock`/`__rcu_read_unlock`、`find_task_by_vpid`、
   `get_task_mm`、`mmput`。
3. **不持有 task_struct。** `put_task_struct` 非符号 ⇒ 只取 mm 引用
   （`get_task_mm`），临界区外只用 `mm`，最后 `mmput()`。
4. **结构体偏移只信 KP。** 任务字段用 KP 导出的 `task_struct_offset`（实测：只填了
   `comm_offset`，`pid_offset` 为 -1 ⇒ 取 pid 改用真实符号 `__task_pid_nr_ns`）。
5. **SukiSU 上 ctl0 没有字符串回传。** `ksud kpm control` 只回 int；细节一律 `pr_info`
   进 dmesg。`compat_copy_to_user` 只在 `out_msg` 非空时调用（兼容 APatch）。
6. **hook 回调极轻。** before 回调只做计数 + comm 比较 + 写请求槽；reader 线程是唯一的
   状态机消费者（mm 的取放单点）。

## 构建

```sh
git clone --depth=1 https://github.com/ShirkNeko/SukiSU_KernelPatch_patch.git KernelPatch
NDK_PATH=/path/to/android-ndk KP_DIR=$PWD/KernelPatch make
make check                      # 产物静态自检 (scripts/check_kpm.sh)
```

自检内容：`ET_REL` + `AArch64`、必备节 `.kpm.info/.kpm.init/.kpm.exit`、**未定义符号白名单**
（只允许 `kf_*` 与固定 KP 导出集合）。CI 见 `.github/workflows/build.yml`。

## 部署与运行

```sh
# 推包 (root; /sdcard 是 noexec)
adb push hero_reader.kpm /sdcard/
su -c 'cp /sdcard/hero_reader.kpm /data/local/tmp/'
adb push scripts/vt-drive.sh /sdcard/
su -c 'cp /sdcard/vt-drive.sh /data/local/tmp/ && chmod 755 /data/local/tmp/vt-drive.sh'

su -c '/data/adb/ksud kpm load /data/local/tmp/hero_reader.kpm'

# 一条命令驱动 (自动取 pid/base, 结果看 dmesg)
su -c 'sh /data/local/tmp/vt-drive.sh walk'
su -c 'sh /data/local/tmp/vt-drive.sh findclass Actor|Hero'
su -c 'sh /data/local/tmp/vt-drive.sh dump 0x6e9df83ea0 16'
su -c 'sh /data/local/tmp/vt-drive.sh log 30'

su -c '/data/adb/ksud kpm unload hero-reader'
```

开机自动加载：把 `.kpm` 放进 `/data/adb/kpm/`（ksud booted_load；safe mode 跳过）。

## ctl0 控制命令

结果一律看 dmesg；SukiSU 上返回值只是 int。

| 命令 | 作用 |
|------|------|
| `status` / `info` | pid / mm / base / s_domain / actors / 英雄数 / hook 触发次数 |
| `set <pid> [base]` | 设目标（base 可省） |
| `walk` | 遍历 domain→assemblies→image，打印全部 image 名字与类数 |
| `findclass <词\|词>` | 按类名子串找 Il2CppClass，打印 image / ns / static_fields |
| `classes <image>` | 探测 image 的类数组偏移 |
| `dump <addr> [n]` / `peek <addr> [n]` | 读目标内存 n 个 32 位字 |
| `vma <addr>` | 打印 `vm_area_struct` 头部（偏移探测） |
| `scan` / `actors` / `read` / `find` / `hunt` / `reset` | 数组扫描 / 手动指定 / 读取 / 候选搜索 / domain 反查 / 复位 |

## 状态与待办

| 环节 | 状态 |
|------|------|
| 内核态 pid 捕获 / mm 锁定 / 基址定位 | ✅ 真机验证 |
| domain→assemblies→image→class + 按类名定位 | ✅ 真机验证 |
| 坐标数组定位（最后一跳） | ⏳ 待 IDA 偏移（见 `docs/IDA_TODO.md` B1/B2） |

`ACTOR_SIZE=1008` / `camp@0x08` / 坐标 `0x20,0x24,0x28` 这组旧常量在当前版本
**未通过真机验证**（扫描命中的段坐标是垃圾值），需 IDA 重新确认。

## 内核日志前缀

统一 `[hero-reader]`。关键行：`目标 pid=`、`已锁定目标 mm`、`base=`、`walk:`、
`findclass:`、`自动发现 Actor 数组:`、`Hero Positions`、`FATAL:`、`状态复位:`。
