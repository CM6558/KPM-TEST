# hero_reader 模块化拆分 + 4 根因修复说明

## 1. 拆分概要

原 `hero_reader.c` 133KB / 2909 行单体文件,按功能拆成 8 个文件:

| 文件 | 大小 | 行数 | 功能 |
|------|------|------|------|
| `hr_internal.h` | 18.9 KB | 395 | 公共头:宏/类型/全局变量/`rm`/`r32`/`rstr` 原语 |
| `hr_pagewalk.c` | 5.1 KB | 131 | 页表 walk + VMA 遍历 + ELF base 定位 |
| `hr_metadata.c` | 7.1 KB | 173 | IL2CPP metadata 验证/大小/转储 |
| `hr_il2cpp_scan.c` | 38.4 KB | 851 | IL2CPP class/field/static_fields 查找 + 诊断扫描 |
| `hr_actor_chain.c` | 25.5 KB | 566 | **★ 核心**:GameRoot→CActorManager→Hero→Transform→VInt3 坐标链 |
| `hr_diag.c` | 5.3 KB | 136 | 诊断:do_walk/do_peek/do_name/do_dump/do_gcwatch |
| `hr_lifecycle.c` | 32.7 KB | 658 | 生命周期:init/exit/ctl0/reader_thread/find_pid/pin_mm |
| `hero_reader.c` | 0.9 KB | — | 主入口(#include 所有模块,编译时合并为单 .o)|

## 2. 编译

**方式 A(推荐,KPM Makefile)**: `#include` 合并编译(对 Makefile 最小改动)
```makefile
# 原:  hero_reader.o: hero_reader.c heromap.h
# 改:  hero_reader.o: hero_reader.c hr_internal.h hr_pagewalk.c hr_metadata.c hr_il2cpp_scan.c hr_actor_chain.c hr_diag.c hr_lifecycle.c heromap.h
#       $(CC) -c hero_reader.c -o $@
```
`hero_reader.c` 内容(已提供)就是 `#include "hr_internal.h"` + `#include` 其他 6 个 .c。

**方式 B(可选拆编译)**: Makefile 改成编译 7 个 .o 后链接 — 对 KPM ELF 重定位段约束更友好。

## 3. 4 根因修复

### 根因 #1(直接导致"过段时间不准")— `get_actor_coords` 回退到 SetSpawnPosition

**位置**:`hr_actor_chain.c` → `get_actor_coords()` (L421)

**原代码问题**:
```c
if (xx != 0 || zz != 0) {
    *ox = xx / 10; ...
    return 1;
}
/* fallback 到路径 2 (+32/+40/+44) */
rm(&xx, actor + 32UL, 4);  /* ★ 这是 SetSpawnPosition 写的出生点, 不更新 */
if (xx != 0 || zz != 0) {
    *ox = xx; ...
    return 2;  /* ← 返回出生点坐标, 开局后"卡住" */
}
```

**修复**:**删除路径 2**,只保留 Transform 链。Transform 链读失败 → 返回 0(坐标保持 0,不写入错误数据)。

### 根因 #2 — Transform 链无 seqlock 读 race

**位置**:`hr_actor_chain.c` → `get_actor_coords()` (L451-458)

**修复**:读完整个 Transform→VInt3 链后,重读 `node` 和 `link` 指针比对一致性:
```c
/* seqlock: 重读 node/link 比对 */
rm(&node2, actor + 0xA8UL, 8);
node2 = untag(node2);
if (node2 != node) return 0;  /* node 被换 → 丢弃 */
rm(&link2, node + 0x10UL, 8);
link2 = untag(link2);
if (link2 != link) return 0;  /* link 被换 → 丢弃 */
```

### 根因 #3 — `gc_base()` 永久缓存不刷新

**位置**:原 `hero_reader.c` L1880-1889(`hr_pagewalk.c`)

**修复**(见 `15-root-case-fix-patch.md`):每 30 帧重新校验 base 有效性(通过 GOT 读 `0x51EA4D0` 内容是否是合法指针),过期则 reset 重定位。

### 根因 #4 — IndexBuffer 读 race

**位置**:`hr_actor_chain.c` → `read_rootactor_chain()` 循环内(L478+)

**修复**(见 `15-root-case-fix-patch.md`):读完 Hero 后,重读 flag + IndexBuffer[i] 比对,变了则跳过这一帧。

## 4. 唯一坐标链(不再有 fallback)

```
g_gc_base (libGameCore base, 每 30 帧校验)
  → + 0x51EA4D0  (GOT,  GameRoot**
  → deref            GameRoot*
  → + 0x388       CActorManager*
  → + 0x2EB0      flag
  → flag ? +0x2EAC : +0x2E8C → count
  → + 0x2E90      IndexBuffer*
  → + 0x2E70      pool_base
  循环 i ∈ [0, count):
    slot = flag ? (IndexBuffer[i] + i) : i
    ★ seqlock: 读完整个链路后重读 flag + IndexBuffer[i] 比对一致性
    hero = *(pool_base + slot*32 + 8)
    hero + 0x28: config_id
    hero + 0x34: camp
    hero + 0xA8 → Node* (0xA8 = 168)
    node + 0x10 → Link*
    link + 0x00 → Transform*
    transform + 0x60 → VInt3*
    VInt3 + 0/+4/+8: real_x_mm / real_y_mm / real_z_mm (毫米)
    ★ seqlock: 重读 node+link 比对一致性, 变了则丢弃
    / 10 = 厘米
```

## 5. 持久化

- **模块文件位置**(本仓库):`src/modules/hr_*.c` + `hr_internal.h` + `hero_reader.c`
- **修复说明文档**:`docs/analysis/15-root-case-fix-patch.md`(根因 + 修复方案)
- **修复说明补充**:`docs/analysis/16-module-architecture.md`(本文件)
- **ID A 验证报告**:`docs/analysis/13-gameroot-chain-verification.md`(设备实测)
- **全部差异验证**:`docs/analysis/14-verify-report-device-discrepancies.md`(6 个设备实测差异静态验证)
