# Hero Reader —— 零 hook 内核读 + 悬浮窗

> 最后更新：2026-10-17
> 设备：OnePlus PJZ110 / Android 16 / kernel 6.6.150 / SukiSU + KPM
> 游戏：王者荣耀 `com.tencent.tmgp.sgame`
> 模块名：**`hero-reader`（固定，不要版本化）**

---

## 仓库布局（GitHub / 设备）

仓库：<https://github.com/CM6558/KPM-TEST>

| 仓库路径 | 设备路径（本机工作目录 `~/kpmwork`） | 说明 |
|---|---|---|
| `hero_reader.c` | `KPM-TEST-work/hero_reader.c` | 内核模块主源码 |
| `heromap.h` | `KPM-TEST-work/heromap.h` | 英雄 id → 名字 |
| `Makefile` / `hero_reader.lds` | `KPM-TEST-work/` | 构建 |
| `scripts/hero_start.sh` | `~/kpmwork/hero_start.sh` → `/data/local/tmp/` | 启动 |
| `scripts/hero_stop.sh` | `~/kpmwork/hero_stop.sh` → `/data/local/tmp/` | 停止 |
| `scripts/deploy.sh` | `~/kpmwork/deploy.sh` | 部署 |
| `bridge/hero_bridge.c` | `~/kpmwork/bridge/` | WS 桥接 |
| `overlay/` | `~/kpmwork/overlay/build/` | 悬浮窗 / App |
| `docs/` | — | 早期指针链分析（历史资料） |

> 下文路径以仓库根目录为准；设备上的对应关系见上表。

---

## 0. 现在能做什么

| 能力 | 来源 | 状态 |
|---|---|---|
| 英雄 id / 阵营 / objid | 原生 actor 链 | ✅ |
| 真实坐标（雾中不冻结） | 原生 `link+0x2C`（×1000） | ✅ |
| HP / HPmax | 原生属性组件 | ✅ |
| C# 坐标（可见时同步的镜像） | `ActorLinker.position@0x4C4` | ✅ 仅兜底 |
| 等级 / 金币 / 装备 / 技能 cd | C# | ✅ |
| 逻辑可见 / 在相机 / 死亡 / 草丛 / 冰冻 | C# 标志位 | ✅ |
| 悬浮窗 | 方向箭头 + 相机内敌人数 + 最近距离 | ✅ |
| App 全量表格 | 每个英雄一行 + 技能行 | ✅ |
| 游戏进程定位 | 内核遍历 task（`setcomm` / `findpid`） | ✅ 无用户态 pidof |

**不做的事（硬约束）**

1. 零 hook、非侵入、不阻塞渲染（纯页表物理读）。
2. 不创建任何可枚举内核对象（无字符设备 / netlink / procfs / sysfs）。
3. **所有游戏内存读取都在内核模块里完成**；用户态只读定长 bin / WebSocket。
4. 悬浮窗不显示原始 JSON / 状态文本（原文只给 App 界面）。
5. **不使用 `access_remote_vm` / `get_user_pages` / `ptrace` / `/proc/<pid>/mem`**：
   读内存只有一条路径 `rm()` → `my_pgtable_phys()`（页表物理读）。
6. 游戏 pid 也由内核定位（`setcomm`），用户态脚本不再 `pidof` 游戏进程。

---

## 1. 架构与数据流

```
               ksud kpm control hero-reader '<cmd>'
                              │
                              ▼
        ┌───────────────────────────────────────┐
        │  内核模块 hero_reader.kpm             │
        │  · 页表物理读（my_pgtable_phys）      │
        │  · 原生链 + C# 链                      │
        │  · seqlock 定长 bin 写入              │
        └───────────────┬───────────────────────┘
                        │ /data/local/tmp/heroes.bin（64B 头 + 16×324B）
                        ▼
        ┌───────────────────────────────────────┐
        │  hero_bridge（用户态，只读 bin）      │
        │  JSON → WebSocket 127.0.0.1:8787/ws   │
        └───────────────┬───────────────────────┘
                        │
            ┌───────────┴────────────┐
            ▼                        ▼
   OverlayService（悬浮窗）     MainActivity（App 表格）
   箭头 / 人数 / 距离            完整 JSON 解析展示
```

守护进程：`hero_start.sh --daemon` 每 200ms 给模块发一次 `heroes`（写 bin），保持模块加载 / 桥接存活；
开局时发 `setcomm com.tencent.tmgp.sgame`，由**模块在内核遍历 task 表**定位游戏 pid（pid 失效/游戏重启会自动重定）。

---

## 2. 快速开始

### 2.1 构建模块

```sh
# 仓库根目录（设备上则是 ~/kpmwork/KPM-TEST-work）
make KP_DIR=/path/to/KP-SUKISU                     # Termux clang
make NDK_PATH=/path/to/android-ndk KP_DIR=...      # 或用 NDK
sh scripts/check_kpm.sh hero_reader.kpm            # 产物自检（CI 同款）
# 产物: hero_reader.kpm
```

### 2.2 部署 / 启停

```sh
# 仓库根 / 本机工作目录均可（deploy.sh 会自动找 KPM-TEST-work 或当前目录）
sh scripts/deploy.sh            # 拷贝 + 先停旧实例 + 启动（推荐）
sh scripts/deploy.sh status     # 只看状态

# 设备上（root）
su -c "sh /data/local/tmp/hero_start.sh"          # 启动（默认重启）
su -c "sh /data/local/tmp/hero_start.sh keep"     # 已在跑就不动
su -c "sh /data/local/tmp/hero_start.sh 300"      # 指定周期 300ms
su -c "sh /data/local/tmp/hero_stop.sh"           # 停止全部
su -c "sh /data/local/tmp/hero_stop.sh clean"     # 停止并删 heroes.bin
```

> **必须 root 执行停止**。非 root 时脚本杀不掉守护、`rm` 也删不了 pid 文件，会留下旧实例。

> **pid 来源**：脚本不再调用 `pidof` 找游戏。模块用 `setcomm com.tencent.tmgp.sgame` 在内核定位。
> 内核 `task->comm` 只有 16 字节（最大 15 字符，实际值为 `cent.tmgp.sgame`），
> 所以模块内部只比对**包名的后 15 位**；**调用时仍然传完整包名**。

### 2.3 App / 悬浮窗

```sh
cd overlay
ANDROID_JAR=/path/to/android.jar sh build.sh   # 依赖 javac/d8/aapt2/apksigner
adb install -r hero.apk                        # 或 su -c "pm install -r /data/local/tmp/hero.apk"
```
打开 App → 点「启动悬浮窗」（`isForeground=true` 即正常）。

### 2.4 改完模块后必做

```sh
su -c "/data/adb/ksud kpm control hero-reader 'diag on'"
```

`diag` 是**门控**：重载后默认关闭，`classinfo / findfield / findstatic / dumpall / 扫描类命令`全部会被静默拒绝（返回值不会进 dmesg，看起来像"命令没生效"）。

---

## 3. 数据格式

### 3.1 heroes.bin（seqlock 定长）

```
struct hb_hdr {            // 64 B
    u32 magic = 0x48523031 ("HR01"); u32 version = 1;
    u32 seq; u32 rec_size = 324; u32 max_rec = 16; u32 n;
    u64 ts_ms; u32 flags; u32 rsv[7];
    // rsv[0] = 内核定位到的游戏 pid   (offset 36)
    // rsv[1] = mm 是否已锁定 (0/1)     (offset 40)
};
struct hb_rec { ... }      // 324 B × 16（n 为有效条数）
```

`seq` 每写一次 +1；用户态读 `seq → 数据 → seq` 一致才算有效（桥接/App 已按此处理）。
> bin 只在**局内**刷新；局外文件保持上一次内容（所以 `status` 会退回用 `findpid` 查 pid）。

### 3.2 记录字段（偏移，小端，packed）

| off | 字段 | 说明 |
|---|---|---|
| 0x00 | heroid, camp, objid | u32×3 |
| 0x0C | hp, hpmax, exp, expmax, lvl, gold, incgold | i32×7 |
| 0x28 | charge, chargemax, shield, shieldmax | i32×4 |
| 0x38 | x, y, z, fx, fz, move, groundy | i32×7（x/z = C# 坐标，×100） |
| 0x54 | mx, mz | i32×2（原生真值，×100） |
| 0x5C | ad, def, res | i32×3（当前恒 0，见 §7） |
| 0x68 | atktarget | u32 |
| 0x6C | dead, dying, grass, freeze, battle, nomove, inroom, fantasy, autoai, lvis, cam, me | u8×12 |
| 0x78 | eqn | u32（装备条数 ≤ 8） |
| 0x7C | eq[8] = {u16 id, u16 cnt} | 32 B |
| 0x9C | sk[6] = {u8 lvl,ready,lvlup,bean; i32 cd,cdmax,power,powermax,tgt,hit} | 6×28 B |

### 3.3 单位（很重要）

| 来源 | 单位 | 例子 |
|---|---|---|
| libGameCore `link+0x2C` | **×1000**（毫米） | `37453` = 37.453 m |
| C# `ActorLinker.position`（float） | 米 | 写 bin 时 `rf32x100` → **×100** |
| bin 里的 x/z、mx/mz | **×100**（厘米） | `3745` |
| 悬浮窗/距离 | `/100` = 米 | `11.5m` |

模块写 bin 时 `mx = native.x / 10`。**不要**在别处再乘/除 10。

### 3.4 WebSocket JSON（桥接输出）

```json
{"seq":9306,"n":10,"heroes":[
  {"heroid":107,"camp":1,"objid":0,"me":1,
   "hp":8250,"hpmax":8250,"lvl":15,"gold":0,
   "x":3091,"y":0,"z":475,"move":0,"fyaw":1234,"mx":3091,"mz":475,
   "ad":0,"def":0,"res":0,
   "dead":0,"dying":0,"grass":0,"freeze":0,"battle":0,
   "nomove":0,"inroom":0,"fantasy":0,"autoai":0,"lvis":1,"cam":1,
   "atktarget":0,"eqn":6,"eq":[[id,cnt],...],
   "skills":[{"s":0,"lvl":5,"cd":0,"cdmax":8000,"ready":1,"bean":0,
              "power":0,"powermax":0,"tgt":0,"hit":0,"lvlup":0}, ...]}
]}
```

桥接已经把 `x/z` 换成 `mx/mz`（原生优先，无值回退 C#）。
`fyaw` = 朝向（毫弧度，由 `fx/fz` 四元数算）。

---

## 4. 模块命令手册

统一入口：`su -c "/data/adb/ksud kpm control hero-reader '<cmd>'"`，输出在 dmesg（`[hero-reader]` 前缀）。

### 4.1 状态 / 开关

| 命令 | 说明 |
|---|---|
| `status` / `info` | pid / mm / pgd / base / meta / dumped / comm |
| `diag on\|off` | 诊断命令总开关（**重载后默认 off**） |
| `verbose on\|off` | 详细日志 |
| `unsafe on\|off` | 放开 `dumpall / findobj / scanlive` 等重扫 |
| `set <pid> [base_hex]` | 手动指定目标进程（一般不再需要） |
| `setcomm <完整包名>` | **内核态按包名定位 pid**（幂等；内部比对 comm 后 15 位） |
| `findpid <完整包名>` | 一次性打印 pid（诊断，需 `diag on`） |
| `reset` | 清空锁定状态 |

### 4.2 数据读取

| 命令 | 说明 |
|---|---|
| `native` | 打印原生链 10 条（hero/camp/xyz） |
| `heroes` | 一次性打印 C# 英雄表（JSON 到 dmesg） |
| `herobin <path> [ms]` | 周期写定长 bin（守护用的就是它） |
| `herobin stop` | 停止周期写 |
| `fullchain` | 原生链逐级校验（10 条） |
| `nscorr` | 原生字段与 C# 交叉验证（默认 10 英雄） |
| `classinfo <类名子串>` | 类地址 + static_fields + 字段数 |
| `fields <类地址>` | 导出该类的字段表（偏移/类型/名） |
| `findfield <字段名子串>` | 按字段名搜类 |
| `findstatic <类地址>` | **遍历类表静态字段**，找谁持有该类实例（无堆扫描） |
| `natgate on\|off` | 原生坐标是否用 C# 交叉校验（默认 on；调试时 off = 完全信任原生） |
| `natchain` | 用 10 个英雄的 C# 坐标反推稳定的原生坐标链（诊断，需在局内） |
| `natfind <hero> <x_cm> <z_cm>` | 单英雄坐标链搜索（d0/d1/d2 路径） |
| `nat3` | 同时打印三条候选链的值（对比雾中更新） |
| `binflush` | 立即用当前 `g_bin_rec` 写一次 bin（自检，不需要对局） |
| `name <对象地址>` | 打印对象 klass 名 |
| `peek <addr> [n]` | 读内存（原始） |
| `dump <addr> [n]` | 打印 n 个 32 位字 |
| `walk` / `chain` | 指针链探索 |

### 4.3 扫描 / 反推（诊断，需 `unsafe on`）

| 命令 | 说明 |
|---|---|
| `scanvec x y z [lo hi]` | 找连续 3 个 int32 == (x,y,z) |
| `scanptr <hex> [lo hi]` | 找 8 字节指针值（裸/0xb4 标签） |
| `scanval <u32>` | 找 4 字节值 |
| `scanseq <stride>` / `scanrec` / `scanids` | 结构体序列扫描 |
| `scanlive` | 存活对象扫描 |
| `tabdump <base> <S> <n>` | 导表 |
| `wide` | 放宽扫描地址限制（触页命令 `touch` 已移除） |
| `dumpall <path>` | 导出完整类表（含字段）到文件 |
| `findobj <类名> [off...]` | 按类名扫实例 |

### 4.4 硬件断点（写链追踪）

| 命令 | 说明 |
|---|---|
| `hwbp <tid> <addr> [len] [type]` | 挂断点（单次采样：命中即清 `DBGWCR/DBGBCR` 并自动注销） |
| `hwbpslot <tid>` / `hwbpslot4 <tid>` | 按槽位挂 |
| `hwbpxva <tid> <xva>` | 按 XVA 挂 |
| `hwbp off` | 全部注销 + 复位 `g_bp_fired` |

### 4.5 相机（已放弃，仅留档）

`cams`（观察 `_inCamera/_rendererInCamera`）、`camcal`（进出点标定）。见 §7。

### 4.6 常用组合

```sh
# 看原生 10 条
su -c "dmesg -c >/dev/null; /data/adb/ksud kpm control hero-reader 'native'; sleep 2; dmesg | grep 'nat\[' | sed 's/.*\] //'"

# 查类字段
su -c "/data/adb/ksud kpm control hero-reader 'classinfo ActorLinker'"
su -c "/data/adb/ksud kpm control hero-reader 'fields 0x<类地址>'"

# 找静态持有者
su -c "/data/adb/ksud kpm control hero-reader 'diag on'"
su -c "/data/adb/ksud kpm control hero-reader 'findstatic 0x76711e1780'"
```

---

## 5. 关键内存结构

> 完整偏移表与逐级推导见 [`docs/POINTER_CHAINS.md`](docs/POINTER_CHAINS.md)；
> 定位/验证方法论见 [`docs/ANALYSIS_METHOD.md`](docs/ANALYSIS_METHOD.md)。本节是速查版。

### 5.1 原生链（libGameCore，零扫描）

```
libGameCore image base（ELF magic 定位）
  base + 0x53F1810            (= .bss 0x526F000 + 0x182810)  → root
  root            → p
  p + 0x250       → roster
  roster[i*0x18]  → actor            (i < 16)
  actor + 0x28    = hero cfg id
  actor + 0x34    = camp (1/2)
  actor + 0xA8    → node
  node  + 0x10    → link
  link  + 0x2C    = (x, 0, z)  int32 ×1000     ← 真值坐标
  强校验: link[0] = transform, transform + 0x60 必须是同一组 (x,y,z)
          （两条路径一致才采用；特殊模式会 MISMATCH，直接拒绝）
  备路 1: actor + 0x248 → +0x128 → +0x2C
  备路 2: actor - 0x758 → ptr → (x,0,z)
  actor + 0x1D0   → attr component
  attr + 0xC0     = hp
  attr + 0xC8     = hpmax
```

校验规则：`y == 0`、`|x|,|z| < 300000`、hero ∈ (0,4000]、camp ∈ {1,2}。

### 5.2 C# 链（il2cpp）

```
类表 s_TypeInfoTable（.bss 内有界结构区定位，find_typeinfo_table）
  table[39479] + 0xB8 (static_fields) + 0x80  → ActorManager 实例
  ActorManager + 0x18  → HeroActors 容器 (TVL)
  TVL + 0x08 = items 数组, +0x10 = count
  items[i] → ActorLinker
  ActorManager 同 holder: static_fields + 0xE0 → GamePlayerCenter
  GamePlayerCenter + 0x40 = hostPlayerID（自己）
```

> `table[39479]` / `+0x80` 是当前版本的常量；换版本需重新定位（`findobj ActorManager` + 静态持有者扫描已内置自动回退）。

### 5.3 ActorLinker 常用偏移

| 偏移 | 字段 |
|---|---|
| 0x028 | SkillControl → SkillLinkerComponent |
| 0x030 | EquipComponent → EquipLinkerComponent |
| 0x038 | resHeroCfgInfo（低 32 = 英雄 id） |
| 0x3B8 | ValueComponent |
| 0x3C0 | ActorControl |
| 0x3F0 | miniMap → MinimapComponentNew（`+?` 位置） |
| 0x410 | BuffLinkerComponent |
| 0x480 | groundY |
| 0x4AC | objid |
| 0x4B0 | name |
| 0x4B8 | forward（float xyz） |
| 0x4C4 | position（float Vector3，米） |
| 0x505 | `_logicVisible` |
| 0x506 | `_meshVisible` |
| 0x507 | `_inCamera`（受渲染/雾门控） |
| 0x580 | staticData |
| 0x764 | moveSpeed |

### 5.4 合并规则

- 原生：hero / camp / 坐标 / hp / hpmax
- C#：等级 / 金币 / 装备 / 技能 / 可见性标志
- 按 `(hero, camp)` 合并；C# 坐标只在原生无值（slot5 异常）时兜底。
- `620/621` 这类非英雄单位**保留**，不按 hero id 过滤。

### 5.5 写链（已完整追踪，未使用，留档）

```
0x3F49CA0  分发
0x3F7F668  浮点变换/缩放（全局 scale = *(0x4FF4000+0x610)）
0x3F7F08C
0x3F7CCA0  比较 + 写（脏检查）
0x3F7D040 → 0x3F7D074  setter: str x10,[x8]; str w9,[x8,#8]
另一支 0x3F7C7CC → 0x3F7C3B0
分发表 0x51B7000 槽位 +0x460/+0x4B0/+0x4C0/+0x4E0/+0x540/+0x5D0（RELA addend 已解）
```

### 5.6 内核态进程定位（替代用户态 pidof）

```
setcomm <完整包名>  →  g_target_comm 保存
reader 线程（每 5 轮 ≈1s，仅当 pid 未锁定）:
    RCU 下 for pid = 1..32768:
        tsk = find_task_by_vpid(pid)
        if tsk && comm(tsk) == 包名后 15 位  →  pid
```

- 调用方传**完整包名** `com.tencent.tmgp.sgame`；内核 `comm` 只有 15 字符
  （实际 `cent.tmgp.sgame`），模块内部自动取尾部比对。
- `comm_offset` 由 KP 运行时解析（本机实测 `0x830`）。
- **注意**：本内核导出的 `task_struct_offset` 里只有 `comm_offset` 有效，
  `pid/tgid/tasks/mm` 全是 `-1`，所以不能用 task 链表遍历，只能用 pid 循环。
- 每次定位约扫 7000+ 个存活 pid，耗时几毫秒；pid 失效（游戏重启 / pid 复用）会自动重定。
- 全程 RCU + 内核态，不读 `/proc`，不碰游戏内存。

---

## 6. 悬浮窗判定模型

### 6.1 屏幕基（已确认）

| 阵营 | 基地 | 屏幕上方 = 世界方向 |
|---|---|---|
| 1（蓝） | 左下 | **45°**（+x+z 对角） |
| 2（红） | 右上 | **225°**（旋转 180°） |

世界向量先投影到屏幕基，再交给箭头/矩形：

```
up    = (cos45, sin45)          # 阵营1；阵营2 = +180°
right = (cos(-45), sin(-45))
u = dx*up.x + dz*up.z           # 屏幕上方（前）
v = dx*right.x + dz*right.z     # 屏幕右方
屏幕角度 = atan2(u, v)           # 0°=右，90°=上（ArrowView 约定）
```

- 长按悬浮窗 0.7s（不拖动）→ 基准 +45° 循环校准，Toast 显示当前值，持久化。
- 阵营 2 自动使用“基准 + 180°”。

### 6.2 相机范围矩形

```
|v| <= 1150 && -1400 <= u <= 1900     # 单位 ×100（cm），阵营1屏幕基标定
```

- 常量来自 68 个相机进出点标定（`camcal`）。
- 与视野无关（几何判定），雾里也算；阵营 2 用同一矩形（基向量旋转 180°）。
- 距离 = 最近敌人的欧氏距离 `/100` 米。
- 箭头**优先指向可见（lvis=1）的最近敌人**，没有可见目标才退回最近敌人
  （避免雾里错误坐标把箭头带偏）。
- **已知限制**：拖动相机后判定中心会偏（相机对象定位失败的遗留问题，见 §7）。

---

## 7. 已确认结论 / 放弃项（避免重复劳动）

### 7.1 战斗属性 ad/def/res —— 放弃

- 原生 10 英雄交叉验证 `nscorr`：**0/10**。
- 923/545 成对搜索出的 6 处均不与赵云（id 107 / hp 8250）相邻。
- 只出现在牛魔（168）的 `*(actor+0x170)+0x3F4`（923.0 float）。
- 结论：界面值是**运行时计算**，不在 actor 图上。只接受最终生效值 → 拿不到就不用。

### 7.2 相机标志位 —— 不可用

| 字段 | 结论 |
|---|---|
| `_inCamera @0x507` | 受渲染/雾门控（存在 u=17.8,v=0.3 却为 0 的点） |
| `_rendererInCamera @0x508` | 同上 |
| `_checkRealInCamera @0x509` | 恒 0 |

### 7.3 相机对象定位 —— 已放弃（用户决定）

已确认的事实（下次若重启此线可直接用）：

```
Moba_Camera 类 0x765f591800
  +0xB8 static_fields (0x77a0987920)
    +0x0  -> 0x755a7b87c0    klass = UnityEngine.Camera ✅（纯指针，无需扫描）
```

- `UnityEngine.Camera` 在本 build **只有 7 个 static 字段**，实例数据全在原生层。
- `UnityEngine.Object.m_CachedPtr @0x8` → 原生 Camera 指针 ✅（已读出）。
- 原生 Camera 对象（0x76f7babe20）里未找到正交矩阵/位置字段；看到的 3×4 块不自洽。
- `CameraSystem`（0x76711e1780，字段：`MobaCamera@0x18`, `m_mainCamera@0x48`, **`m_mainCameraTrans@0x50`**, `m_mainCamVPCache@0x58`, **`CachedFrustum@0x28`**, `bFreeCamera@0x20`）**没有任何静态引用**（`findstatic` 实测 0 命中）。
- `Moba_Camera` 实例也没有静态引用；只有静态字段指向 UnityEngine.Camera。
- 结论：要拿真实相机需要 **堆扫描找 CameraSystem 实例**（用户明确不要），或走 Unity GameObject→components 链 / 原生 Transform（未完成）。
- 这条路真正的价值是 `CameraSystem.CachedFrustum`（视锥平面数组）→ 可做**精确**可见判定（含拖动/缩放/旋转），以后若重启优先它。

### 7.4 其他

- 等级/经验：全为同值，无法区分字段是否正确（未验证）。
- 护盾：字段存在但未验证。
- 技能/装备是否在原生侧存在：未验证（当前全走 C#）。

---

## 8. 调试与踩坑

### 8.1 dmesg 被充电日志刷屏

本机 `OPLUS_CHG` 每秒十几行，模块输出会被冲掉。两个办法：

```sh
# A. 实时捕获（推荐）
su -c 'dmesg -c >/dev/null; dmesg -w > /data/local/tmp/cap.txt & DP=$!; \
       /data/adb/ksud kpm control hero-reader "native" >/dev/null; sleep 3; kill $DP'
su -c "grep 'hero-reader' /data/local/tmp/cap.txt"

# B. 精确 grep（时间窗要短）
su -c "dmesg -c >/dev/null; <cmd>; sleep 2; dmesg | grep -E 'findstatic|static:'"
```

> **不要**用 `pkill -f 'dmesg -w'`：命令行自己包含该字符串，会把自己杀掉。用 `kill $PID` 或 `pkill -f '[d]mesg -w'`。

### 8.2 命令"没反应"= diag 没开

`diag` 关闭时，诊断命令直接返回一句 `诊断命令已禁用`，**这句只通过 control 返回值给调用方，不进 dmesg**。
所以现象是：`ksud kpm control` 返回 `0`，但 dmesg 什么都没有。
→ 先 `diag on`。

### 8.3 部署后跑的还是旧构建

- 同名模块已存在时 `kpm load` 会报 `File exists`，静默失败。
- 本机 `kpm unload` 有时第一次报 `No such file or directory`，需循环重试。
- **现在 `deploy.sh` 已改为先 root 执行 `hero_stop.sh`（循环卸载到名字消失）再启动**；如果还怀疑，手动确认：

```sh
su -c "/data/adb/ksud kpm list"          # 必须为空
su -c "/data/adb/ksud kpm num"           # 0
```

- `deploy.sh` 必须以 root 能力执行（脚本内部已用 `su -c`）。

### 8.4 内核日志格式

- `printk` **不支持 `%f`**，所有浮点要转定点/整数。
- 日志前缀统一 `[hero-reader]`。

### 8.5 进程名 / pid 相关

| 现象 | 原因 |
|---|---|
| `findpid` 找不到 | 直接传完整包名即可（`com.tencent.tmgp.sgame`）；模块内部按 comm 后 15 位比对 |
| `task_struct_offset.tasks_offset == -1` | 本内核只解析了 `comm_offset`，其余字段全是 -1，不能用链表遍历 |
| `setcomm` 后没有立刻生效 | 解析有节流（每 ~1s 一次），且需游戏确实在运行 |
| `status` 里 pid 是 `?` | bin 只在局内刷新；局外走 `findpid` 兜底，若游戏没开则为空 |

### 8.6 不再有缺页触发（access_remote_vm 已移除）

- `touch` 命令已删除，`prefault_range` 已删除。
- 后果：metadata 里**未驻留**的 file-backed 页会读成 0，
  表现为个别类名/字段名为空（`name_printable` / `cname_ok` 会过滤掉）。
- 实测对局内绝大部分 metadata 页已驻留，`classinfo/findfield/findstatic/dumpall` 正常。
- 如果以后发现名字缺失严重，正确做法不是恢复 `access_remote_vm`，
  而是：① 让游戏自己先访问到那些页；② 或从磁盘 `global-metadata.dat` 解析名字。

### 8.7 其他

| 现象 | 原因 |
|---|---|
| `heroes: 未在对局 (ActorManager 失效, cnt=0)` | 不在局内 / 刚进局未初始化 / 进程重启 |
| 模块卸载后仍有名字 | KP unload 幽灵记录；循环重试即可，不影响新实例 |
| `pkill -f hero_start.sh` 杀到自己 | 用 `[h]ero_start.sh --daemon` 写法 |
| 扫描命令没结果 | 需 `unsafe on`；或区域被 `wide` 限制跳过 |
| 内存池不够 | KP `preset.h`：RW 2MB / ROX 4MB；当前占用约 0.5MB，**不需要改** |

---

## 9. 文件清单（重要路径）

### 9.1 仓库 / Termux 工作目录

| 路径 | 说明 |
|---|---|
| `hero_reader.c` | 模块主源码（唯一需要改的文件） |
| `heromap.h` | 英雄 id → 名字（107=赵云、168=牛魔） |
| `hero_reader.kpm` | 构建产物（.gitignore 忽略） |
| `scripts/hero_start.sh` / `hero_stop.sh` / `deploy.sh` | 启停 / 部署 |
| `bridge/hero_bridge.c` | WS 桥接源码 |
| `overlay/java/com/hero/overlay/*.java` | OverlayService / ArrowView / MainActivity / HeroState |
| `overlay/build.sh` | 本地打包 APK |
| `overlay/AndroidManifest.xml` | App 清单（`com.hero.overlay`） |
| `docs/POINTER_CHAINS.md` | 完整指针链（原生 / C# / 组件 / 相机 / 写链） |
| `docs/ANALYSIS_METHOD.md` | 分析方法与验证流程 |
| `docs/`（其余） | 早期指针链分析（历史资料，以 `POINTER_CHAINS.md` 为准） |
| 本机（未入库）：`libGameCore.so` | 原生核心副本（写链/读链反汇编依据） |
| 本机（未入库）：`libil2cpp.so` / `global-metadata.verified.dat` | il2cpp 静态分析 |
| 本机（未入库）：`static_chain.py` / `up.py` / `slotxref.py` / `meth.py` | 静态推导 / 读内存小工具 |

### 9.2 设备侧 `/data/local/tmp`

| 文件 | 说明 |
|---|---|
| `hero_reader.kpm` | 当前模块 |
| `hero_bridge` | 桥接 |
| `heroes.bin` | 定长数据（64B + 16×324B） |
| `hero_start.sh` / `hero_stop.sh` | 启停 |
| `hero_mod.name` | 模块名（`hero-reader`） |
| `hero.log` | 守护日志 |
| `hero_daemon.pid` / `hero_bridge.pid` | pid |
| `all.txt` | 完整类表 dump（~7MB，`dumpall` 产物，查字段/类地址用） |
| `hero.apk` | App 安装包 |

---

## 10. 下次开工 checklist（5 分钟）

1. 确认设备 root / SukiSU 正常：`su -c "/data/adb/ksud kpm num"`
2. 起服务：`sh ~/kpmwork/deploy.sh`
3. `diag on`
4. 进一局，确认数据：
   ```sh
   su -c "dmesg -c >/dev/null; /data/adb/ksud kpm control hero-reader 'native'; sleep 2; dmesg | grep 'nat\['"
   ```
5. 看 App / 悬浮窗是否出数
6. 要改代码：改 `KPM-TEST-work/hero_reader.c` → `make` → `deploy.sh`

---

## 11. 待办 / 可继续方向

- [ ] 验证等级/经验字段（当前全同值，无法区分）
- [ ] 验证护盾（`ActorLinker` 上有字段，未确认语义）
- [ ] 确认技能/装备是否存在于原生侧（目前全 C#）
- [ ] （可选）把 `findstatic` 保留为常驻诊断命令（当前已内置，无副作用）
- [ ] （若重启相机线）优先做 `CameraSystem` 实例定位 → 读 `CachedFrustum@0x28` 做精确视锥判定
- [ ] （可选）相机拖拽检测的启发式方案（对比 `_inCamera` 与几何预测的偏差）

---

## 12. 变更记录

| 日期 | 变更 |
|---|---|
| 2026-10-17 下午 | 方向改为屏幕基（阵营1=45°/阵营2=225°），长按悬浮窗可 45° 步进校准 |
| 2026-10-17 下午 | 坐标读取加“双路径一致”强校验；新增备链 `0x248/0x128`；特殊模式自动拒绝 |
| 2026-10-17 下午 | 性能：局外不再全堆扫描（曾 650ms/次）、页表翻译缓存、bin 句柄常驻、守护/桥接降频 |
| 2026-10-17 下午 | 新增诊断命令：`natgate` `natchain` `natfind` `nat3` `binflush` |
| 2026-10-17 | 新增 `docs/POINTER_CHAINS.md`（完整指针链）与 `docs/ANALYSIS_METHOD.md`（分析方法） |
| 2026-10-17 | **移除 `access_remote_vm` 全部使用**：删除 `prefault_range` / `touch` 命令 / KSYM 解析；内存只剩页表物理读一条路 |
| 2026-10-17 | 新增 `setcomm` / `findpid`（传完整包名）：游戏 pid 改为**内核遍历 task 定位**，移除脚本里的 `pidof` |
| 2026-10-17 | bin 头部 `rsv[0]=pid`、`rsv[1]=mm 已锁定`，供 `status` 显示 |
| 2026-10-17 | `deploy.sh` 改为先 root 停止（循环卸载）再启动，修复"新构建加载不上" |
| 2026-10-17 | 新增模块命令 `findstatic <类地址>`（类表静态字段遍历，无堆扫描） |
| 2026-10-17 | 确认 `Moba_Camera._currentMobaCamera → UnityEngine.Camera`（纯指针） |
| 2026-10-17 | 放弃相机对象定位（用户决定）；清理 `/data/local/tmp` 临时抓包文件 |
| 2026-10-17 | 文档整理（本文件） |
