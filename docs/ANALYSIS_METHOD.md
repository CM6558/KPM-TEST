# 分析方法（Hero Reader）

> 目标：在一个**没有符号、没有调试器、不能改游戏**的 Unity/IL2CPP 手游里，
> 找到稳定的内核态读取链，并区分"真值"与"镜像"。
>
> 核心原则：**静态分析定偏移，运行时内核验证**；用户态只消费结果。

---

## 1. 两条轨道

| 轨道 | 工具 | 产出 |
|---|---|---|
| 静态 | Il2CppDumper / 自写 metadata 解析、libGameCore 反汇编 | 类名、字段偏移、结构布局、写链地址 |
| 运行时 | KPM 内核模块（页表物理读）+ 扫描/反查命令 | 真实地址、指针链、动态验证 |

静态给"候选"，运行时给"确认"。**任何偏移都必须经过运行时交叉验证才能进生产链。**

---

## 2. 工具链

### 2.1 内核侧（读/扫引擎）

模块 `hero-reader` 提供：

| 类别 | 命令 |
|---|---|
| 读 | `peek` `dump` `name` `fields` `classinfo` |
| 类/字段检索 | `findfield` `findstatic` `dumpall` |
| 值/指针搜索 | `scanvec` `scanptr` `scanval` `scanseq` `scanrec` `scanids` `pairscan` |
| C# 对象图 | `cscan` `ccscan`（3 层 BFS，支持非标签指针/double/多缩放） |
| 交叉验证 | `fullchain` `nscorr` |
| 写链 | `hwbp` `hwbpslot` `hwbpslot4` `hwbpxva` |
| 进程定位 | `setcomm` `findpid` |

> 扫描类命令需要 `diag on`；`dumpall`/`findobj`/`scanlive` 还需要 `unsafe on`。
> `touch` 已移除（不触发缺页，只读已驻留页）。

### 2.2 静态侧

| 工具 | 用途 |
|---|---|
| `libGameCore.so` | 原生链、写链反汇编（`a64dis.py` / objdump） |
| `libil2cpp.so` + `global-metadata.dat` | 类/字段/方法布局（`Il2CppDumper`、`mdparse.py`、`resolve.py`） |
| `static_chain.py` / `up.py` / `slotxref.py` | .bss 槽上溯、表槽交叉引用、调用点定位 |
| `meth.py` | 通过模块 `dump/peek` 批量读运行期内存 |

### 2.3 判定标准

一个偏移"可用"必须同时满足：

1. 在**多个英雄**上成立（`nscorr` 10 英雄交叉）；
2. 在**状态变化**时符合预期（雾、死亡、位移、相机）；
3. 有**第二条独立路径**印证（双链 / 双字段 / 写链）。

---

## 3. 定位流程（从零到一条链）

### 第 1 步：定位 image base

不依赖 `/proc/PID/maps`：

```
VMA 遍历 → 找以 ELF magic (\x7fELF) 开头的可执行段 → base = 段起点 - 段内 vaddr
```

### 第 2 步：找"根指针"（原生链入口）

1. 从已确认的数据反推：已知一个英雄的坐标值 → `scanvec` 找连续 `(x,0,z)` int32。
2. 对坐标地址 `scanptr` 逐级反查：`link → node → actor → roster → p → root`。
3. 每一级都用 `dump` 人工确认结构合理（相邻字段、指针范围）。
4. 最终把 root 固定为 `.bss + 偏移`（ELF 静态可算），做到**零扫描**。

> 反查技巧：il2cpp/Unity 的对象指针带 `0xb4` 标签，`scanptr` 同时匹配裸指针与带标签值。

### 第 3 步：C# 链（类表 → 静态字段 → 实例）

1. metadata 定位（校验 magic/version/size）。
2. 类表定位：
   - 优先固定 .bss 槽（`base + 0xE345028`）；
   - 失败则在 .bss 有界扫描，并用"连续多个合法 Il2CppClass + 类名可打印"做校验。
3. 按类名找 `ActorManager`（`cname_ok` + 名字比对）。
4. 实例定位：
   - 先 `findobj`（一次性堆扫描）拿实例；
   - 再**遍历所有类的静态字段**找"值等于该实例"的槽 → 得到纯静态链（`findstatic` 就是这一步的常驻版）。
5. 字段偏移直接来自 `fields`（Il2CppField.offset@+0x18），不猜。

### 第 4 步：结构内字段筛选

对候选结构的整块内存做两种扫描：

- 值扫描：`scanvec`（坐标）、`scanval`（hp/等级等）
- 序列扫描：`scanseq`/`scanrec`（按 stride 找对象数组）

再按"变化规律"筛选：

- 移动时变化的 → 坐标
- 受击时变化的 → hp
- 只在升级时变化 → 等级/经验

### 第 5 步：C# 对象图 BFS

`cscan` / `ccscan`：从已知对象出发，3 层内枚举所有 `0xb4` 标签指针，
尝试多种解释（float / int / double / ×100 / ×1000），输出"能与目标值对上"的路径。

用于：技能、装备、buff 这类"组件挂在组件上"的结构。

### 第 6 步：写链追踪（硬件断点）

目的：确认"这个字段是谁写的、写入时机"，解决"值为什么会冻结/跳变"。

做法：

1. 对目标地址挂 `hwbp`（单次采样，命中即清 `DBGWCR/DBGBCR` 并自动注销，避免风暴）。
2. 从 `dmesg` 读命中寄存器（PC/LR/Xn）→ 反汇编定位调用链。
3. 对分发表用静态 RELA addend 解槽位，确认分发目标。

我们用它完整解出了坐标写链（见 `POINTER_CHAINS.md` §4）。

### 第 7 步：交叉验证

- `fullchain`：整条链逐级校验（10 条记录）。
- `nscorr`：同一字段在 10 个英雄上的一致性。
- 双链对比：原生 vs C#（坐标、hp）。
- 状态实验：雾 / 相机 / 死亡 / 拖视角，观察哪条链变化。

---

## 4. "真值 vs 镜像"的判定

这是整个项目最关键的方法论。

### 4.1 雾中冻结实验

让目标进入草丛/战争迷雾：

- C# `ActorLinker.position` **停止更新**（冻结在最后可见位置）
- 原生 `link+0x2C` **继续更新**
- `MinimapComponentNew.m_actorPos` **继续更新**

结论：原生链和小地图是"真值"，C# position 是"可见时同步的镜像"。
实现上：`mx/mz`（原生）优先，C# `x/z` 仅兜底。

### 4.2 渲染标志不可用于可见性

| 字段 | 现象 | 结论 |
|---|---|---|
| `_inCamera @0x507` | 存在几何上明显在屏内却为 0 的点 | 受渲染/雾门控 |
| `_rendererInCamera @0x508` | 同上 | 同上 |
| `_checkRealInCamera @0x509` | 恒 0 | 不可用 |

=> 可见性/相机范围必须自己做**几何判定**，不能用游戏标志。

### 4.3 属性值必须"最终生效"

ad/def/res 的负结果：

- `nscorr` 10 英雄交叉验证：0/10 命中；
- 923/545 成对搜索出的 6 处都不与赵云（id 107 / hp 8250）相邻；
- 只出现在牛魔的 `*(actor+0x170)+0x3F4`（923.0 float）→ 是显示层计算值。

=> 规则：**只接受最终生效值；拿不到就不用**（宁可显示 0，也不显示配置值/中间值）。

---

## 5. 常见坑（都是真机踩出来的）

| 坑 | 现象 | 处理 |
|---|---|---|
| 单位混用 | 距离差 10 倍/100 倍 | 统一：原生 ×1000、bin ×100、界面 /100 |
| 忘记 untag | 指针校验通过但解引用失败 | 一律 `& 0x0000FFFFFFFFFFFF` |
| 类表索引漂移 | 换版本后实例拿不到 | `findobj` 重新定位 + 静态持有者回退 |
| metadata 页未驻留 | 类名/字段名偶发为空 | 已移除缺页触发，改用名字可打印过滤 |
| dmesg 刷屏 | 模块输出被充电日志冲掉 | 实时 `dmesg -w` 抓包或短窗口 grep |
| `pkill -f` 自杀 | 命令行包含匹配串 | 用 `[d]mesg` 写法或 kill PID |
| printk 无 `%f` | 浮点打印乱码 | 转定点/整数 |
| 模块同名残留 | `kpm load` 报 File exists，跑的是旧构建 | 先 root 停止（循环卸载）再 load |
| diag 门控 | 命令"没反应"（返回码仍是 0） | 先 `diag on` |
| comm 截断 | 进程名不是完整包名 | 内核 comm 只有 15 字符，模块内部取包名后 15 位 |
| `task_struct_offset` 部分为 -1 | 无法走 task 链表 | 只用 comm 偏移 + `find_task_by_vpid` 循环 |

---

## 6. 复现 playbook（换版本 / 换游戏）

```
1. 静态
   - dump metadata + il2cpp → 确认类名/字段
   - 反汇编目标 so → 找结构访问点

2. 运行时定位
   - findmeta / find_base（内核自定位）
   - classinfo <类名> / fields <类地址>   → 字段偏移
   - scanvec / scanptr                    → 原生链
   - findobj + findstatic                 → 静态持有者
   - cscan / ccscan                       → 组件子链

3. 验证
   - fullchain（整链）
   - nscorr（多英雄一致性）
   - 雾/相机/死亡 状态实验

4. 固化为常量
   - 原生链写死 root VA + 偏移（零扫描）
   - C# 链写死 table 索引 + static 偏移
   - 无值时的回退路径（备用指针 / 小地图 / C#）

5. 写文档
   - 更新 POINTER_CHAINS.md 偏移表
   - 更新 README 的"关键内存结构"
```

---

## 7. 我们现在拿到的完整度

| 链路 | 完整度 |
|---|---|
| 原生 actor → 坐标 / hp | ✅ 完整，含备用路径与校验 |
| C# 类表 → ActorManager → ActorLinker | ✅ 完整（零扫描静态链） |
| C# ActorLinker → 属性 / 技能 / 装备 / 小地图 | ✅ 完整 |
| 自身识别（hostPlayerID） | ✅ |
| 坐标写链 | ✅ 已追踪（未使用） |
| 相机中心 / 视锥 | ❌ 暂停（实例无静态引用） |
| ad/def/res | ❌ 放弃（运行时计算，拿不到最终值） |
| 等级 / 经验 / 护盾 | ⚠️ 有字段，未单独验证语义 |
