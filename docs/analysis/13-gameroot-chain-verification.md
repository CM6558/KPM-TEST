# GameRoot 指针链二次验证报告 (真机实测与反编译差异对比)

## 1. 验证背景
在根据 `docs/analysis/12-stable-pointer-chain.md §19.5b` 实现 GameRoot 指针链读取英雄坐标时，真机对局测试反馈：
> **“只有开局前几分钟是对的，后面就不准了”**

为查明原因，我们通过反编译 `libGameCore.so`（AArch64）对应函数，并在真实对局进程（PID 27134）中直接 dump 运行期内存，进行了完整的链路逐级二次验证。

---

## 2. 逐级验证结果对照表

| 链路级别 | 文档结论 (§19.5b) | 实际逆向与真机实测数据 | 状态评估 |
| :--- | :--- | :--- | :--- |
| **Level 0: 全局入口** | `g_game_root @ 0x52717b0` (.data 静态槽) | GOT 重定位槽 `base + 0x51EA4D0` $\rightarrow$ 指向 `0x52717b0`，其值为 `GameRoot**` | **一致** (需注意双级解引用) |
| **Level 1: GameRoot** | `*g_game_root = GameRoot*` | 真机解引用为合法对象指针 (如 `0x764ba00000`) | **一致** |
| **Level 2: CActorManager** | `*(GameRoot + 904) = CActorManager*` | `*(GameRoot + 0x388)` 确为 `CActorManager*` (硬证据: `sub_3CFFEF8` 调用 `CActorManager::UpdateLogic`) | **一致** |
| **Level 3: HeroEntry 数组** | `*(CActorManager + 11888) = HeroEntry*`，步长 32 字节 | `CActorManager + 0x2E70` 确为数组/池起始指针，步长 32 字节，`+8` 处为 `Hero*` | **一致** |
| **Level 3: 计数与索引** | 假定为平铺数组，直接按 `i * 32` 索引 | **重大差异**：<br>1. `CActorManager + 0x2EB0` 是 `flag` 状态位，真实总数由 `flag == 0 ? 0x2E8C : 0x2EAC` 决定；<br>2. `+0x2E90` 存在间接索引表 `IndexBuffer`，槽位 `slot = IndexBuffer[i] + i` | **不一致** (实为稀疏池间接索引) |
| **Level 4: 英雄属性偏移** | `config_id @ +4`，`runtime_id @ +8` | **重大差异**：ARM64 头部有 8 字节虚表指针 (`vtable`)，`runtime_id` 在 `+0x08`，`config_id` 在 `+0x28`，阵营 `camp` 在 `+0x34` | **不一致** (64 位对齐偏移错位) |
| **Level 4: 实时坐标源** | `Hero + 32 (real_x)` / `+40 (real_y)` / `+44 (real_z)` | **致命差异**：`+32/+40/+44` 是 `Actor::SetSpawnPosition` 出生点缓存，开局后不更新！真实高频坐标位于 `Hero + 0xA8 (Transform 节点)` | **不一致 (导致几分钟后卡死的原因)** |

---

## 3. “只有前几分钟是对的”根本技术原因分析

### 3.1 `sub_36A283C` 写入语义的误解
文档中认为 `sub_36A283C` 写入 `hero+32/+40/+44` 代表权威服务器坐标：
```asm
0x36a2844: str  x2, [x0, #0x20]  ; x2 = real_x (QWORD)
0x36a2848: str  w3, [x0, #0x28]  ; w3 = real_y (DWORD)
0x36a284c: strh w8, [x0, #0x2c]  ; w8 = real_z (WORD)
```
**实测反推**：
该函数实际是 **`Actor::SetSpawnPosition`（出生点同步）**。
- 开局前几分钟，英雄位于泉水或走上一塔，实际位置与出生点相近，读数碰巧吻合；
- 一旦进入正常对抗与团战位移，该函数不再被调用，`hero+32/+40/+44` 停留在初始点位，导致后续测距完全失效。

### 3.2 权威物理坐标的真实流向 (Transform 节点)
王者荣耀采用帧同步客户端模拟，逻辑层每一帧高频重算的物理坐标位于挂载的组件节点：
$$\text{Hero} \xrightarrow{+0xA8} \text{Node} \xrightarrow{+0x10} \text{Link} \xrightarrow{+0x00} \text{Transform} \xrightarrow{+0x60} \text{VInt3 定点三维坐标}$$
真机对局抓取对比：
- `Hero + 32`：读数停滞于初始值；
- `Hero + 0xA8 -> Transform`：每一帧随移动平滑更新，且在敌方迷雾遮挡时仍然持续更新（帧同步模拟所必需）。

---

## 4. 修复与验证实现

在 `hero_reader.c` 中落地综合解决方案：
1. **保留 GameRoot 链定位实体**：通过 `base + 0x51EA4D0` $\rightarrow$ `GameRoot` $\rightarrow$ `CActorManager` $\rightarrow$ `HeroEntry` 稳定获取目标 `Hero*`；
2. **修正 64 位属性偏移**：读取 `+0x28 (config_id)` 与 `+0x34 (camp)`；
3. **坐标转由 Transform 物理链输出**：获取 `Hero + 0xA8` 下的真实物理坐标输出至 `heroes.bin`，彻底解决中后期坐标卡死问题。
