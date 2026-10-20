<!-- 01-entry-points.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: 引擎入口 + 限制 + 操作规范 -->

## 3. 引擎逻辑关键入口(已确认/部分确认)

### 3.1 顶层访问路径
```cpp
GameRoot::ActiveDesk()->BattleLogic->isFighting
```
- `off_51EA4D0` — **GameRoot 单例全局指针**(强证据,所有 ensure/log 都用此表达式)
- `GameRoot` 持有 `BattleLogic`,通过 `ActiveDesk()` 返回当前 `GameDesk`
- `GameDesk` 持有 `BattleLogic`(CBattleLogic 类型)作为成员(偏移 ~952)

**Evidence**: `ev_866ef248...` (sub_46D5244 pseudocode)

### 3.2 引擎 Tick 系统(已确认是字符串表注册)
| 字符串地址 | 字符串内容 | 引用者 |
|--------|-----|-----|
| `0x1b030` | `sgc_InspectorTick` | `0x1d90`(注册表项) |
| `0x1b042` | `sgc_LogicTick` | `0x1da8`(注册表项) |

- `0x1d90` / `0x1da8` 是 ELF 早期表区,极可能是 **.init_array / 函数指针表 / 字符串→函数注册表**
- `sgc_*Tick` 是命名约定(sgc = SGCore 缩写),通过**字符串名字查表分发**,这是 puerts/Lua 桥接的典型模式

### 3.3 AGE Tick 节点系统(AGE 引擎的核心机制)

源码路径 `Mods/AGE/src/AGE/Tick/` 显示 AGE 用 **Tick 节点树**驱动动作。
基类 `Framework/Parts/AGECore/src/Runtime/AGE/ActionTemplate.cpp`

**已观察的 AGE Tick 节点(引擎逻辑核心组件,部分清单)**:

**AGE::** (运行时实例)
- `AGE::GuidePathIndicatorTick`        - 路径指示
- `AGE::SetParticleExtraScaleTick`    - 粒子缩放
- `AGE::SetSkillLevelTick`             - 技能等级
- `AGE::SetObjBehaviourModeTick`      - 行为模式
- `AGE::SetBulletAbilityTick`          - 子弹能力
- `AGE::PlayInBattleCommercialActionTick` - 战斗中商业动作
- `AGE::SetSquadUnitTick`              - 设置小队单位
- `AGE::VariableScopeBuffTick`         - 变量作用域 Buff
- `AGE::CheckBuffMarkCountTick`        - Buff 计数检查
- `AGE::NewVariableIntCompareTick`    - 整数比较
- `AGE::GuideToggleHeroShowTick`       / `AGE::GetSkillBeanTick` / various

**AGETemplate::** (模板/工厂)
- `AGETemplate::InitSquadUnitTick`(★初始化小队单位)
- `AGETemplate::ForceButtonUpTick`     - 按键抬起
- `AGETemplate::ADGHitTriggerAgeParamEffectTick`
- `AGETemplate::CheckSkillIDConditionTick` - 技能 ID 条件检查
- `AGETemplate::CheckCanWalkWallTick`   - 能否穿墙(寻路)
- `AGETemplate::NewSpawnBulletSetLifeTick` - 生成子弹
- `AGETemplate::SpawnShenFuTickAdv`     - 神符(Buff 道具)
- `AGETemplate::PlaySoundTick`          - 播放声音
- `AGETemplate::ReviveTimerTick`        - 复活计时
- `AGETemplate::PreLoadTick`            - 预加载
- `AGETemplate::TriggerNewbieGuideTick` - 新手引导

**Evidence ID**: `ev_94ca9998...`(AGE/SGCore/Buff 等 search 保留,因 10MB limit 不能直接读出)

### 3.4 战斗系统核心(CBattleLogic + ActorManager)
- `CBattleLogic.UpdateLogic`(战斗主更新,字符串地址 `0x11a4108`)
- `CBattleLogic_filter::SIG_UpdateLogic`(filter 装饰器)
- `CBattleLogic_filter.UpdateAreaCheck`(区域检查)
- `CBattleLogic_filter::SIG_UpdateLogic`
- `SGCore::BattleLogicUnitSignal`(战斗单元信号)
- `SGCore::BattleLogicUnit`(战斗逻辑单元基类)
- `SaveUnityObjectsToBattleLogicUnit` / `GetUnityObjectsFromBattleLogicUnit`
- `GameRoot::ActiveDesk()->BattleLogic->isFighting`(顶层访问)

### 3.5 JNI 启动流程(JNI_OnLoad,已确认 — 见 v1 ledger 第 2 节)

JNI_OnLoad @ `0x4b3ee50` -> setTag("Escher-GameCore") -> enableDebug(1)
  -> 拿 Context(2 路径) -> AAssetManager -> 加载 2 个关联文件
  -> asset 记录表解析(每条 96 字节,12898944 ~ 12MB 大小)

---

## 4. 当前限制 & 缓解

### Provider 真实限制(已实测)
| 操作 | 状态 | 备注 |
|------|------|------|
| `binary_session` | ✅ | 正常 |
| `binary_overview` | ✅ | 一次调用走完 list_documents + list_procedures + list_strings(几十秒) |
| `open_binary` | ✅ | attached 模式直接成功 |
| `procedure_pseudo_code` | ✅ | 用地址或名字均可;接受任意代码地址会拿到所属函数 |
| `procedure_assembly` | ✅ | (未测,签名同 pseudocode) |
| `procedure_callers` / `procedure_callees` | ✅ | |
| `search_procedures` | ⚠️ | **substring 模糊匹配,Broad 匹配爆 10MB**(AGE::/SGCore/sgc_/CBattleLogic 等都爆) |
| `search_strings` | ✅ | 广泛 pattern 可用,返回 address+value |
| `xrefs` | ✅ | 接受字符串地址,返回引用代码地址(可能返回 0x1dXX 这种表地址) |
| `read_bytes` | ❌ | **IDA adapter 不声明此能力**(无法直读字符串字节内容) |
| `resolve_containing_procedure` | ❌ | **不支持** |
| `inspect_analysis_view` | ⚠️ | **不支持 search_procedures/search_strings 结果的分页**(只支持 native/layout/macho/managed 等 operation 的 facet) |
| `list_procedures` / `list_strings` | ⚠️ | 无 offset/count,**绝对不能裸调**(73k 函数全返会爆) |

### 10MB 限制的应对
1. **`search_procedures` 用极具体的 pattern**(类全名 `CBattleLogic::UpdateLogic` 而非 `CBattleLogic::`)
2. **`search_strings` 通常安全**(返回 address+value,即使 1000 条也才几百 KB)
3. **大量数据用 export → Python 解析**(本地解析 35MB bundle 文件比 MCP 分页快)
4. **`procedure_pseudo_code` 单函数单调用**,响应一般 <100KB

---

## 5. 下一步分支(待选,聚焦游戏引擎逻辑)

### A. **CBattleLogic 主更新循环**(最值得,引擎业务核心)
- `xrefs` 到 `0x11a4108`(字符串 "CBattleLogic.UpdateLogic")的代码 → 那是主循环调用者
- 包含函数的伪代码 → 引擎每帧业务入口
- 预期发现:GameLoop 主驱动、Actor Tick 调度、Skill/Buff 系统调度

### B. **ActionTemplate 基类**(AGE 引擎逻辑核心)
- 路径 `Framework/Parts/AGECore/src/Runtime/AGE/ActionTemplate.cpp`
- 搜 `ActionTemplate` 相关函数 → 拿基类 Update/Tick 法
- 预期发现:AGE 整个 Tick 树的遍历机制

### C. **Actor 管理器及 Actor Tick 更新**
- `Framework/src/BattleSys/ActorManager.cpp`
- 路径字符串 → xref 到包含函数 → Actor 注册/调度代码
- 预期发现:Actor 生命周期管理

### D. **GameDesk 主流程**
- `Framework/src/BattleSys/GameDesk.cpp`
- 期望找到 `GameDesk::Update` / `GameDesk::Init` 主框架

### E. **Escher 热更系统**(不再继续,非引擎逻辑核心,留待后续)

---

## 6. 操作规范(沿用 v1)

- **禁止**:`list_procedures()` / `list_strings()` 无参裸调
- **禁止**:`search_procedures` 用 broad 前缀(`AGE::`、`SGCore`、`sgc_`、`CBattleLogic::` 都会爆 10MB)
- **必须**:先用本地 35MB bundle 解析(避免 MCP 往返)
- **必须**:`procedure_pseudo_code` 单函数单调用
- **必须**:每次结论附 Evidence ID
- **每次** IDA 工具调用前确认:Port 13337 listening = True
- **每次** 任务继续时:`binary_session({})` 检查 provider 状态
- IDA GUI 不要关闭(attached 模式要求)

---

