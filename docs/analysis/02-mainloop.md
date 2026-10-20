<!-- 02-mainloop.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: CBattleLogic::UpdateLogic 主调度循环 -->

## 6.5 ★ CBattleLogic::UpdateLogic 主调度循环(已分析 — 引擎业务核心)

**函数地址**: `sub_45D7178 @ 0x45d7178`
**Evidence**: `ev_65f332605dc1f5fd2bf175942135acbcd6c4c215368a72c4cb02667140613a45`

签名:`__int64 __fastcall sub_45D7178(__int64 a1, unsigned int a2)`
- `a1` = `this`(CBattleLogic 实例指针)
- `a2` = 帧号 / 帧时间

### 单帧更新顺序(逐行解析,line 40-160)

| # | 调用 | 子系统 / 含义 |
|---|------|--------|
| 1 | `off_50B0CC0(26148873, a1+928)` | Profile 区段起始标记(profiler mark) |
| 2 | `(*(v8 + 120))(v8, a2)` (a1+632) | 子系统 #1(未命名) |
| 3 | `off_5136568()` (a1+632/136) | 子系统 #2 |
| 4 | `v12->vtable[18](v12, a2)` (BattleLogic+952+0x10+432) | ★ **ActorManager::UpdateLogic**(条件 a2 <=0x12 时取 unk_53F1860 兜底) |
| 5 | `off_511B1E0(GameRoot+1240, a2)` | GameRoot+1240 子系统 |
| 6 | `off_52174D8()` (a1+136) | 子系统 |
| 7 | `off_50D9410()` (a1+232) | 子系统 |
| 8 | `off_5140A28()` (a1+256) | 子系统 |
| 9 | `off_5133A70()` (a1+584) | 子系统 |
| 10 | `off_5135E10()` (a1+184) | 子系统 |
| 11 | `off_511C028(a1+304, a2)`("BattleInteractionSys::UpdateLogic") | ★ **战斗交互系统** |
| 12 | `off_5216810(a1+496, a2)`("CAIActorMgr::UpdateLogic") | ★ **AI Actor 管理器** |
| 13 | `off_511BBA8(a1+520, a2)`("Physics::UtilityCollisionManager::UpdateLogic") | ★ **物理碰撞** |
| 14 | `v26->vtable[18](v26, a2)`("BattleRecordManager::UpdateLogic") | ★ **战报回放**(条件取 unk_53F1860) |
| 15 | `(*v28)->vtable[18](*v28, a2)`("HeroTrickTrainManager::UpdateLogic") | ★ **英雄连招训练**(条件 a1+939 && a1+44<=4 取 qword_53F14C8) |
| 16 | `off_50B0C40(26148874)` | profiler mark |
| 17 | `off_5159688()`(v30+1360) | 又一子系统 |
| 18 | `off_50CC610(GameRoot+1384, a2)` | 子系统 |
| 19 | `off_50B0C40(26148875)` | profiler mark |
| 20 | `v30+1552` 对象的 vtable[17]() | 子系统 |
| 21 | `off_5226D00(GameRoot+904)` | 子系统 |
| 22 | `v35->vtable[18](v35, a2)`("AIBlueprintEventHandler::UpdateLogic") | ★ **AI 蓝图事件**(配合 Behaviac) |
| 23 | `v38->vtable[18](v38, a2)`("GrassEffectManager::UpdateLogic") | ★ **草丛效果**(MOBA 战争迷雾视野) |
| 24 | `off_50B0CC0(26148876)` | profiler mark |

### Engine UpdateLogic 子系统清单(已确认)

```
✓ ActorManager::UpdateLogic              # (GameRoot.BattleLogic 持有)
✓ BattleInteractionSys::UpdateLogic     # CBattleLogic+304 (a1+304)
✓ CAIActorMgr::UpdateLogic              # CBattleLogic+496 (a1+496)
✓ Physics::UtilityCollisionManager      # CBattleLogic+520 (a1+520)
✓ BattleRecordManager::UpdateLogic      # BattleLogic 子表
✓ HeroTrickTrainManager::UpdateLogic    # CBattleLogic+16 (a1+44<=4 时兜底)
✓ AIBlueprintEventHandler::UpdateLogic  # BattleLogic+952+0x10+336
✓ GrassEffectManager::UpdateLogic       # BattleLogic+952+0x10+360
```

**调用约定**:每个 UpdateLogic 用 vtable[18] (offset 0x90 / 144 字节) 调用 —— 这是引擎基类 `GameLoopObject` 或相似的虚接口。
**Profiler**:用 numeric ID (26148873-26148876) mark 每段 —— 配合 libLightProfiler.so 收集。

### 重要 C++ 对象布局(已推导)

- `off_51EA4D0` = **GameRoot 单例**(`GameRoot::GetInstance()`)
- `GameRoot + 952` 偏移 → **BattleLogic 指针**(CBattleLogic*)
- `GameRoot + 1240` 偏移 → 某子系统管理器
- `GameRoot + 1384` 偏移 → 某子系统
- `GameRoot + 1552` 偏移 → 某子系统(vtable+136)
- `GameRoot + 904` 偏移 → 某子系统
- `CBattleLogic + 1360` 偏移 → 子系统 #17
- `CBattleLogic + 1368` 偏移 → 子系统 #17 使用的 reference ID
- `CBattleLogic + 932` 偏移 → use_flag(`a1+928` 第一参数)
- `CBattleLogic + 939` 偏移 → HeroTrickTrainManager enable flag

---

