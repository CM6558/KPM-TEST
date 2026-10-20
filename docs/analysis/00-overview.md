<!-- 00-overview.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: 概述 + 引擎架构 + 库身份 -->

## 1. 引擎架构(已确认,基于源码路径字符串)

### 三层结构(高置信度,证据:148 个 `/src/` 路径字符串)

```
Foundation/                       # 底层基础库
├─ Common/src/                    # 通用类型、内存、文件、状态机
│  ├─ Type/Class.cpp
│  ├─ Type/StateMachine.cpp
│  ├─ Mem/ArchiveCompressionReader.cpp / Writer.cpp
│  └─ File/DummyFile.cpp
└─ Physics/src/Physics/           # 物理引擎
   ├─ PathFinding/NavMesh/        # 寻路(导航网格)
   │  ├─ NavMeshInstance.cpp / NavMeshLimitUtility.cpp
   │  └─ clipper/clipper.cpp       # 路径裁剪
   └─ Entity/EntityHelper.cpp
   └─ Transform/TransformProxy.cpp

Framework/                        # 游戏框架(核心业务)
├─ src/
│  ├─ BattleSys/                  ★★★ 战斗系统(引擎核心)
│  │  ├─ CBattleLogic_filter.cpp   # CBattleLogic 主战斗逻辑
│  │  ├─ ActorManager.cpp          # Actor 管理器
│  │  ├─ GameDesk.cpp              # 场景/桌管理
│  │  ├─ GameDeskStaticMember.cpp
│  │  ├─ BattleInteraction/BattleInteractionGroup.cpp
│  │  ├─ HeroEnergy/BaseEnergyLogic.cpp     # 英雄能量/蓝条
│  │  ├─ BattleMechanics/GrassEffectManager.cpp  # 草丛(战争迷雾)
│  │  ├─ Equip/CPVPEquipInfo.cpp             # PVP 装备
│  │  ├─ Horizon/                            # ★ 战争迷雾系统
│  │  │  ├─ FieldObjBase.cpp
│  │  │  ├─ GameFowMapData.cpp
│  │  │  ├─ FOWSurfCell.cpp
│  │  │  └─ FowLos.cpp                        # Line of Sight
│  │  └─ StarSystem/WinLoseByStarSys.cpp     # 星系统胜负判定
│  ├─ Actor/                      ★ Actor 系统
│  │  ├─ OrganControler.cpp                   # 单位控制
│  │  ├─ MountManager.cpp                     # 坐骑
│  │  ├─ MonsterControler.cpp                 # 怪物
│  │  ├─ BlockControler.cpp                   # 障碍物
│  │  ├─ HeroProperty.cpp                     # 英雄属性
│  │  ├─ ValueProperty.cpp
│  │  ├─ PropertyAdjuster.cpp
│  │  └─ BaseBulletControler.cpp              # 子弹
│  ├─ Client/                     # 客户端层
│  │  ├─ Actor/ActorControler_filter.cpp
│  │  ├─ BattleSys/AutoRecoverCollectRecorder.cpp
│  │  ├─ Player/GlobalFilter.cpp
│  │  └─ Unity/VirtualUnity_filter.cpp        # Unity 桥接
│  ├─ Skill/
│  │  └─ SkillFunc/SkillFuncPropertyDelegator.cpp  # 技能委托
│  ├─ LogicUnit/                  # 逻辑单元
│  │  ├─ Income/IncomeRuleLogicUnit.cpp
│  │  └─ Actor/ActorHealthSegmentUnit.cpp
│  ├─ Region/SoldierRegion.cpp     # 兵线/区域
│  ├─ Global/GlobalHelper.cpp
│  ├─ Serializer/UGCUnityTypeSerializer.cpp
│  ├─ Report/GameFinishProcessData.cpp  # 战报结束处理
│  └─ GameBuilder/GameBuilderBase.cpp    # 场景构建
│
├─ Parts/                          # 框架子模块
│  ├─ AGECore/src/Runtime/AGE/ActionTemplate.cpp   ★ AGE 引擎核心基类
│  ├─ GraphLogicCore/src/CustomDef/
│  ├─ Serializer/src/Serializer/VariableSerializer.cpp
│  ├─ Databin/src/Resource/CLanguageMap.cpp
│  ├─ IncPatch/src/IncPatch/IncrementalPatchHelper.cpp  # 增量补丁(配合 Escher)
│  └─ GameEntity/src/Unity/VirtualUnity.cpp

Mods/                               # 可选玩法/模块
├─ AGE/src/AGE/                    ★ AGE 动作引擎
│  ├─ Tick/                        # Tick 系统(动画节点)
│  │  └─ ModifyTransform.cpp
│  └─ MMGame/HitTriggerDurationContext.cpp
├─ USG/                            # USG (Unified Scene Graph?)
│  ├─ Engine/src/Serializer/
│  │  ├─ USGSerializer.cpp
│  │  └─ USGTsActorContainerDescriptor.cpp
│  └─ GameModes/Moba55/src/GamePlay/GameMode/Adapter/USGMobaActorRoot.cpp  ★ ★王者荣耀特征★
├─ Lua/src/Lua/                    # Lua 脚本
│  ├─ LuaLoader.cpp
│  ├─ LuaBinder.cpp
│  └─ LuaScriptBinderProxy.cpp
├─ Behaviac/src/AI/ObjAgent_Fun/  # Behaviac 行为树 AI
│  └─ ObjAgent_UseSkill.cpp
├─ GraphLogic/src/GraphLogic/Implements/GraphLogicNodeSGameImplement.cpp
├─ GameModes/Project8/src/GamePlay/GameMode/Project8/Project8SceneManagement.cpp
└─ UGCFramework/src/.../UGCGameBuilder.cpp
```

---

