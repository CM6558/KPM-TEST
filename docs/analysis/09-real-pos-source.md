<!-- 09-real-pos-source.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: MovementComponent::UpdateLogic + 真实坐标写入链 -->

## 16. ★ MovementComponent::UpdateLogic + 真实坐标写入链(已分析)

### 16.1 MovementComponent::UpdateLogic(每帧位置更新分发器)

**函数地址**: `sub_287D264 @ 0x287d264`  
**Evidence**: `ev_4cafd483a4c3ab150f62d56eef04d2c61d218fdea17d0c6824f9c758d4ae10f6`

```cpp
__int64 __fastcall sub_287D264(__int64 result, unsigned int a2)
// a1 = MovementComponent* this
// a2 = frame_id

// Line 18: v2 = actor+16 的 count(高 17 bits = count, 低 15 bits = 某标志)
v2 = *(DWORD*)(result + 16);
if ((v2 & 0x7FFF) != 0) {           // 只在有 movement children 时进入
    v9 = 24 * (v2 & 0x7FFF) - 24;   // 24 字节步长的 children 数组(count * 24 - 24)
    
    // 遍历每个 movement child(每项 24 字节)
    while (1) {
        // 拿 child(v13)
        if (v11)  v12 = *v7;        // SSO / heap 切换
        v13 = v12[v5/8];
        
        // Line 44: ★ child+560 偏移找到真正的 movement_sub_component(可能 rvo agent)
        if (v13 && v13[3] == v12[v5/8+1]) {
            v14 = v15[v5/8] + 560LL;  // ★ child+560 = RVO/Physics 子模块(可能是 RVOSimulator)
        }
        
        // Line 47-55: ★ 若 child 活跃 → 调 off_51AF748 真正更新
        v16 = *(_QWORD *)v14;
        if (v16 && v16[3] == v14[1]) {        // ID 校验
            if (*(_BYTE *)(v16 + 328)) {       // 子组件 enabled flag
                log("MovementComponent::UpdateLogic");
                v17 = off_51AF748(*(_QWORD *)v14, a2);   // ★ 真正的 movement update!
                result = (*v10)(v17);                    // = (off_50C0C38)(v17) = profiler end
            }
        }
        
        if (v9 == v5) break;
        v5 += 24;
    }
}
```

### 16.2 ★★★ 真实坐标写入完整链(完整反推)

```
┌─────────────────────────────────────────────────────────┐
│ 1. CBattleLogic::UpdateLogic (sub_45D7178)             │
│    - 引擎每帧总入口                                     │
│    - 调用各 UpdateLogic 子系统(8 个,见 ledger §6.5)  │
└──────────────────────────────┬──────────────────────────┘
                               │
                               ↓ ActorManager::UpdateLogic
                               ↓ (sub_45AAB64, line 53: actor->vtable[19])
                               ↓
┌─────────────────────────────────────────────────────────┐
│ 2. HeroControler::UpdateLogic (sub_3D90AE8)            │
│    - 每帧英雄 tick                                      │
│    - line 28: a1+1640 = MovementComponent* 子对象      │
│    - line 28: MovementComponent.vtable[22](frame) 调用 │
└──────────────────────────────┬──────────────────────────┘
                               │
                               ↓ MovementComponent.vtable[22]
                               ↓
┌─────────────────────────────────────────────────────────┐
│ 3. MovementComponent::UpdateLogic (sub_287D264)        │
│    - 遍历 movement children(每项 24 字节)             │
│    - 调 off_51AF748(child, frame)                       │
└──────────────────────────────┬──────────────────────────┘
                               │
                               ↓ off_51AF748(child, frame)
                               ↓ (GOT slot,未直接反编译)
┌─────────────────────────────────────────────────────────┐
│ 4. off_51AF748 — 真正位置更新函数(底层)              │
│    - 基于 RVO(Reciprocal Velocity Obstacles)算法     │
│    - Physics::RVOSimulatorMgr(避障 sim)                 │
│    - 计算 velocity,累积位移                           │
│    - ★★★ 写入 hero+32(real_x) / hero+40(real_y) /   │
│               hero+44(real_z)                            │
└─────────────────────────────────────────────────────────┘
```

### 16.3 物理 / 移动相关组件清单(从字符串反推)

| 组件 | 模块 | 用途 |
|------|------|------|
| `Physics::RVOSimulatorMgr` | Foundation/Physics/ | RVO 避障仿真总管(MOBA 必备) |
| `Physics::SNavMesh` | Foundation/Physics/PathFinding/NavMesh/ | 寻路网格 |
| `Physics::NavMeshInstance` | NavMesh/NavMeshInstance.cpp | 寻路场景实例 |
| `Physics::NavMeshEntity` | NavMesh/ | 网格实体 |
| `Physics::NavMeshLimitUtility` | NavMesh/NavMeshLimitUtility.cpp | 网格边界限制 |
| `MovementComponent::UpdateLogic` | Foundation/Physics | 每帧位置更新分发器 |
| AGE::CreateNavMeshDuration / SetRVORadiusTick / AddRVOAgentDuration | AGE/Tick | 引擎 tick 节点(创建 / 设置 RVO 半径) |

### 16.4 服务端同步流程(完整推断)

```
1. 服务端权威帧:
   CBattleLogic::UpdateLogic(frame)
   → HeroControler.UpdateLogic(frame)
   → MovementComponent.UpdateLogic(frame)
   → off_51AF748(child, frame)
   → off_51AF748 内部:
      - RVO 计算新 velocity(基于邻居避障)
      - velocity × frame_dt 累加位置
      - ★ 写入 hero+32(real_x)/ hero+40(real_y)/ hero+44(real_z)

2. 同步检查(bSyncPos flag):
   - 检查每个 hero 是否需要同步位置给客户端
   - 用 SyncPositionMoveCmd(sub_28D1600 单例工厂)生成同步命令
   - 调 ViewManager::ModifyEnemyInvisibleHeroPosition(敌方 hero)做视野混淆
   - 把 display_pos(hero+28/+36)发给敌方客户端

3. 视野混淾示例(兰陵王/阿轲技能3隐身):
   - 读 real_pos(hero+32/+40)
   - 计算 dist_to_main_hero
   - 若 dist < 79cm 或 <99cm:微调 display(±4000/±8888cm 偏移)
   - 若 dist > 79:设 display = (50000, 50000) 或 (-50000, -50000)
   - 客户端收到 display_pos(已混淆)
```

### 16.5 关键 IDA 限制(本轮遇到)

| 问题 | 原因 |
|------|------|
| `sub_44F4E20` 反编译失败 | 函数大小 = 0x3B708 = 243,720 字节,IDA Hex-Rays 超时 |
| 多个 xref 地址都指向 sub_44F4E20 | Sub_44F4E20 是巨大 dispatcher(可能 puerts/JS/Lua binder),内含大量 case 分支 |
| 因此 `SetPosition`、`bSyncPos`、`ForceSetPositionTick` 等具体 case 反编译失败 | 它们都在 243KB dispatcher 函数内 |

### 16.6 已知 setter 函数(从字符串命名推断)

| 函数名 | 字符串地址 | 用途(推测) |
|--------|----------|------------|
| `bSetHeroHpValue` | 0x1191014 | 设置英雄 HP |
| `bSetHeroMaxHpValue` | 0x117dc45 | 设置英雄最大 HP |
| `bSetHeroEpValue` | 0x1163fbe | 设置英雄 EP(蓝条)|
| `bSetHeroLevel` | 0x11aaafe | 设置英雄等级 |
| `bSetInitialVelocity` | 0x11c993f | 设置初速度 |
| `bSetFinalVelocity` | 0x11dd3aa | 设置最终速度 |
| `bSyncPos` | 0x11fe4d5 | 同步位置(flag) |
| `bForbidRVO` | 0x1190ea2 | 禁用 RVO |
| `bUpdatePosLater` | 0x11702d7 | 延迟更新位置 |

注:`b` 前缀 = bool 返回值(成功/失败),典型服务端 RPC 调用模式

### 16.7 待挖(下轮 IDA 恢复后)

- `off_51AF748` 真实函数地址(GOT slot 间接)— **最关键**,这是真正写入 hero+32/+40/+44 的源泉
- `sub_44F4E20` 243KB dispatcher 的具体 case 处理 — 看具体 `bSetHeroXxx` / `bSyncPos` / `SetPosition` 的实际写入逻辑
- `Project8SetHeroCmd`(0x114de09)— Project8 命令总入口

---

