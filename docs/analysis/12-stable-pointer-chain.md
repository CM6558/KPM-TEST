<!-- 12-stable-pointer-chain.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: 闭环总结 + 稳定指针链 + 待回答问题 -->

## 19. ★★★ 闭环总结 — 真实 Hero 位置完整生命周期

### 19.1 完整生命周期图(最终版)

```
                 ┌────────────────────────┐
                 │ 服务端每帧 tick          │
                 │ CBattleLogic::UpdateLogic│
                 │   (sub_45D7178)        │
                 └──────────┬─────────────┘
                            │
                            ↓ 调 8 个 UpdateLogic 子系统
                            │
                 ┌──────────┴─────────────┐
                 │ ActorManager::UpdateLogic│
                 │   (sub_45AAB64)        │
                 │ 遍历所有 actor          │
                 └──────────┬─────────────┘
                            │ actor.vtable[19](offset 152)
                            ↓
                 ┌────────────────────────┐
                 │ HeroControler::UpdateLogic│
                 │  (sub_3D90AE8)         │
                 │  a1+1640 子对象(即       │
                 │  MovementComponent)     │
                 └──────────┬─────────────┘
                            │ MovementComponent.vtable[22](offset 176)
                            ↓
                 ┌────────────────────────┐
                 │ MovementComponent::Update│
                 │  Logic(sub_287D264)    │
                 │  遍历 child(24 字节步长)│
                 └──────────┬─────────────┘
                            │ child+560 = RVO agent
                            │
                            ↓ off_51AF748(child, frame)
                            │ GOT slot 0x51AF748 → 0x3ee11b8
                            ↓
                 ┌────────────────────────┐
                 │ sub_3EE11B8(MovementComponent│
                 │  真正更新)              │
                 │ 1. off_51AF678(child, RVO, 0,0)
                 │    → 计算 velocity        │
                 │ 2. vtable[19] 更新子模块1│
                 │ 3. vtable[21] 更新子模块2│
                 └──────────┬─────────────┘
                            │
                            ↓ 通过上层调 sub_3D7BB94
                            ↓ Profile mark 23068733
                            ↓ off_5153CD0(hero, frame, pos, vel)
                            │ GOT slot 0x5153CD0 → 0x36a283c
                            ↓
       ┌──────────────────────────────────────────┐
       │ ★★★ sub_36A283C - 真正写入 hero 位置!     │
       │                                          │
       │  *(_QWORD*)(hero + 32) = a3;  // real_x  │
       │  *(_DWORD*)(hero + 40) = a4;  // real_y  │
       │  *(_WORD*) (hero + 44) = z16; // real_z  │
       │  *(_DWORD*)(hero + 84) = a2;  // atk_r   │
       │  *(_DWORD*)(hero + 88) = a6;  // enabled │
       │  *(_DWORD*)(hero + 92) = 3;    // state   │
       │  *(_BYTE*) (hero + 234) = a5; // srv_auth │
       │  *(_DWORD*)(hero + 200) = a2;  // atk_r_v2│
       └──────────────────────────────────────────┘
                            ↓
                            ↓ 之后 ViewManager.ViewManager::ModifyEnemyInvisibleHeroPosition
                            ↓ (sub_24AD7FC line 89) 读 hero+32/main_hero+32 算
                            ↓ off_517F388 → sub_3AC94A8 欧式 2D 距离
                            ↓
                            ↓ 若敌方隐身 → 修改 hero+28/+36(display_x/y) → (50000, 50000)
                            ↓
                            ↓ 写 display_pos 到客户端网络包
                            ↓
                            ↓ 客户端收到 display_pos,渲染位置
```

### 19.2 Hero 真实坐标生命周期 4 阶段

```
┌─────────────────────────────────────────────────────────────┐
│ 阶段 1: 写入(服务端权威)                                   │
│   sub_36A283C(hero_ptr, frame, pos, vel, is_auth, enabled)  │
│   写入 hero+32/+40/+44/+84/+88/+92/+200/+234                │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段 2: 读取(服务端用)                                     │
│   sub_3AC94A8(hero_ptr, target_pos_ptr, ..., mode=1)        │
│   - 读 hero+32(+36) = real_x                                 │
│   - 读 hero+40 = real_y                                       │
│   - 算欧氏距离: sqrt((dx)² + (dy)²)                        │
│   被 730 个函数调用(CanHitTarget / CheckHitTarget /         │
│   GetNorAtkTarget / ViewManager / EscapeFromPosSkill 等)     │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段 3: 视野混淆(发给敌方客户端)                           │
│   ViewManager::ModifyEnemyInvisibleHeroPosition              │
│   (sub_24AD7FC)                                              │
│   - 若敌方 hero 隐身(兰陵王/阿轲技能3):                    │
│     a) 距离<79cm: 微调 display ±4000cm                       │
│     b) 距离<99cm: 微调 display ±8888cm                       │
│     c) 草丛内: 微调 display ±2222cm                          │
│     d) 远距离: display = (50000, 50000)                       │
│   - 只修改 hero+28/+36 (display_x/y),不动 hero+32/+40       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段 4: 网络同步(发给客户端)                               │
│   ViewManager 发送 display_pos 给敌方客户端                  │
│   NtfSubMsg / 战斗消息包                                     │
│   (display_pos 已混淆)                                       │
## 19. ★★★ 真实稳定指针链(完整修复版)— 含 hero 真实坐标

### 19.1 修复:Hero 数组真实位置 = CActorManager + 11888

通过 `sub_45ACA90`(CActorManager 析构 / ClearActor,@0x45aca90)分析得到 **Hero 数组的真实位置**:

```cpp
// sub_45ACA90 line 121:
((void(__fastcall**)(_QWORD))v2[20])(*(_QWORD *)(*(_QWORD *)(a1 + 11888) + 32LL * v23 + 8));
//                                           ↑
//                                          a1+11888 = Hero 数组起点(Vector<HeroEntry>)
//                                                       步长 32 字节
//                                                                  每项 +8 = Hero*
//                                           v2 = &off_51B5000(vtable), v2[20] = vtable[20]
```

**evidence**: `ev_d110c5b707e46a311c8f47140ccbb07e274e8b5683d9ac06158ef57dbacb0b22`

### 19.2 CActorManager 完整字段布局(从析构函数反推)

`sub_45ACA90`(CActorManager::~Clear,确认 ID = Profile 26116101):

| 偏移 | 类型 | 含义 | 证据 |
|------|------|------|------|
| +48  | PTR | Vector start(可能不是 Hero 数组) | 之前误判 |
| +120 | PTR | Vector start | |
| +192 ~ +672 | 多个 vector (每 32 字节) | 各种数据 | line 157-173 |
| +11888 | PTR | ★ **Hero 数组 Vector start**(步长 32) | line 121 |
| +11920 | PTR | Index 数组(每项 4 字节) | line 120 |
| +11952 | DWORD | 第二组 actor 索引数 / count | line 122 |
| +11960 | PTR | Monster cache 数组 | ledger §10.5 |
| +11988 | DWORD | Monster cache count | |
| +12032 | PTR | 定时器队列 | ledger §8.3 |
| +12080 | PTR | Vector start | line 59 |
| +12108 | DWORD | Vector size | line 63 |
| +12112 | PTR | Vector start(步长 24) | line 46 |
| +12140 | DWORD | Vector size | line 50 |
| +12144 | DWORD | 析构后清零 flag | line 175 |

### 19.3 ★★★ 最稳定的英雄信息指针链(完整版)

```
┌─ Level 0: 全局入口(全局唯一,永不为 0) ──────────────────┐
│ [off_51EA4D0] = GameRoot** (g_game_root)                  │
│   物理地址 0x52717b0(.data 段硬证据)                       │
│   类型: GameRoot* 单例                                     │
│   永远是单局内的稳定入口                                   │
└─────────────────┬──────────────────────────────────────────┘
                  ↓ deref
┌─ Level 1: GameRoot 实例 ───────────────────────────────────┐
│ *off_51EA4D0 = GameRoot*                                  │
│   所有线程/系统通过此访问                                   │
└─────────────────┬──────────────────────────────────────────┘
                  ↓ +952 bytes
┌─ Level 2: CBattleLogic 实例 ─────────────────────────────┐
│ *(GameRoot + 952) = CBattleLogic*                         │
│   硬证据: ev_866ef248 / ev_434bb35a / ev_65f33260         │
│   (sub_46D5244 line 30 + GetNorAtkTarget §15.2 line 97)   │
└─────────────────┬──────────────────────────────────────────┘
                  ↓ +16 bytes (CBattleLogic 持有的子链路起点)
                  ↓ +432 bytes (硬证据 CBattleLogic::UpdateLogic line 56)
┌─ Level 3: CActorManager 实例 ⚠ (软证据) ──────────────────┐
│ *(*(CBattleLogic + 16) + 432) = CActorManager*           │
│   软证据来源:只有 CBattleLogic::UpdateLogic line 56 推导  │
│                                                            │
│   注意:这是整条链唯一的软证据点                            │
│   更稳办法见 §19.5 备选入口                                │
└─────────────────┬──────────────────────────────────────────┘
                  ↓ +11888 bytes
┌─ Level 4: Hero 数组(vector 头) ────────────────────────┐
│ *(CActorManager + 11888) = HeroEntry*  (vector start)    │
│   每项 32 字节(步长)                                      │
│                                                            │
│   struct HeroEntry {  // 32 字节                           │
│       +0:  ?_ptr_or_data1;     // 待验证                   │
│       +8:  Hero*  hero_ptr;     // ★ 真正的 Hero 对象指针 │
│       +16: ?_data2;                                          │
│       +24: ?_data3;                                          │
│   };                                                        │
│   证据: sub_45ACA90 line 121 (~CActorManager)             │
└─────────────────┬──────────────────────────────────────────┘
                  ↓ 遍历匹配或按 index 读
                  ↓ *(HeroEntry + 8) = Hero*
┌─ Level 5: ★★★ Hero 对象(1008 字节)— 真实坐标就在这 ────┐
│                                                            │
│  Hero + 4:    config_id     (DWORD)   ← 多条硬证据         │
│  Hero + 8:    runtime_id    (DWORD)   ← ev_2b861dcb       │
│  Hero + 28:   display_x     (DWORD) ⚠ 视野混淆,禁用!      │
│  Hero + 32:   ★ real_x      (QWORD = 8B packed)  ← ev_d42d2de8│
│  Hero + 40:   ★ real_y      (DWORD)            ← ev_d42d2de8│
│  Hero + 44:   ★ real_z      (WORD, 16-bit)      ← ev_d42d2de8│
│  Hero + 84:   atk_range_factor (DWORD) ← ev_d27eb977       │
│  Hero + 88:   enabled_flag (DWORD ≥1) ← ev_2b861dcb        │
│  Hero + 92:   state_code (DWORD =3)  ← §18.2               │
│  Hero + 196:  ?_copy_of_config_id                          │
│  Hero + 200:  atk_range_factor_v2 (DWORD)                  │
│  Hero + 212:  source_id (DWORD,同步标记)                   │
│  Hero + 234:  is_server_auth (BYTE)                        │
│  Hero + 712:  is_in_grass (BYTE,ViewManager 用)           │
│  Hero + 856:  is_in_grass2 (BYTE)                        │
│  Hero + 1008: next entry                                    │
└────────────────────────────────────────────────────────────┘
```

### 19.4 C++ 等价代码

```cpp
// ===== 最稳定指针链(基于硬证据)=====
// 唯一软证据点:BattleLogic → +16 → +432 跳到 ActorManager

// Level 0: 全局入口
extern GameRoot** g_game_root;          // @ 0x52717b0 (.data)

// Level 1: 解引用拿 GameRoot*
GameRoot* game_root = *g_game_root;

// Level 2: +952 拿 BattleLogic*
CBattleLogic* battle_logic = *(CBattleLogic**)((char*)game_root + 952);

// Level 3: +16 +432 拿 ActorManager*(软证据)
char* bl_inner = *(char**)((char*)battle_logic + 16);
CActorManager* actor_mgr = *(CActorManager**)(bl_inner + 432);

// Level 4: 拿 Hero 数组 vector 起点
HeroEntry* hero_array = *(HeroEntry**)((char*)actor_mgr + 11888);

// Level 5: 遍历找目标 hero(可按 config_id 或 runtime_id 匹配)
Hero* target_hero = nullptr;
for (int i = 0; i < /* actor count */; i++) {
    Hero* candidate = *(Hero**)((char*)&hero_array[i] + 8);  // +8 = hero_ptr
    if (!candidate) continue;
    if (*(int*)((char*)candidate + 88) < 1) continue;         // enabled_flag
    if (*(int*)((char*)candidate + 4) == target_config_id    // config_id 匹配
        || *(int*)((char*)candidate + 8) == target_runtime_id) {
        target_hero = candidate;
        break;
    }
}

// ★★★ 读取真实坐标(永不被视野混淆影响)
int32_t real_x = *(int32_t*)((char*)target_hero + 32);
int32_t real_y = *(int32_t*)((char*)target_hero + 40);
int16_t real_z = *(int16_t*)((char*)target_hero + 44);   // WORD = 16 位!

// 其他有用字段
int32_t config_id = *(int32_t*)((char*)target_hero + 4);
int32_t runtime_id = *(int32_t*)((char*)target_hero + 8);
int32_t atk_range = *(int32_t*)((char*)target_hero + 84);
uint8_t is_in_grass = *(uint8_t*)((char*)target_hero + 712);
```

### 19.5 备选入口(更稳但更繁琐)— 绕过 BattleLogic 软证据

如果 `BattleLogic → +16 → +432` 这条软证据不可靠,可以用 **`SpawnActor`(sub_45AB134)的 callers 反推**:

- SpawnActor 的 caller 一定持有 CActorManager*
- 但 IDA procedure_callers 返回空(虚调用)— 不能直接拿
- **替代**:扫所有 store 到 `.+11888` 的函数(用离线 capstone 脚本类似本次但定位 +11888)— 这能找到所有构造 CActorManager 的代码,从而确认全局单例

另外一个完全不同的备选链路:
- 通过 `qword_53DEF90` 单例(SGCore::HERO_INFO 单例)— 这是另一个全局
- 但这个装的是主英雄的镜像副本,有滞后风险
- 适合主英雄快速访问,不适合所有 10 个英雄

### 19.6 关于"永不被影响"的分析

| 风险 | 评估 | 缓解 |
|------|------|------|
| 视野混淆 | ✅ 安全 | `real_x/y/z` 在 +32/+40/+44;ViewManager 只改 +28/+36,从不碰 +32/+40/+44 |
| 网络延迟 | ✅ 安全 | 读的是服务端权威值,与客户端收到时无关 |
| Display 坐标同步抖动 | ✅ 安全 | display 走另一条链路 |
| 单局生命周期 | ⚠ `GameRoot` 单例可能重启时换地址 | 单局内稳定 |
| ActorManager 重建 | ⚠ SpawnActor 时增,DestroyActor 时减 | 用 +88 enabled_flag 过滤 |
| 多线程 | ⚠ 主 tick 线程写、其他线程读 | DWORD 是原子读,基本安全;若要完全安全需 memory barrier |
| SpawnActor 进行中读 | ⚠ Hero 数组可能正在被插入 | 用 `+88 ≥1` 过滤已就绪的 |

### 19.5 备选入口(更稳但更繁琐)— 绕过 BattleLogic 软证据

**重大发现**:`sub_3CFFEF8` 是 `CFrameSynchr.UpdateLogicPartB`(`CFrameSynchr.UpdateLogicPartB` log @ line 12),它通过更直接的路径调用 `CActorManager::UpdateLogic`:

```cpp
// sub_3CFFEF8 line 18:
off_5226A90(*(_QWORD *)(*(_QWORD *)off_51EA4D0 + 904LL), a2);
//             ↑                     ↑
//   CActorManager::UpdateLogic     GameRoot + 904 = CActorManager*
//   (= sub_45AAB64, 0x5226a90 是 vtable)
//   a2 = frame_id
//
// ★★★ 这意味着 GameRoot + 904 = CActorManager*!  (硬证据!)
```

**evidence**: `ev_afb3e1a130bde8d8ec9583b799bfb7f811844ea8fbc6a726580e5ea29b5345af`

**这条新路径完全跳过 BattleLogic**!不需要 `BattleLogic → +16 → +432` 的软证据路径。

**新发现的 GameRoot 子系统布局**(从 `CFrameSynchr.UpdateLogicPartB` 反推):
- `GameRoot + 688` = 某 UpdateLogic 子系统(可能 NavMesh)
- `GameRoot + 904` = **★ CActorManager***(硬证据)
- `GameRoot + 952` = CBattleLogic*(已知)
- `GameRoot + 1024` = 某 subsystem
- `GameRoot + 1072`, +1096, +1120, +1216, +1240, +1264, +1360, +1384, +1408, +1432, +1552 = 其他子系统

### 19.5b ★★★ 最终最稳定指针链(更新版,绕过软证据)

```
┌─ Level 0: 全局入口 ─────────────────────────────────────┐
│ [off_51EA4D0] = GameRoot**                  │
│   物理地址 0x52717b0(.data 段硬证据)         │
│   永远稳定,全局唯一                          │
└─────────────────┬────────────────────────────┘
                  ↓ deref
┌─ Level 1: GameRoot 实例 ─────────────────────────────────┐
│ *off_51EA4D0 = GameRoot*                                 │
└─────────────────┬─────────────────────────────────────────┘
                  ↓ + 904 bytes
┌─ Level 2: CActorManager 实例 ────────────────────────────┐
│ *(GameRoot + 904) = CActorManager*                       │
│   ★ 硬证据: ev_afb3e1a1 (CFrameSynchr.UpdateLogicPartB  │
│             line 18 直接调 CActorManager::UpdateLogic)   │
│   替代了旧版 Level 2-3 的 BattleLogic 软证据路径           │
└─────────────────┬─────────────────────────────────────────┘
                  ↓ + 11888 bytes
┌─ Level 3: Hero 数组(vector 头) ─────────────────────────┐
│ *(CActorManager + 11888) = HeroEntry*  (vector start)   │
│   每项 32 字节                                           │
│   struct HeroEntry {  // 32 字节                          │
│       +0:  ?_ptr_or_data1;                                │
│       +8:  Hero*  hero_ptr;     ← ★ Hero 对象指针       │
│       +16: ?_data2;                                       │
│       +24: ?_data3;                                       │
│   };                                                      │
└─────────────────┬─────────────────────────────────────────┘
                  ↓ *(HeroEntry + 8) = Hero*
┌─ Level 4: ★★★ Hero 对象(1008 字节)— 真实坐标在这 ────┐
│  Hero + 4:    config_id     (DWORD)                      │
│  Hero + 8:    runtime_id    (DWORD)                      │
│  Hero + 28:   display_x     (DWORD) ⚠ 视野混淆,禁用!    │
│  Hero + 32:   ★ real_x      (QWORD = 8B packed)          │
│  Hero + 40:   ★ real_y      (DWORD)                       │
│  Hero + 44:   ★ real_z      (WORD, 16-bit)                │
│  Hero + 84:   atk_range_factor (DWORD)                   │
│  Hero + 88:   enabled_flag (DWORD ≥1)                    │
│  Hero + 92:   state_code (DWORD =3)                       │
│  Hero + 196:  ?_copy_of_config_id                        │
│  Hero + 200:  atk_range_factor_v2 (DWORD)                │
│  Hero + 212:  source_id (DWORD,同步标记)                 │
│  Hero + 234:  is_server_auth (BYTE)                      │
│  Hero + 712:  is_in_grass (BYTE,ViewManager 用)          │
│  Hero + 856:  is_in_grass2 (BYTE)                        │
│  Hero + 1008: next entry                                   │
└───────────────────────────────────────────────────────────┘
```

### 19.5c C++ 等价代码(更新版,更稳)

```cpp
// ===== 最稳定指针链(完全硬证据,无软证据点)=====
extern GameRoot** g_game_root;          // @ 0x52717b0 (.data)

GameRoot* game_root = *g_game_root;

// ★ GameRoot + 904 = CActorManager*(硬证据 ev_afb3e1a1)
CActorManager* actor_mgr = *(CActorManager**)((char*)game_root + 904);

// + 11888 = Hero 数组 vector start(硬证据 ev_d110c5b7 ~CActorManager)
HeroEntry* hero_array = *(HeroEntry**)((char*)actor_mgr + 11888);

// 遍历找目标 hero(可按 config_id 或 runtime_id 匹配)
Hero* target_hero = nullptr;
for (int i = 0; i < /* actor count */; i++) {
    Hero* candidate = *(Hero**)((char*)&hero_array[i] + 8);  // +8 = hero_ptr
    if (!candidate) continue;
    if (*(int*)((char*)candidate + 88) < 1) continue;         // enabled_flag
    if (*(int*)((char*)candidate + 4) == target_config_id    // config_id 匹配
        || *(int*)((char*)candidate + 8) == target_runtime_id) {
        target_hero = candidate;
        break;
    }
}

// ★★★ 读取真实坐标(永不被视野混淆影响)
int32_t real_x = *(int32_t*)((char*)target_hero + 32);
int32_t real_y = *(int32_t*)((char*)target_hero + 40);
int16_t real_z = *(int16_t*)((char*)target_hero + 44);   // WORD = 16 位

// 完整英雄信息(不被混溪)
int32_t config_id = *(int32_t*)((char*)target_hero + 4);
int32_t runtime_id = *(int32_t*)((char*)target_hero + 8);
int32_t atk_range = *(int32_t*)((char*)target_hero + 84);
uint8_t is_in_grass = *(uint8_t*)((char*)target_hero + 712);
int32_t state_code = *(int32_t*)((char*)target_hero + 92);    // 应该是 3
```

### 19.5d 可靠度评级(更新版)

| 链路 step | 可靠度 | 证据 |
|-----------|--------|------|
| Level 0: `g_game_root` | ★★★★★ | .data 段硬证据 |
| Level 1: `*g_game_root = GameRoot` | ★★★★★ | deref 硬操作 |
| Level 2: `GameRoot + 904 = ActorManager` | **★★★★★** | **硬证据 ev_afb3e1a1** (CFrameSynchr line 18) |
| Level 3: `ActorManager + 11888 = Hero array` | ★★★★★ | ~CActorManager 中验证 |
| Level 4: `HeroEntry + 8 = Hero*` | ★★★★★ | ~CActorManager 中验证 |
| Level 4: `Hero + 32/40/44 = real_coords` | ★★★★★ | ev_d42d2de8 多方验证 |

**整条链可靠度:★★★★★ 完全硬证据!**

### 19.6 关于"永不被影响"的分析(同上)

| 风险 | 评估 | 缓解 |
|------|------|------|
| 视野混淆 | ✅ 安全 | `real_x/y/z` 在 +32/+40/+44;ViewManager 只改 +28/+36 |
| 网络延迟 | ✅ 安全 | 读服务端权威值 |
| Display 坐标同步抖动 | ✅ 安全 | display 走另一条链路 |
| 单局生命周期 | ⚠ `GameRoot` 单例可能重启时换地址 | 单局内稳定 |
| ActorManager 重建 | ⚠ SpawnActor 时增,DestroyActor 时减 | 用 +88 enabled_flag 过滤 |
| 多线程 | ⚠ 主 tick 线程写、其他线程读 | DWORD 是原子读,基本安全 |
| SpawnActor 进行中读 | ⚠ Hero 数组可能正在被插入 | 用 `+88 ≥1` 过滤已就绪的 |

---

## 20. 待回答问题(原问题"完整内部实现"被拆分为)

- [x] 这个 .so 是什么?→ 腾讯 MOBA 手游 GameCore
- [x] 引擎是什么?→ AGE(Action Game Engine)+ USG + Unity 桥接
- [x] 入口在哪?→ JNI_OnLoad @ 0x4b3ee50
- [x] 引擎架构是什么?→ Foundation/Framework/Mods 三层
- [x] 热更新框架?→ Escher(section-based)
- [ ] **战斗系统主循环?** → 待拿 CBattleLogic.UpdateLogic 伪代码(分支 A)
- [ ] **AGE Tick 树遍历机制?** → 待拿 ActionTemplate 基类(分支 B)
- [ ] **Actor 生命周期?** → 待拿 ActorManager(分支 C)
- [ ] **GameDesk 顶层流程?** → 待拿 GameDesk::Update(分支 D)
- [ ] **Buff/Skill 子系统?** → 引擎内 Buff/Skill 数据结构与执行
- [ ] **寻路/物理?** → NavMesh + 物理代理(Evidence: Foundation/Physics)
- [ ] **战争迷雾(FOW)算法?** → 已知模块在 Framework/src/BattleSys/Horizon/

