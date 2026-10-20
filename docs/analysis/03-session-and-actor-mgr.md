<!-- 03-session-and-actor-mgr.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: 会话管理 + CActorManager::UpdateLogic + 生命周期 + SpawnActor -->

## 7. ★★★ 会话管理经验(重要!已踩坑,务必遵循)

**踩坑记录**:第 3 次重连后,执行 `export_evidence_bundle(overwrite: true)` 把之前累积的 37 条 record(107MB)覆盖成了 6 条!后续虽然又累积到 11 条,但之前的部分成果丢失。

### 规则
1. **重连后绝不 overwrite bundle**:用版本化文件名 `test_so_evidence_v{N}_{date}.json` 保留每次重连前的状态
2. **`open_binary` 重连 = 新 session**:之前 session 的 retained Evidence 不会自动 merge;每次重连前先 export 一份带版本号的 snapshot
3. **重要 pseudocode 立刻完整保存到 ledger**:不依赖 retained Evidence(可能会丢)
4. **当前文件**:
   - `test_so_evidence_bundle.json` —— 当前 session 累积(已不可靠,只有最近几条)
   - `test_so_evidence_v3_after_reconnect.json` —— 重连后 22MB / 11 条的最新 snapshot
5. **后续每次重要发现,先 ledger 文本复制 pseudocode 摘要(防丢)**

---

## 8. ★ CActorManager::UpdateLogic(已分析 — Actor 调度核心)

**函数地址**: `sub_45AAB64 @ 0x45aab64`  
**Evidence**: `ev_10e52d3cd59a2a3f29a87f8eb550e8c3726d6b8b81c5e1d609169c74be5573f2`(在 v3 snapshot 里)

签名:`__int64 __fastcall sub_45AAB64(__int64 a1, unsigned int a2)`  
- `a1` = `this`(CActorManager 实例)
- `a2` = 当前帧号

### 工作机制(清晰的 Actor 遍历 + 定时销毁)

```cpp
// 完整伪代码已保留 — 此处是简化说明

// Line 30-33: 选择索引数组(76 或 108 偏移)
v5 = (a1+112 != 0) ? 108 : 76;        // 两组 actor 索引(活/死 或 本地/远程)
v28 = *(a1 + v5);                       // 取 actor 数量

// Line 35-36: 检查 battle 是否激活
v7 = GameRoot->BattleLogic;             // +952
if (v7[930] || v7[931])                 // battle active 标志位
{
  // Line 42-64: ★ Actor 遍历主循环
  do {
    v12 = (a1[112] != 0) ? v11 : a1[80][v11] + v11;
    v13 = a1[48][v12];                  // Actor 对象指针(a1+48 是 actor 表,步长 24)
    (*(*v13 + 152))(v13, a2);            // ★ Actor 的 frame tick (vtable+152 = 第 19 个虚函数)
    v11++;
  } while (v11 < v17);

  // Line 66-93: ★ 定时器队列 — 帧递减时间,到时销毁
  while (entry = v28[v29]) {
    entry.time -= a2;                    // 帧时间差递减
    if (entry.time <= 0) {
      log("CActorManager.DestroyActor");
      off_5226D70(a1, entry.actor_id);   // 销毁 actor
      ...
    }
  }
  // Line 95-97: 最终清理
}
```

### ★ CActorManager 对象布局(已推导)

| 偏移 | 含义 |
|------|------|
| `a1+48` | **Actor 对象表**(指针数组,24 字节步长,索引数组) |
| `a1+80` | **Actor 索引映射表**(int 数组,用于变长索引) |
| `a1+76` | 第一组 actor 数量(`a1+112==0` 时用) |
| `a1+108` | 第二组 actor 数量(`a1+112!=0` 时用) |
| `a1+112` | **Actor 组别 flag**(0→第一组;非 0→第二组)|
| `a1+12032` | **定时器队列**(最小堆结构,16 字节/条) |

### 验证假设(待证据)

- ⚠ 假设:`a1+76` vs `a1+108` 是"活/死 actor"或"本地/远程 actor"(MOBA 网络同步特征)。需验证
- ⚠ 假设:`Actor::vtable+152`(`0x98`)是 frame tick 函数。需拿 actor 实例伪代码确认(因为 actor 是动态派发的,无法直接搜;但可以从 `SpawnActor` 入口追到 actor 类型注册)
- ⚠ 假设:`a1+12032` 是最小堆;需看 `off_511C530` / `off_511C550` / `off_50F9D00` 实现确认

### 全局 BattleLogic 标志位

- `GameRoot->BattleLogic` (off_51EA4D0 + 952) 持有两个 byte 标志:
  - `+930` = battle_started(或 frame_in_progress)
  - `+931` = battle_finished(或 paused)
  - 推测:两者都需 false 才进入 tick(条件 `v7[930] || v7[931]` 真 = tick)

---

## 9. Actor 生命周期入口候选(下一步分析)

### 创建侧(已找到入口字符串)
- `SpawnActor` @ `0x1154001` —— 创建入口
- `FinalizeSpawnActor` @ `0x11d3db3` —— 完成创建(可能异步)
- `SpawnActorNode` @ `0x11e91be` —— 蓝图节点版
- `CreateActorBluePrintComponentNode` @ `0x11c89cb` —— 蓝图组件节点

### 销毁侧
- `CActorManager.DestroyActor` 日志字符串(在 CBattleLogic::UpdateLogic line 88 调用)
- `off_5226D70(a1, actor_id)` — 实际销毁函数(未分析)
- `off_5226DB0(a1)` — 最终清理(未分析)

### Actor 类型注册侧(待挖掘)
- Actor 通过 `Actor::vtable` 派发,但 IDA 没识别出"Actor 基类"完整类型(vtable+152 = 第 19 虚函数)
- 需要:从 `SpawnActor` 入口追到 actor 类型注册(找到 vtable[19] 槽位对应的实际函数)

---

## 10. ★ CActorManager::SpawnActor(已分析 — Actor 创建入口)

**函数地址**: `sub_45AB134 @ 0x45ab134`  
**Evidence**: `ev_d27eb9772a55f165c2014f0442a609bdc15345b1783e3ca0889c77dd0198aefe`(在 v3 snapshot)

**铁证**:`off_50916F8("Framework/src/BattleSys/ActorManager.cpp", "SpawnActor", ...)` —— 源码路径完全实锤身份

### 签名(15 参数,典型的 "配置爆炸" 创建 API)

```cpp
__int64 sub_45AB134(
    int *a1,           // CActorManager* this
    __int64 a2,         // template_id / blueprint_id
    __int64 a3,         // config handle
    char a4,            // autonomous flag
    unsigned int a5,    // frame id
    int a6,             // ?
    char a7,            // bit 16  flag
    _QWORD *a8,         // ★ out_actor_handle(输出 actor 对象指针)
    char a9,            // bit 64  flag
    char a10,           // (line 254: 用于 actor slot 写入)
    char a11,           // bit 256 flag
    char a12,           // bit 512 flag
    __int64 *a13,       // complex cond(配合 bit 1024)
    int a14,
    char a15
)
```

### 主要工作流程

```cpp
// Line 81: Profile mark(26116099 = SpawnActor enter)
off_50B0C38(26116099);

// Line 84-86: 从 GameRoot+1024 拿某 setting
*((BYTE*)a1+44) = *(DWORD*)(off_51AA8E8(*(QWORD*)(*off_51EA4D0 + 1024)) + 72);

// Line 87-88: 从 GameRoot+1072 拿第一 pool,调 vtable[25](slot 25)
v24 = off_50E5B78(GameRoot+1072, 2);
v25 = v24->vtable[25]();    // 拿某资源(预分配?)

// Line 109-110: GameRoot+1072 第三 pool,vtable[17] 
v29 = off_50E5B78(GameRoot+1072, 3);
v29->vtable[17](v29, a1, v82, 0);  // 注册 actor 入管理

// Line 158-163: ★ 日志 with 完整源码位置 / 错误模板
off_50916F8(
    "Framework/src/BattleSys/ActorManager.cpp",
    "SpawnActor", "0", v35,
    "actor info {0} can not be loaded",
    v28 + 456  // 错误时显示的 key
);

// Line 180-187: ★★★ Actor 配置 mask 系统(bit flag 决定 actor 属性)
off_50AE6B0(v79, v61, v68, v58, v59, v62, v63, v60, v64, v70, v65, a14, a15);
off_50AE6C8(v79, 16,   v69 & 1);    // bit 16 = a7
off_50AE6C8(v79, 64,   a9  & 1);    // bit 64 = a9
off_50AE6C8(v79, 512,  a12 & 1);    // bit 512 = a12
off_50AE6C8(v79, 256,  a11 & 1);    // bit 256 = a11
off_50AE6C8(v79, 1024, v67);        // bit 1024 = a13 complex cond

// Line 253: 写 actor slot id 到 out_actor + 80
*((DWORD*)(*a8 + 80)) = (*a1) >> 19;

// Line 262: ★★★ 真正的 actor 初始化入口
result = off_51B5090(*a8, v79, v43, v42, ...);
```

### 重大发现

**1. Actor 创建用 bitmask 配置能力**
- bit 16(`a7`)、64(`a9`)、256(`a11`)、512(`a12`)、1024(complex)
- 推测:可移动/可碰撞/可被攻击/可被选中/有 AI
- 这是引擎的 actor capability 系统,后续应该能从其它"DisableXxx"/"EnableXxx" 函数反推每个 bit 的精确含义

**2. CActorManager 持有 pool/cache 链**
- GameRoot+1072 → pools collection(参数 2/3 区分不同 pool)
- vtable[25]:从 pool 取资源(可能预分配的 actor object)
- vtable[17]:注册 actor 到管理(把 actor 加入管理表)

**3. a8 是 out 参数(out_actor_handle)**
- 调用者通过 `*a8` 拿到 actor 对象指针
- `*a8 + 80` 写 actor slot id
- 此前 +56/+72/+88/+104/+116 偏移已拷贝 CActorManager 当前状态(继承上下文)

**4. 真正的 actor 初始化**:`off_51B5090(*a8, v79, ...)`(v79 = mask 配置)
- 这是 actor 对象自己的初始化函数
- **下一步**:调 vtable+152 的反向 —— 先拿这个函数的伪代码,它会引用 actor vtable 的 set 方法

### CActorManager 还确认的偏移

| 偏移 | 含义 |
|------|------|
| `a1+44` | byte,需被初始化(从 GameRoot+1024 取 + 72 偏移的某 byte 设置) |
| `a1+7` | int(C++ 是 a1+28,byte offset),frame_id 备用 |
| `a1+0`(读)| 取高位 >> 19 → actor slot id(说明 `*a1` 的高位编码了 slot index) |

### Actor 生命周期闭环(已部分建立)

```
Spawn:
  SpawnActor(a1,this; a2,template_id; a8,&out_handle; mask bits...)
    → off_51B5090(actor, mask, ...) [真正构造]  ★ 待挖
    
Tick (每帧):
  CActorManager::UpdateLogic
    → for each actor in a1[48]:
        actor->vtable[19](actor, frame_id)  // vtable+152 = frame tick

Destroy:
  CActorManager::DestroyActor
    → off_5226D70(this, actor_id)  // ★ 待挖
    → 从 timer queue 弹出(line 90-92 in UpdateLogic)
    
Monster Cache (周期淘汰):
  CActorManager::UpdateMonsterCache
    → 每 (a1+12024) 帧执行一次
    → 遍历 a1+11992 的 monster_cache 表(每项 16 字节: {actor_ptr, frame_last_seen})
    → frame - last_seen >= period → off_5226B60(销毁) / off_511C5B0(列表移除)
    → ★ 注:这是怪物离开视野后的延迟销毁机制(MOBA 兵线/野怪 despawn)
```

---

