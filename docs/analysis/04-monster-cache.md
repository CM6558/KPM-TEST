<!-- 04-monster-cache.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: CActorManager::UpdateMonsterCache -->

## 10.5 ★ CActorManager::UpdateMonsterCache(已分析 — 怪物视野淘汰)

**函数地址**: `sub_45B054C @ 0x45b054c`  
**Evidence**: `ev_cbae1406ef18e815f235c60e4d7ab43c91f596943fee405c8d945a9706950e5d`(在 v4 snapshot)

签名:`__int64 __fastcall sub_45B054C(__int64 a1)` — a1 = CActorManager*

### 工作机制(周期性任务模式)

```cpp
// Line 10: 周期(帧数)
period = a1+12024;
if (!period) return;

// Line 13: 全局 frame counter
frame = *(DWORD*)(GameRoot->BattleLogic + 92);

// Line 14: ★ 周期触发(`frame % period == 0`)
if (frame % period != 0) return;

// Line 16-32: 遍历 monster cache 表(a1+11992, 每项 16 字节)
count = *(int*)(a1 + 12020) - 1;
i = count;
while (i >= 0) {
    // Line 23: ★ 若 frame - entry.last_seen >= period → 离开视野太久
    if (frame - *(DWORD*)(*(QWORD*)(a1+11992) + 16*i + 8) >= period) {
        // Line 25: 销毁该 MonsterActor
        off_5226B60(a1, *(QWORD*)(*(QWORD*)(a1+11992) + 16*i));
        // Line 26: 从 cache 列表移除该项
        off_511C5B0(a1 + 11992, i);
    }
    i--;
}
```

### CActorManager 对象布局(补充)

| 偏移 | 含义 |
|------|------|
| `a1+11992` | **Monster cache 表** (每项 16 字节: `{actor_ptr, frame_last_seen}`) |
| `a1+12020` | Monster cache 当前项数 |
| `a1+12024` | **Monster cache 淘汰周期**(帧数,典型 60/120) |

### BattleLogic 重要偏移(补充)

| 偏移 | 含义 |
|------|------|
| `GameRoot->BattleLogic + 92` | **全局帧计数器** |

### 重要推测

- 这个机制是 MOBA 典型的"**怪物离开视野后延迟销毁**"
- a1+12024 周期极可能 = 120 帧(2 秒 @ 60fps)或类似
- 此机制配合"server authoritative despawn":客户端视野内 spawn 怪物、离开视野后不立即销毁而是延迟 period 再销毁,防抖动

### 待挖(Monster Cache 相关)

- `off_5226B60(a1, monster_ptr)` — Monster 销毁函数(类似 DestroyActor)
- `off_511C5B0(cache, index)` — cache 列表删除函数
- **`SpawnActor` 如何区分 Hero/Monster/Minion**?需找调用 SpawnActor 的上游

---

