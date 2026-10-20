<!-- 08-can-hit.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: CanHitTarget / GetNorAtkTarget 真实坐标读取 -->

## 15. ★★★ CanHitTarget / GetNorAtkTarget(已分析 — 技能命中 + 真实坐标读取)

### 15.1 CanHitTarget 函数

**函数地址**: `sub_2801AE4 @ 0x2801ae4`  
**Evidence**: `ev_7fa3f63204975c86a7833a7573ed265cc781400d2968592d7eee3afea0bdcf3c`

```cpp
// Line 73: ★★★ off_517F388 距离计算 + 坐标抽取
v30 = off_517F388(a1 + 124, v44, a3 + 1, 1LL);
//   - a1+124 = main_hero_ptr  (真实英雄对象)
//   - v44    = 输出 main_hero 真实坐标缓冲区(104 DWORD)
//   - a3+1   = target 真实坐标 +4 偏移(即 target.real_x)
//   - 1LL    = 模式 flag

// Line 76-84: log(同 CheckHitTarget)
log("[CanHitTarget] main_hero:%d,%d, target_id:%d, target_pos:%d,%d",
    v44[0],   // main_hero real_x
    v44[2],   // main_hero real_y
    *a3,      // target runtime_id  
    a3[1],    // target real_x  (target+4)
    a3[3]);   // target real_y  (target+12)

// Line 86: 距离 log
log("[CanHitTarget] dist: %d, skill_atk_range: %d", v31, v29/100);

// Line 87: ★★★ 命中判定
return dist < skill_atk_range;
```

### 15.2 GetNorAtkTarget 函数

**函数地址**: `sub_277CA74 @ 0x277ca74`  
**Evidence**: `ev_75f6d529a41ed9e1635edf9c8d89d531022359d937f229d4155de3a1c9bdf56e`

**关键证据 — main_hero 真实坐标存于 hero+32 和 hero+40!**

```cpp
// Line 97-114: 在英雄 584 上做距离判定
v49 = *(_QWORD *)(a1 + 448);   // main_hero_ptr
if (*(_DWORD *)(v49 + 4) == 584) {                       // config_id == 584
    v25 = off_517FFC8(v13, v49, 584108LL);              // check skill 584108
    if (v25) {
        // ★★★ 真实坐标距离计算 — main_hero+32 vs target+4
        v25 = off_517F388(v13, *(_QWORD *)(a1 + 448) + 32LL, a5 + 1, 1LL);
        //                                ↑ main_hero+32 = real_x!
        v50 = 1374389535LL * *(int *)(*(_QWORD *)(a1 + 448) + 84LL);
        //                                 ↑ main_hero+84 = 比例因子
        
        if ((int)v25 > (int)((v50 >> 37) + ...)) {
            // ★★★ log 验证:main_hero+32, main_hero+40
            log("[GetNorAtkTarget] quit normatk, main_hero_loc:%d,%d target_id:%d",
                *(_DWORD *)(*(_QWORD *)(a1 + 448) + 32LL),    // ★ main_hero+32 = real_x
                *(_DWORD *)(*(_QWORD *)(a1 + 448) + 40LL),    // ★ main_hero+40 = real_y
                *a5);
        }
    }
}

// Line 124-131: NorAtkTarget 结构验证
log("[GetNorAtkTarget] target_id:%d, target_pos,x:%d, y:%d, z:%d",
    *a5,    // a5[0] = runtime_id
    a5[1],  // ★ Target.real_x  (target+4)
    a5[2],  // ★ Target.real_y  (target+8)
    a5[3]); // ★ Target.real_z  (target+12)
```

### 15.3 ★★★ Hero 对象完整最终布局(三重验证)

```cpp
struct Hero {
    +4:    config_id              (DWORD)   ★ (所有函数验证)
    +8:    runtime_id             (DWORD)   ★
    +20:   some_id                (DWORD)
    +28:   display_x              (DWORD)   // ★ 视野混淆后的 X(发给敌方客户端)
    +32:   ★★★ real_x            (DWORD)   // ★★★ 真实 X 坐标(厘米)
    +36:   display_y              (DWORD)   // ★ 视野混淆后的 Y(发给敌方客户端)
    +40:   ★★★ real_y            (DWORD)   // ★★★ 真实 Y 坐标(厘米)
    +44:   real_z                 (DWORD)   // 真实 Z 坐标(从 GetPosFromHero v27=*(hero+40) 推出,可能 +44)
    +84:   atk_range_factor      (int)     // 攻击范围比例因子
    +88:   enabled_flag           (int ≥1)  // slot 有效标志
    +560:  bitmask_table         (PTR)
    +568:  bitmask_size           (QWORD)
    +712:  is_in_grass          (BYTE)    // (ViewManager 用)
    +856:  is_in_grass_2        (BYTE)    
    +880:  mode_flag              (DWORD/byte)
    // Hero 数组步长 = 1008 字节
};

struct NorAtkTarget {
    +0:   runtime_id  (DWORD)
    +4:   real_x      (DWORD)   ★
    +8:   real_y      (DWORD)   ★
    +12:  real_z      (DWORD)   ★
};
```

### 15.4 ★★★ 真实坐标 vs 显示坐标分离(重大发现)

```
真实坐标(服务端权威):
  hero+32: real_x
  hero+40: real_y
  hero+44: real_z(待最终验证)

显示坐标(发给敌方客户端):
  hero+28: display_x  (ViewManager 修改此值混淆)
  hero+36: display_y  (ViewManager 修改此值混淆)
```

**重要**:ViewManager::ModifyEnemyInvisibleHeroPosition 的 `*(QWORD*)(hero+28) = 50000LL` 是 同时写 hero+28 和 hero+32,这其实是 "同时把 display_x 和 real_x 设为 50000"(因为 little-endian 64 位写)。这是**英雄彻底"移到地图外"**的硬切换,不是常规混淆。常规混淆只改 hero+28 / hero+36 不动 hero+32。

但 `ModifyEnemyInvisibleHeroPositionByTimeDynamic` 的实现可能不同 — 它可能只改 display 而保留 real,后续需验证。

### 15.5 Hero 坐标读取 API 入口(已知)

- ★ `off_517F388(main_hero_ptr, output_buffer, target_ptr+1, 1LL)` — 距离计算 + main_hero 真实坐标读入 buffer[0]/buffer[2]

调用位置:
- `CanHitTarget` @ 0x2801ae4 line 73
- `CheckHitTarget` @ 0x2801828 line 77
- `ViewManager::ModifyEnemyInvisibleHeroPosition` @ 0x24ad7fc line 89 (使用 main_hero+32, enemy+32 比较)
- `GetNorAtkTarget` @ 0x277ca74 line 103 (使用 main_hero+32, target+4)
- `game_aivoice::AiProcess::ModifyEnemyInvisibleHeroPosition` @ 0x2a2eb54 (类似)

### 15.6 战场目标 ID 584 + 技能 584108(待挖)

config_id 584 是个特殊英雄(GetNorAtkTarget 特判):可能与某游戏机制关联
- 584108 = 584_108(英雄 584 的技能 1,08 号?)

### 15.7 重要参数对照表

| 字符串地址 | 内容 | 用途 |
|----------|------|------|
| `0x113f4fa` | `[ParseTargetLabel] target_id:%d, target_pos,x:%d, y:%d, z:%d` | 解析目标标签(4 坐标)|
| `0x1160370` | `[ParseNorAtkLabel] target_id:%d, target_pos, x:%d, y:%d, z:%d` | 普攻标签 |
| `0x1179a92` | `[GetNorAtkTarget] target_id:%d, target_pos,x:%d, y:%d, z:%d` | 获取普攻目标 |
| `0x11bfcbc` | `[GetNorAtkTarget] target_id:%d, target_pos,x:%d, y:%d, z:%d` | (另一处)|
| `0x11a774a` | `[CanHitTarget] main_hero:%d,%d, target_id:%d, target_pos:%d,%d` | 命中判定 |
| `0x11e069d` | `[CheckHitTarget] main_hero_pos:%d,%d, dist: %d, skill_atk_range: %d` | 命中检查 |
| `0x1208247` | `[CheckHitTarget] target id:%d, pos:%d,%d` | 目标位置 |
| `0x116b357` | `frame: %d, ssg: %s -> main_hero: %d set target_pos: %d` | SSG 设目标 |
| `0x11734e2` | `target_id:%d, target_pos,x:%d, y:%d, z:%d` | 通用目标 log |
| `0x11c5c6b` | `frame:%d camp:%d hero:%d(%d, %d) atk_pos:(%d, %d)` | 攻击位置 |
| `0x1185eb8` | `[Teaching] ai instruction rule %d, after search target pos_location:(%d,%d,%d), target_location:%d,%d,%d` | AI 教学(规则 + pos)|
| `0x11a0492` | `target_position=(%d, %d)` | 目标位置 |

---

