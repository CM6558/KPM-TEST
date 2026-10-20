<!-- 07-hero-pos-api.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: GetHeroInfo + 视野混淆 + 命中判定 -->

## 13. ★★★ ssg::SSGHelper::GetHeroInfo(已分析 — 英雄信息批量收集)

**函数地址**: `sub_4ACF828 @ 0x4acf828`  
**Evidence**: `ev_ba031731269c2b95e1a5252ac36e6661a2a1d96a06564b36e584190c137d49af`

**铁证**:函数末尾 log `"ssg::SSGHelper::GetHeroInfo"` + `"hero_runtime_id.size() != 10 or hero_config_id.size() != 10, size:%d,%d"` —— 硬编码验证数组大小为 10

### 签名(反推)

```cpp
bool SSGHelper::GetHeroInfo(
    SSGHelper* this,        // a1
    void* context,          // a2
    HeroInfoOutput* output, // a3 - 输出,包含两个 vector<int>(config_ids + runtime_ids)
    HeroQuery* query        // a4 - 过滤条件 ({camp_id, config_id, ...})
)
```

### 主要工作流程

```cpp
// 第一阶段 (Line 91-103): 初始化 output 容器,设置 begin=end=start of arrays
a3[681] = a3[680];  // config_ids begin = start
a3[684] = a3[683];  // runtime_ids begin = start

// 第二阶段 (Line 104-322): ★ 遍历 SSGHelper 内部红黑树(a3[480])
//   按 camp_id + config_id 二级过滤
//   树节点结构 (推断 56 字节):
//   - node[0] = left child
//   - node[1] = right child
//   - node[2] = parent
//   - node[5] = linked list begin
//   - node[7] (DWORD at offset 28) = camp_id  
//   - node[8] (DWORD at offset 32) = config_id 或 runtime_id

// 第三阶段 (Line 323-475): 把过滤后的英雄写入 output.config_ids 数组
//   vector<int> grow logic(标准 SSO + realloc 模式)
//   如果 v34 == -1,用 query.config_id 做 default

// 第四阶段 (Line 477-591): 类似处理另一个红黑树,写入 output.runtime_ids

// 第五阶段 (Line 592-606): ★ 校验
if (runtime_ids.size() != 10 || config_ids.size() != 10) {
    log("ssg::SSGHelper::GetHeroInfo",
        "hero_runtime_id.size() != 10 or hero_config_id.size() != 10, size:%d,%d",
        runtime_ids.size(), config_ids.size());
    return false;
}
return true;
```

### SSGHelper 状态对象布局(部分推导)

| 偏移 | 类型 | 含义 |
|------|------|------|
| `a3[480]` | PTR | 红黑树根节点 1(按某键组织) |
| `a3[481]` | sentinel? | end iterator(树尾哨兵) |
| `a3[680]` | PTR | **config_ids vector begin**(运行时 ID 的 begin/end/capacity) |
| `a3[681]` | PTR | config_ids end(下一个写位置) |
| `a3[682]` | PTR | config_ids capacity end |
| `a3[683]` | PTR | **runtime_ids vector begin** |
| `a3[684]` | PTR | runtime_ids end |
| `a3[685]` | PTR | runtime_ids capacity end |

### ★★★ 重大确认 — 这是 MOBA 5v5(实锤)

- **硬编码**:两个数组必须各 10 个元素
- 10 = 5(players per camp) × 2(camps)
- **这是 MOBA 5v5 战场布局**,配合之前的 `USGMoba55` 命名,实锤《王者荣耀》 MOBA 特征

### 与 SituationAnalyze 的对应

- SituationAnalyze 每帧调用的 HERO_INFO 收集 → 最终应该调到这个函数拿 10 个英雄
- 然后对每个英雄(a2+0 的 HERO_INFO 结构)填充字段,组成全集
- 然后 AI Voice 模块根据全集做实时播报判断

---

## 14. ★★★ game_aivoice::AiProcess::ModifyEnemyInvisibleHeroPosition(已分析 — 隐身英雄位置混淆)

**函数地址**: `sub_2A2EB54` 或更大函数(986行,**本会话最长**)
**Evidence ID**: `ev_46450188f963edaa9dd2ab76fcb913586842f13d6e52f97b5ca6959c1413390a`

注:实际上这个 evidence ID 对应包含 `mian_hero[%d-%d-%d] tgt_hero[%d-%d-%d]` log 的 986 行函数

### 铁证字符串

```
"game_aivoice::AiProcess::ModifyEnemyInvisibleHeroPosition"
"lanlingwang use skill3, invisible, real_location = (%d,%d), main_hero_location = (%d, %d)"
"lanlingwang use skill3, invisible, modified location = (%d,%d), main_hero_location = (%d, %d)"
"lanlingwang use skill3, invisible and far to main hero, real location = (%d, %d), modified location = (50000, 50000)"
"lanlingwang use skill3, invisible and far to main hero, real location = (%d, %d), modified location = (-50000, -50000)"
"ake use skill3, invisible, real_location = (%d,%d), modify to (%d,%d)"
"ake use skill3, invisible and dist to main hero < 100, real location = (%d, %d), main_hero_location = (%d, %d)"
"ake use skill3, invisible and dist to main hero < 100, modified_location = (%d, %d), main_hero_location = (%d, %d)"
"ake use skill3, invisible and dist to main hero > 100, real location = (%d, %d), modified_location = (50000, 50000)"
"ake use skill3, invisible and dist to main hero > 100, real location = (%d, %d), modified_location = (-50000, -50000)"
"hero config_id = %d, may in grass, real location = (%d, %d), main_hero_location = (%d, %d)"
"hero config_id = %d, may in grass, modified location = (%d, %d), main_hero_location = (%d, %d)"
"mian_hero [%d-%d-%d] tgt_hero [%d-%d-%d] cur_frame %d, last_invisible_ingrass %d --> visible_ingrass less than 6 frame"
"hero:%d loc:(%d, %d) invisible2visible change to 55000"
"hero:%d loc:(%d, %d) invisible2visible delay:%d change to 50000"
"hero:%d invisible2visible"
"hero config_id = %d, may in grass, real location = (%d, %d), modified location = (50000, 50000)"
"hero config_id = %d, may in grass, real location = (%d, %d), modified location = (-50000, -50000)"
"position_of_enemy_ake_in_past_1s is NULL now, call it later, frame_no:%d"
```

### 英雄坐标字段最终确认(高置信度)

```cpp
hero+4:   config_id     (DWORD)  // 英雄配置 ID
hero+8:   runtime_id    (DWORD)  // 运行时 ID
hero+20:  ???           (DWORD)  // 阵营或某 ID
hero+28:  ★ hero_x      (DWORD)  // 英雄 X 坐标(厘米,int)
hero+32:  ???           (DWORD)  // (可能是 hero_x 高位 / 或某 4 字节字段)
hero+36:  ★ hero_y      (DWORD)  // 英雄 Y 坐标(厘米,int)
hero+40:  ★ hero_z      (DWORD)  // 英雄 Z 坐标(厘米,int)
hero+88:  enabled_flag  (int ≥1) // slot 有效标志
hero+712: is_in_grass   (BYTE)   // 是否在草丛(或 v3+712)
hero+856: is_in_grass   (BYTE)   // (ViewManager::ModifyEnemyInvisibleHeroPosition 中用)
// 注意:712 vs 856 偏移可能是不同结构 — 一种可能是 Hero,另一种可能是 Hero in array
```

注:
- `*(QWORD*)(hero+32)` 把 hero+32/36 当 8 字节合并读,实际上 little-endian 64 位读 = 高位 hero+36 低位 hero+32。可能 hero+32 是一个 8 字节 packed struct,前 4 字节=X 后 4 字节=Y

### 位置混淆算法(防作弊核心)

#### 1. 兰陵王(lanlingwang)技能3隐身

```cpp
// Main Hero 距离 ≤ 79 (单位"厘米"近似距离)
if (distance_to_main_hero <= 79) {
    // 近距离:微调位置(±4000 范围)
    add_x = (random_0_50_minus_25 / 100) * 4000 * sign(dx)   // ±4000 cm = ±40m
    add_y = (random_0_50_minus_25 / 100) * 4000 * sign(dy)
    hero_x += add_x
    hero_y += add_y
}
else if (*v7 == 1) {
    // 远距离 + v7=1:完全隐藏到 (50000, 50000) — 即 (500m, 500m)
    *(_QWORD *)(v3 + 28) = 50000LL;   // 把 hero+28 和 hero+32 同时写
    *(_DWORD *)(v3 + 36) = 50000;     // hero+36 也写 50000
}
else {
    // 远距离另一条件:隐藏到 (-50000, -50000)
    *(_QWORD *)(v3 + 28) = 4294917296LL;   // = 0xFFFFFFFFFFFF3CB0 = -50000 packed
    *(_DWORD *)(v3 + 36) = -50000;
}
```

#### 2. 阿轲(ake)技能3隐身

```cpp
// 取 "position_of_enemy_ake_in_past_1s" 表(过去1秒 ake 的位置历史)
v111 = *(_QWORD *)(v4 + 2456);
table_entry = off_5089210(v111, &frame_no);

if (table_entry != v111 + 8) {
    // 找到历史位置:把 ake 当前位置改为过去的位置(混淆)
    *(_DWORD *)(v3 + 36) = *(_DWORD *)(table_entry + 40);  // historical hero_y
    *(_QWORD *)(v3 + 28) = *(_QWORD *)(table_entry + 32);    // historical hero_x (8 bytes)
}
else if (distance ≤ 99) {
    // 与 main hero 距离<100(近): 微调位置 ±8888(=88m,更大幅度的抖动)
    add_x = random_0_50_minus_25 / 100 * 8888
    add_y = random_0_50_minus_25 / 100 * 8888
    hero_x += add_x; hero_y += add_y;
}
else if (*v7 == 1) {
    // 远距离: (50000, 50000)
}
else {
    // 远距离另一条件: (-50000, -50000)
}
```

#### 3. 草丛算法

```cpp
// hero+712 = is_in_grass (byte)
// v83 = config_id
if (v83 == 196 && distance ≤ 29 && main_hero_in_grass) {
    log("hero config_id: %d, is_in_grass: %d, main_hero config_id: %d, is_in_grass: %d, dist: %d", ...)
    return; // 不修改位置,只 log
}

// 否则:if (*v104[8] <= 150 && frame - last_seen ≤ grace_period):
srand(time(0))
rand_x_offset = (rand() % 50 - 25) / 100.0  // [-0.25, 0.25]
srand(time(0)+1)
rand_y_offset = (rand() % 50 - 25) / 100.0
hero_x += (int)(rand_x_offset * 8888.0)  // ±2222 cm = ±22m
hero_y += (int)(rand_y_offset * 8888.0)
log("hero config_id = %d, may in grass, modified location = (%d, %d), ...")
```

### 关键魔法数字

| 数字 | 含义 |
|------|------|
| **50000** | (500m, 500m) 地图外隐藏位置 — 英雄"消失"的服务端真相 |
| -50000 | (-500m, -500m) 地图外反向隐藏 |
| 4000 | 兰陵王近距离抖动幅度(cm) |
| 8888 | 阿轲近距离抖动 + 草丛抖动幅度(cm) |
| 79 / 99 | 兰陵王/阿轲的"近距离"阈值(距离) |
| 150 | 草丛 grace period(帧数)|
| 29 | hero 在草丛距离阈值 |
| 6 | "visible_ingrass less than 6 frame" — 短暂露面阈值 |

### 关键字段引用(完整 hero 对象偏移更新)

| 偏移 | 类型 | 字段 | 来源 |
|------|------|------|------|
| +4 | DWORD | hero_config_id | 全局一致(所有函数都验证)|
| +8 | DWORD | runtime_id | 全局一致 |
| +20 | DWORD | 某基线 ID | ModifyEnemyInvisibleHeroPosition |
| +28 | DWORD | hero_x | ModifyEnemyInvisibleHeroPosition, log `real_location = (%d,%d)` |
| +32 | DWORD | (?可能是 X 的高位 / 或 packed struct 头) | GetPosFromHero 8字节合并读 |
| +36 | DWORD | hero_y | ModifyEnemyInvisibleHeroPosition |
| +40 | DWORD | hero_z | GetPosFromHero v27=*(DWORD*)(hero+40) |
| +88 | int | enabled (≥1) | GetPosFromHero, ModifyEnemyInvisibleHeroPosition |
| +560 | PTR | bitmask_table | ModifyEnemyInvisibleHeroPosition line 213 |
| +568 | QWORD | bitmask_size | line 212 |
| +712 | BYTE | is_in_grass | ModifyEnemyInvisibleHeroPosition line 590 |
| +856 | BYTE | is_in_grass | ModifyEnemyInvisibleHeroPosition (另一个偏移) - ViewManager |
| +1008 | size | hero_entry_total_size | 所有函数 step = 1008 |

### 2 个 is_in_grass 偏移之谜(未解)

- `+712` 和 `+856` 都用作 `is_in_grass`
- 可能:一个是"当前在草丛?",另一个是"长时间在草丛?"(配合 `longtime_ingrass_move`)
- 还可能是不同 Hero 子类(organ=+712, hero_subclass=+856)
- 待解:需要找赋值点确认

### Algorithm 总结(英文版)

```
ModifyEnemyInvisibleHeroPosition():
  For each hero in array (size=1008 bytes per hero):
    If hero is invisible:
      If is Lanlingwang (config_id == 153? or special check):
        If dist to main_hero <= 79:
          Add random offset ±4000 to (hero_x, hero_y)
        Elif v7 flag == 1:
          Move hero to (50000, 50000) — outside map
        Else:
          Move hero to (-50000, -50000)
      If is Ake (config_id == 116?):
        Look up position_of_enemy_ake_in_past_1s table
        If found: replace current pos with historical pos
        Elif dist <= 99:
          Add random offset ±8888
        Else:
          Move to (50000, 50000) or (-50000, -50000)
      If may be in grass:
        If grass flags set and dist <= 29:
          Don't modify, just log
        Elif frame - last_seen <= grace_period:
          Add random offset ±2222 (8888 * 0.25) to (hero_x, hero_y)
        Else:
          Move to (50000, 50000) or (-50000, -50000)
```

### 关键服务端机制发现 — 这是"视野防作弊"

**机制实质**:
- 服务端有所有英雄真实位置(`hero+28, +36`)
- 但发给敌方客户端的位置可能是混淆过的
- 隐身英雄(兰陵王/阿轲技能3)位置一定被混淆
- 草丛内但被推测可见的英雄位置也被混淆
- 混淆幅度:近距离(<100)用随机微调,远距离直接设到地图外(50000)
- **50000cm = 500m**:远超王者峡谷尺寸(~200m × 200m),客户端收到这个坐标会认为"看不见"

---

