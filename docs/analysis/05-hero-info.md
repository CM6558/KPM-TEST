<!-- 05-hero-info.md - 自动拆分自 test_so_INVESTIGATION_LEDGER.md -->
<!-- 内容: HERO_INFO 完整结构 -->

## 11. ★★★ HERO_INFO 完整结构(已完整破解 — 英雄全部信息)

### 11.1 EscapeFromPosSkill(AI Voice 逃生算法)

**函数地址**: `sub_4A95880 @ 0x4a95880`  
**Evidence**: `ev_7f8743306dac939700273c292133abb6a176381769685ceacb934266d56881f5`

**铁证**: 内部 log 包含 `"EscapeFromSkill_aivoice::EscapeFunc::EscapeFromPosSkill"` 命名空间 + `"main_hero_pos -- x:%d, y:%d, z:%d"` 字符串

#### 关键发现
- 英雄坐标 = **int[3] 数组 (x, y, z)**,单位是**厘米**(代码中 `/100` 转 float 米)
- 这是 **腾讯 AI Voice**(智能解说)模块的**技能逃生位置算法**(纯几何:求圆-圆切点 + 二次方程的根)

### 11.2 SGCore::HERO_INFO 单例

**函数地址**: `sub_25AC15C @ 0x25ac15c`  
**Evidence**: `ev_ce6db9beccc9f4632508b5fcab2d7175bb07aaf6b9d1fd0648c753ca42dd2723`

```cpp
// qword_53DEF90 = SGCore::HERO_INFO 单例指针
// 第一次访问时 new(0x178 = 376 bytes) 分配
// 注册 20 个字段(off_5009358=字段名表, off_5009360=类型表, 20LL=字段数)
```

### 11.3 ★★★ HERO_INFO 完整字段映射(SituationAnalyze dump 函数破解)

**函数地址**: `sub_248256C @ 0x248256c`  
**Evidence**: `ev_f57b95a10ad2e3a61573c2ca60953fa7daf45c3234a0919a7156682f7bffb95e`  
**模块**: **`SituationAnalyze`(局势分析,AI Voice 用)**

#### 完整字段表(高可信度,从 log format + 偏移参数对照反推)

| 偏移 | 类型 | 字段名 | 说明 |
|------|------|--------|------|
| `a2+0`   | DWORD | **camp** | 阵营(蓝/红) |
| `a2+4`   | DWORD | **config_id** | 英雄配置 ID(hero_cid) |
| `a2+8`   | DWORD | **runtime_id** | 运行时 ID |
| `a2+12`  | DWORD | **killCnt** | 击杀数 |
| `a2+16`  | DWORD | **deadCnt** | 死亡数 |
| `a2+20`  | DWORD | **assistCnt** | 助攻数 |
| `a2+24`  | DWORD | **moneyCnt** | 金币累计(?) |
| `a2+28`  | DWORD | **level** | 当前等级 |
| `a2+32`  | DWORD | **hero_position** ★ | 英雄位置 enum(0=上单/1=中单/2=下路/3=打野/4=辅助) |
| **`a2+36`** | **DWORD** | **hero_x** ★ | 英雄 X 坐标(int,厘米单位) |
| **`a2+40`** | **DWORD** | **hero_y** ★ | 英雄 Y 坐标 |
| **`a2+44`** | **DWORD** | **hero_z** ★ | 英雄 Z 坐标 |
| `a2+48`  | DWORD | **hp_ratio** | HP 比例 |
| `a2+52`  | DWORD | **ep_ratio** | EP(蓝)比例 |
| `a2+56`  | DWORD | **revive_time** | 复活时间(秒) |
| `a2+64`  | EQUIP_ITEM* | equipment_list begin | 装备数组开始 |
| `a2+72`  | EQUIP_ITEM* | equipment_list end | 装备数组结束 |
| — 每项 8 字节: | `{DWORD config_id, DWORD cooldown}` |
| `a2+88`  | DWORD* | camp_visible_bitmap | 阵营可见性位图数组 |
| `a2+96`  | QWORD | camp_visible_n | 阵营可见项数 |
| `a2+112` | SKILL_ITEM* | skill_list begin | 技能数组开始 |
| `a2+120` | SKILL_ITEM* | skill_list end | 技能数组结束 |
| — 每项 16 字节: | `{DWORD config_id, DWORD level, DWORD cooldown, DWORD slot_type}` |
| `a2+136` | INT* | buff_list begin | Buff 状态数组 |
| `a2+144` | INT* | buff_list end | (每项 4 字节 config_id) |
| `a2+160` | BYTE | **fuhuojia_is_usable** | 复活甲可用标识 |
| `a2+164` | DWORD | **blood_change_ratio** | 血量变化率 |
| `a2+168` | HURT_INFO* | take_hurt_infos begin | 受伤信息 |
| `a2+176` | HURT_INFO* | take_hurt_infos end | (每项 12B: runtime_id+value+ratio) |
| `a2+192` | HURT_INFO* | do_hurt_infos begin | 造成伤害信息 |
| `a2+200` | HURT_INFO* | do_hurt_infos end | |
| `a2+220` | DWORD | **kill_tower_cnt** | 推塔数 |
| `a2+224` | DWORD | **money** | 当前金币 |
| `a2+228` | DWORD | **phy_atk** | 物理攻击 |
| `a2+232` | DWORD | **phy_def** | 物理防御 |
| `a2+236` | DWORD | **mgc_atk** | 法术攻击 |
| `a2+240` | DWORD | **mgc_def** | 法术防御 |

**对象总大小**: 376 字节(0x178,与 `operator new(0x178uLL)` 匹配)

### 11.4 SituationAnalyze 模块识别

模块内部日志标签:`"SituationAnalyze"` — 这是 AI Voice 的局势分析子模块:
- 收集所有英雄信息(camp/level/HP/位置/装备/技能/Buff/伤害)
- 给 AI 解说系统做实时播报判断("XXX 残血"、"XXX 拿到一血"、"XXX 经济领先 XX 金"等)

### 11.5 HERO_INFO 关键访问全局

- `qword_53DEF90` = **SGCore::HERO_INFO 单例指针**
- `off_5009358` = 字段名表(指向 const char* 数组)
- `off_5009360` = 字段类型表
- `off_50694B0` = HERO_INFO 注册器函数指针

### 11.6 英雄坐标的源(待挖)

`sub_4A95880`(`EscapeFromPosSkill`)的 a3 参数 = main_hero_pos 数组,**谁调用这个函数谁就是英雄坐标的实际源头**:
- 期望找到调用方 → 拿到英雄坐标的 getter
- 候选:GetMainHero() / HeroControler 类的 GetPosition()

---

