# test.so 逆向分析报告(拆分索引)

> 原始文件 `test_so_INVESTIGATION_LEDGER.md`(112 KB)为方便浏览和版本管理,
> 按主题拆分为以下 13 个文件。

## 目录

| 文件 | 主题 |
|------|------|
| [`00-overview.md`](./00-overview.md) | 概述 + 引擎架构 + 库身份 (4.5 KB) |
| [`01-entry-points.md`](./01-entry-points.md) | 引擎入口 + 限制 + 操作规范 (6.8 KB) |
| [`02-mainloop.md`](./02-mainloop.md) | CBattleLogic::UpdateLogic 主调度循环 (3.8 KB) |
| [`03-session-and-actor-mgr.md`](./03-session-and-actor-mgr.md) | 会话管理 + CActorManager::UpdateLogic + 生命周期 + SpawnActor (9.2 KB) |
| [`04-monster-cache.md`](./04-monster-cache.md) | CActorManager::UpdateMonsterCache (2.1 KB) |
| [`05-hero-info.md`](./05-hero-info.md) | HERO_INFO 完整结构 (4.7 KB) |
| [`06-hero-controler.md`](./06-hero-controler.md) | HeroControler::UpdateLogic (4.9 KB) |
| [`07-hero-pos-api.md`](./07-hero-pos-api.md) | GetHeroInfo + 视野混淆 + 命中判定 (11.8 KB) |
| [`08-can-hit.md`](./08-can-hit.md) | CanHitTarget / GetNorAtkTarget 真实坐标读取 (6.7 KB) |
| [`09-real-pos-source.md`](./09-real-pos-source.md) | MovementComponent::UpdateLogic + 真实坐标写入链 (8.0 KB) |
| [`10-offline-scan.md`](./10-offline-scan.md) | 离线扫描找到真实坐标写入源 (8.5 KB) |
| [`11-got-resolution.md`](./11-got-resolution.md) | 重定位表解出所有 GOT slot 真实地址 (12.9 KB) |
| [`12-stable-pointer-chain.md`](./12-stable-pointer-chain.md) | 闭环总结 + 稳定指针链 + 待回答问题 (26.3 KB) |

## 完整指针链(最核心结论)

```
GameRoot (g_game_root @ 0x52717b0, .data 段)
  → + 904   = CActorManager*
  → + 11888 = HeroEntry[]  (vector,每项 32 字节)
  → +8       = Hero*       (每项 1008 字节)
  → +32 / +40 / +44 = real_x (int32) / real_y (int32) / real_z (int16)
```

**永不被视野混淆影响** (ViewManager 只改 +28/+36 display_x/y,不动 +32/+40/+44)。

## 相关文件

- `test_so_evidence_v12_StablePointerChain_FINAL.json` — REA Evidence bundle(可恢复完整分析)
- `_reloc_lookup.py` — 关键脚本:`.rela.dyn` 重定位表 1 秒解所有 GOT 真实地址
- `_scan_str_hero_pos.py` / `_scan_triples.py` — 离线 capstone 扫描,定位写入点
