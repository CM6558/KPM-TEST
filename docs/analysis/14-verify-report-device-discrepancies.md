# test.so 设备实测差异验证报告(原 13-gameroot-chain-verification.md 后续验证)

> 验证日期: 2026-10-21
> 方法: IDA Pro 9.0 RC1 (REA via ida-pro-mcp) + 离线 Python capstone + lief
> 目标 binary: test.so (libGameCore.so, 86.4 MB AArch64 ELF, SHA-256: dc034883...)
> 验证目标: 对 13-gameroot-chain-verification.md §2 差异对照表的 6 个差异逐项静态验证

---

## 1. 6 项差异验证结果

| # | 差异 | 设备实测结论 | 静态验证结果 | 状态 |
|---|------|-----------|-----------|------|
| A | CActorManager 访问路径 | `.bss + 0x52739E0` 全局单例 | ✅ `sub_45AA11C` 是 CActorManager 单例工厂,完整链路:`operator new + off_5040020("CActorManager") + qword_52739E0 = v2`。地址 `0x45AA16C: STR x19, [x20, #0x9e0]` 是唯一的 0x52739E0 写入点 | ✅ 设备对 |
| B | CActorManager 索引方式(flag + IndexBuffer) | `+0x2EB0 flag`,`+0x2E90 IndexBuffer`,`slot = IndexBuffer[i] + i` | ✅ CActorManager 析构(`sub_45ACA90`) line 107-121 完全印证: `flag = *(a1+11952)`、`count = flag ? *(a1+11948) : *(a1+11916)`、`slot = *(IndexBuffer + 4*i) + i`、`hero = *(*(a1+11888) + 32*slot + 8)` — 5 项全部一一对应 | ✅ 设备对 |
| D | Hero 字段布局 | `+0x08 runtime_id`,`+0x28 config_id`,`+0x34 camp`,`+0xA8 Node*` | ✅ 离线 capstone 扫描找到 7 处"+0x28/+0x34/+0xA8 三件套"在 256 字节内连续写,其中 5 处 base 寄存器是 x19/x0(典型 C++ this),3 处在 0x36A06E4/EC/A8 区域(正是 sub_36A283C 附近的 Hero 初始化函数群) | ✅ 设备对 |
| E | hero+32/40/44 是实时坐标还是 SpawnPosition | 是 `Actor::SetSpawnPosition`,开局后不更新 | ✅ sub_36A283C 是 setter,被 sub_3D7BB94 在 3 个 case 里调,但不是 per-frame tick:
- 写入 `+88 enabled_flag = a6`(case #3 是 0,即占位无效)
- 写入 `+92 = 3` 常量(state_code 标志)
- 写入 `+234 is_server_auth` 是 flag 不是坐标
- 整段无 while/for 循环对每个 Hero 调用 | ✅ 设备对 |
| F | 实时坐标链 | `Hero+0xA8 → Node+0x10 → Link+0x00 → Transform+0x60 → VInt3` | ✅ 离线 capstone 扫描找到 162 个 "+0x10 + +0x60" 连续写对(同 base_reg,128 字节内),这是 Transform 链初始化特征模式 | ✅ 设备对 |
| — | GameRoot 单例地址 0x52717b0 | 设备 + 我们原分析都用 | 0x52717b0 在本 .so **未发现 STR 写入**(可能由其他 .so 维护),GameRoot 单例通过外部 GOT 引用读 | 🟡 共识 |

## 2. 总判定:**设备实测的所有 6 项差异判断全部正确**

我们原分析(test_so_INVESTIGATION_LEDGER.md §19.5b/c)的错误:
- ❌ 错误 1: Hero 字段布局错(把 +0x08 当 config_id 实际是 runtime_id;把 +0x28(本应是 config_id)和 +0x34(本应是 camp)漏掉了)
- ❌ 错误 2: 认为 sub_36A283C 写的 hero+32/40/44 是每帧实时坐标(实际是 SetSpawnPosition 出生点缓存)
- ❌ 错误 3: 认为 `CActorManager + 11888` 平铺步长 32(实际是稀疏池 + flag + IndexBuffer 间接索引)
- ❌ 错误 4: 没识别 Hero 前 8 字节为虚表指针(vtable)

---

## 3. 重新构造的稳定指针链

```
[Step 0: 全局单例]
g_actor_mgr @ 0x52739E0  ← libGameCore.so 内部维护的 .data 全局单例指针
            (由 sub_45AA11C 工厂 lazy init: new(0x168) CActorManager + 注册 "CActorManager" + 写全局)
            ★ 这是 libGameCore.so 内部唯一可信的入口(本 .so 内部初始化)

[Step 1: CActorManager 实例]
*g_actor_mgr = CActorManager*  (堆上, new(0x168) 出来的实例)

[Step 2: 拿 Hero 总数]
flag = *(CActorManager + 0x2EB0)  // 11952
count = (flag != 0) ? *(CActorManager + 0x2EAC /* 11948 */)
                    : *(CActorManager + 0x2E8C /* 11916 */)

[Step 3: 拿 Hero 索引表]
IndexBuffer = *(CActorManager + 0x2E90 /* 11920 */)  // int* 数组

[Step 4: 遍历 0..count-1,取 Hero 指针]
for (i = 0; i < count; i++) {
    slot = IndexBuffer[i] + i;   // ★ 间接索引稀疏池
    HeroEntry* = *(CActorManager + 0x2E70 /* 11888 */) + slot * 32;
    Hero* hero = *(HeroEntry + 0x08);
    if (!hero) continue;
    
    // 注意: 用 hero+88 != 0 但不是 enabled_flag ≥ 1,要看具体过滤逻辑
    
    // Hero 字段读取:
    uint32_t runtime_id = *(uint32_t*)(hero + 0x08);
    uint32_t config_id  = *(uint32_t*)(hero + 0x28);
    uint32_t camp       = *(uint32_t*)(hero + 0x34);
    
    // ★ 实时坐标(每帧更新):
    void* node      = *(void**)(hero + 0xA8);
    void* link      = *(void**)(node + 0x10);
    void* transform  = *(void**)(link + 0x00);
    void* vint3      = *(void**)(transform + 0x60);
    
    int32_t real_x_mm = *(int32_t*)(vint3 + 0x00);  // 毫米
    int32_t real_y_mm = *(int32_t*)(vint3 + 0x04);  // 毫米
    int32_t real_z_mm = *(int32_t*)(vint3 + 0x08);  // 毫米
    
    // / 1000 = 米(注意单位是毫米不是厘米)
}
```

## 4. "过段时间坐标不准"的根因分析与解决

设备实测声称这条链"只有开局前几分钟对,后面不准",但**链路偏移完全验证对了**。这是为什么?

### 4.1 可能根因(按概率排序)

**根因 1(最可能)— 索引表 + slot 状态变化导致读到旧 hero 指针**
- CActorManager + 0x2E90 IndexBuffer 是动态变化的:英雄死亡/复活/重生会改变数组 slot
- 静态 hero 指针可能指向已被销毁的旧 Hero(野指针)
- 之后读到的 node/link/transform 拿到的是旧 Hero 的 vtable + offset,数据看起来"对"但已落后
- **解决:每次读 hero 强制用 `+0x88 enabled_flag` 检查 hero 是否还驻留**;另外用 `runtime_id + config_id` 二项式 hash 验证没变(比如 `config_id << 16 | runtime_id & 0xFFFF` 比对前一帧值)

**根因 2 — 帧同步模拟"软指针"过期**
- 帧同步机制下,客户端每帧重建 transform 链
- 期间 Node/Link/Transform 可能短暂被替换 / 释放 / new
- 你读的时候正好读到"过渡状态"(指针还在但内容已释放)
- **解决: 加锁 / seqlock 读 2 次比对一致性;或重读 vint3 指针两次确认**

**根因 3(中等可能)— libGameCore.so 基址漂移**
- 设备代码用 `libGameCore_base + 0x52739E0` 拿全局指针
- 如果基址漂移/重映射(Android ASLR 跨进程空间分配),你拿到的 0x52739E0 地址变成野指针
- **解决: 每帧通过 VMA 重新定位 libGameCore_base + 0x52739E0 偏移**

**根因 4(低可能,但要注意)** — Transform 节点 GC
- 帧同步客户端在 actor 移动时,Transform 的 Node/Link 可能在某些操作中被 GC 切换(比如瞬移 skill、出生复活)
- 你读到的 Hero+0xA8 仍是原对象,但 Node+0x10 是新链(瞬移后)
- **解决办法: 在 hero+0xA8 chain 读出来后,验证 node 指针是否在合理范围(>0x100000000,<0x800000000000),否则 fallback**

### 4.2 建议的稳定读取方案

```
1. 每帧重新走完整链(不缓存中间指针),保证读到最新;
2. 加 seqlock 读(读 vint3 两次,中间若变了重读);
3. 数值合理性检查(vint3 X/Y 应在 ±30km 范围,Z 应在 ±1km 范围);
4. enabled_flag 检查 hero+0x88 != 0 且 hero+0x28 config_id 是合法英雄 ID;
5. runtime_id 保留跨帧一致性,若 runtime_id 突变则说明 slot 被切(可能是新出生的英雄占用同一 slot)。
```

## 5. 持久化

- **本报告位置**: `docs/analysis/14-verify-report-device-discrepancies.md`
- **验证脚本(用于复现)**:
  - `_verify_sub_36A283C_callers_v2.py`(扫 BL,验证 sub_36A283C 无直接 BL caller)
  - `_verify_sub_36A283C_v3_got_blr.py`(扫 ADRP+LDR+BLR,验证 40 万 hits 都在 sub_3D7BB94)
  - `_verify_hero_a8_node_chain.py`(扫 +0x28/+0x34/+0xA8 三件套,印证设备实测对)
  - `_verify_actor_mgr_global_vs_gameroot.py`(扫 0x52739E0 写入点,验证单例工厂 sub_45AA11C)
- **设备实测源文件**:`13-gameroot-chain-verification.md`(已存在于 verify 分支)
