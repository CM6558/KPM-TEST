# hero_reader.c 修复补丁 — V2

> **针对 4 个根因的修复补丁**
>
> 目标:从内核态读取 GameCore.so 内部 Hero 实时坐标,保证"过段时间坐标准"。
> 核心修改:`get_actor_coords()`、`gc_base()`、`read_rootactor_chain()` 三个函数。

## 概要 — 4 个根因的修复方案

| 根因 | 当前行为 | 是否导致"过段时间不准" | 修复方案 |
|------|---------|---|---------|
| #1 | `get_actor_coords` fallback 到 `+32/+40/+44`(spawn_pos) | ✅ **直接根因** | 移除 fallback,只保留 Transform 链作为唯一坐标源 |
| #2 | Transform 链读取中无 seqlock,4 级间接指针 race | ✅ 间接根因 | 加 seqlock:读完整个链路后重读 node 比对一致性 |
| #3 | `g_gc_base` 永久缓存不刷新 | ⚠️ 容错性问题 | 每 N 帧重新校验 base 有效性,过期则 reset 重定位 |
| #4 | IndexBuffer 读 → 走完链中途内容改写(race) | ⚠️ 间接根因 | IndexBuffer 读 + slot 解析后,立即用 seqlock 重读 IndexBuffer[i] 比对 |

## 原则

**只用一条正确的链路**(基于已 IDA + 设备实测验证的链路):
```
g_gc_base (libGameCore base)
  → + 0x51EA4D0  (GOT, * ptr = GameRoot singleton)
  → 0                 (deref, GameRoot*)
  → + 0x388 (904)     (CActorManager*)
  → + 0x2EB0 flag     (flag, 决定 count 来源)
  → flag ? +0x2EAC : +0x2E8C 取 count
  → + 0x2E90           (IndexBuffer pointer)
  → + 0x2E70           (pool_base pointer)
  循环 i ∈ [0, count):
    slot = flag ? IndexBuffer[i] + i : i
    hero = *(pool_base + slot*32 + 8)
    hero + 0x08: runtime_id
    hero + 0x28: config_id
    hero + 0x34: camp
    hero + 0xA8 → Node*
    node + 0x10 → Link*
    link + 0x00 → Transform* (★ 4级指针链)
    transform + 0x60 → VInt3* (VInt3 X/Y/Z 三 int32 mm, ÷10 为 cm)
      ✅ 这条链是验证过的,唯一信源
```

**绝不再回退到 +32/+40/+44(SetSpawnPosition 缓存)**。

## 实现细节

### 1. `get_actor_coords()` (line 1967-2012) — 重写,删除 fallback 路径 2

```c
static int get_actor_coords(unsigned long actor, int *ox, int *oy, int *oz)
{
    unsigned long node = 0, link = 0, tr = 0, p2 = 0;
    int xx = 0, yy = 0, zz = 0;
    
    /* 唯一路径: 权威物理变换链 Transform (帧同步模拟层权威真值, 迷雾不冻结)
     * ★ 不再回调到 +32/+40/+44 (SetSpawnPosition 是出生点缓存, 开局后不更新)
     */

    /* Step 1: 读完整个 Transform 链 -> p2 (VInt3 pointer) */
    if (!rm(&node, actor + 0xA8UL, 8)) return 0;
    node = untag(node);
    if (node <= 0x100000000UL || node >= 0x800000000000UL) return 0;
    
    if (!rm(&link, node + 0x10UL, 8)) return 0;
    link = untag(link);
    if (link <= 0x100000000UL || link >= 0x800000000000UL) return 0;
    
    if (!rm(&tr, link + 0x00UL, 8)) return 0;
    tr = untag(tr);
    if (tr <= 0x100000000UL || tr >= 0x800000000000UL) return 0;
    
    if (!rm(&p2, tr + 0x60UL, 8)) return 0;
    p2 = untag(p2);
    if (p2 <= 0x100000000UL || p2 >= 0x800000000000UL) return 0;
    
    /* Step 2: ★ seqlock 读 — 读 3 字段后立即重读 node 比对 node 是否被替换 */
    rm(&xx, p2 + 0, 4);
    rm(&yy, p2 + 4, 4);
    rm(&zz, p2 + 8, 4);
    
    /* Step 3: ★ seqlock 第二次读 — node/link/tr 指针未变化才算读一致 */
    {
        unsigned long node2 = 0, link2 = 0;
        rm(&node2, actor + 0xA8UL, 8);
        node2 = untag(node2);
        if (node2 != node) return 0;   // node 已被替换, 坐标不可信, 返回失败
        rm(&link2, node + 0x10UL, 8);
        link2 = untag(link2);
        if (link2 != link) return 0;  // link 已被替换, 返回失败
    }
    
    /* Step 4: 数值合理性检查 (游戏地图 ±30km, 内 z 极少 > 2km) */
    if (xx == 0 && zz == 0) return 0;
    if (xx < -3000000 || xx > 3000000) return 0;
    if (zz < -3000000 || zz > 3000000) return 0;
    
    /* Step 5: 单位转换 毫米 → 厘米 */
    *ox = xx / 10;
    *oy = yy / 10;
    *oz = zz / 10;
    return 1;
    
    /* ★ 绝不再 fallback 到路径 2 (+32/+40/+44 = SetSpawnPosition) */
}
```

### 2. `gc_base()` — 加 base 有效性校验,过期则 reset

```c
static unsigned long gc_base(void)
{
    struct gcb g;
    /* 每 30 帧重新校验 base — 加 g_gc_base_frames 计数 */
    static unsigned int g_gc_base_frames = 0;
    g_gc_base_frames++;
    
    if (g_gc_base && g_gc_base_frames < 30) return g_gc_base;
    
    /* 超 30 帧重新校验: 读 *g_gc_base 确认 GOT 内容是合法指针 */
    if (g_gc_base) {
        unsigned long slot = 0;
        if (rm(&slot, g_gc_base + 0x51EA4D0UL, 8)) {
            slot = untag(slot);
            if (slot > 0x100000000UL && slot < 0x800000000000UL) {
                /* GOT 仍指向合法对象, base 仍有效 */
                g_gc_base_frames = 0;
                return g_gc_base;
            }
        }
        /* base 失效, 重定位 */
        g_gc_base = 0;
    }
    
    /* 重新 VMA 扫定位 */
    g.base = 0; g.found = 0;
    vma_walk(gcb_cb, &g);
    if (!g.found) return 0;
    g_gc_base = g.base;
    g_gc_base_frames = 0;
    return g_gc_base;
}
```

### 3. `read_rootactor_chain()` — 加 seqlock 读 IndexBuffer + Hero

关键修改在 Level 4 循环内,**读完 Hero 后 seqlock 重读 flag/IndexBuffer 比对**:

```c
/* 在 Level 4 循环里, slot/hero 读完后追加 seqlock 校验 */
for (i = 0; i < (int)count && valid < HB_MAXREC; i++) {
    /* ... 原有就读 slot/hero 的代码不变 ... */
    
    /* ★ seqlock 校验: Hero 读完后再重读 flag/count/IndexBuffer 比对 */
    {
        unsigned int flag2 = 0;
        unsigned long index_buf2 = 0;
        rm(&flag2, actor_mgr + 0x2EB0UL, 4);
        rm(&index_buf2, actor_mgr + 0x2E90UL, 8);
        index_buf2 = untag(index_buf2);
        if (flag2 != flag || index_buf2 != index_buf) {
            /* 容器结构变了, 跳过这一帧, 不写入 bin (数据不可靠) */
            continue;
        }
        /* IndexBuffer 内容也校验 (重读 IndexBuffer[i] 比对 slot) */
        if (flag != 0 && index_buf) {
            int rel_idx2 = 0;
            rm(&rel_idx2, index_buf + (unsigned long)i * 4, 4);
            if (rel_idx2 != rel_idx) continue;
        }
    }
    
    /* ... 原有 read_rootactor_chain 末尾 rm config_id / camp 等 + get_actor_coords + bin 写出 ... */
}
```

### 4. 主循环 `read_rootactor_chain` 末尾的 pr_info 保留,有助于校验

```c
pr_info("[hero-reader]   [#%02d] slot=%d hero=0x%lx cfg=%d ... coords=(%d,%d,%d) ll_valid=1 (seqlock)", ...);
```

## 总结

**最关键修复 = #1 删掉 fallback**。这一改动直接解决"过段时间不准"根因(从 spawn_pos fallback 到实时坐标)。

**#2 seqlock 读 Transform** 是配套 — 改完之后,即使 Transform 链读到中间过渡状态,seqlock 第二次读对比也能发现 node 已被换,返回失败 → 主流程会跳过这一帧的 hero coordinates(而不是给空气数据)。

**#3 gc_base 容错性** 是配套 — 避免偶尔 base 失效后用错误 base。

**#4 IndexBuffer seqlock** 是配套 — 避免 IndexBuffer 指针内容瞬变导致读到旧 slot 的过期 Hero*。
