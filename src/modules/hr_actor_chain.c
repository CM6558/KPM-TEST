/* hr_actor_chain.c — ★ 核心 — GameRoot → CActorManager → HeroEntry → Hero → Node/Link/Transform/VInt3 完整坐标读取链 */
#include "hr_internal.h"

    if (!md) { pr_warn("[hero-reader] findobj: metadata 未就绪\n"); return; }
    g_meta_addr = md;
    table = find_typeinfo_table(&total);
    if (!table) { pr_warn("[hero-reader] findobj: 未找到类表\n"); return; }
    for (i = 0; i < 70000; i++) {
        unsigned long c = rptr(table + i * 8);
        char nm[96];
        if (!c) continue;
        if (rstr(rptr(c + CLASS_NAME_O), nm, sizeof(nm)) <= 0) continue;
        if (strcmp(nm, q) == 0) { klass = c; break; }   /* 精确类名 */
    }
    if (!klass) { pr_warn("[hero-reader] findobj: 未找到类 '%s'\n", q); return; }
    g_fo_hits = 0;
    vma_walk(fobj_cb, &klass);
    pr_info("[hero-reader] findobj '%s' class=0x%lx 实例数=%d\n", q, klass, g_fo_hits);
    for (i = 0; i < (unsigned long)g_fo_hits; i++)
        pr_info("[hero-reader]   obj[%lu] = 0x%lx\n", i, g_fo_addrs[i]);
}

/* =========================================================================================
 * [历史参考 / 已下线] 链路 2: C# 托管层业务链 (IL2CPP)
 *
 * 1. 结构与寻址路径:
 *    - 在 libil2cpp.so 的 .bss 中定位运行时类表 s_TypeInfoTable (find_typeinfo_table)
 *    - 纯静态链定位 ActorManager 单例持有类:
 *        table[39479] (HolderClass)
 *        -> *(HolderClass + 0xB8) (CLASS_STATIC_FIELDS)
 *        -> *(static_fields + 0x80) = ActorManager* 实例 (纯静态链, 零扫描)
 *    - 英雄容器遍历:
 *        ActorManager + 0x18 (OFF_AM_HEROACTORS) -> TinyValueList*
 *          TinyValueList + 0x10 -> count
 *          TinyValueList + 0x08 (OFF_TVL_ITEMS) -> C# 数组对象
 *          数组元素起始: 数组对象 + 0x20 (ARR_ELEMS), 步长 0x10 (ELEM_STRIDE, PooledHandle)
 *          每个元素 + 0x00 -> ActorLinker* (英雄对象)
 *    - 阵营分桶判断:
 *        ActorManager + 0x78 (OFF_AM_CAMPSACTORS) -> CampsActors 数组
 *          每个阵营元素也是 TinyValueList, 包含该阵营的所有 ActorLinker
 *
 * 2. ActorLinker 及其组件关键字段偏移:
 *    - 坐标与移动:
 *        ActorLinker + 0x4C4: AL_POS (float x, y, z, 客户端渲染坐标)
 *        ActorLinker + 0x4B8: AL_FORWARD (float x, y, z, 朝向)
 *        ActorLinker + 0x764: AL_MOVESPEED (float, 移速)
 *        ActorLinker + 0x480: AL_GROUNDY (float)
 *        ActorLinker + 0x505: AL_LOGICVIS (_logicVisible)
 *        ActorLinker + 0x507: AL_INCAM (_inCamera, 视锥体内判定)
 *    - 数值组件 (ValueLinkerComponent, ActorLinker + 0x3B8):
 *        + 0x38: VC_HP (当前血量)
 *        + 0x3C: VC_HPMAX (最大血量)
 *        + 0x28 / + 0x2C: VC_EXP / VC_EXPMAX (经验值)
 *        + 0x30 / + 0x34: VC_GOLD / VC_INCGOLD (金币与金币收益)
 *        + 0x40 / + 0x44: VC_SHIELDMAX / VC_SHIELD (护盾)
 *        + 0x48 / + 0x4C: VC_CHARGEMAX / VC_CHARGE (蓄力/能量)
 *        + 0x58: VC_LEVEL (等级)
 *    - 控制与状态组件 (ObjLinkerWrapper, ActorLinker + 0x3C0):
 *        + 0x28: OC_CONFIGID (配置 ID)
 *        + 0x39 / + 0x3A: OC_ISDEAD / OC_ISDYING (死亡/濒死)
 *        + 0x4C: OC_REVIVE (复活倒计时)
 *        + 0x5A: OC_GRASS (是否在草丛)
 *        + 0x5B: OC_FREEZE (是否冰冻/控制)
 *        + 0x34: OC_BATTLE (战斗状态)
 *        + 0x88: OC_ATKTARGET (普攻锁敌目标 ID)
 *    - 技能组件 (SkillLinkerComponent, ActorLinker + 0x28):
 *        + 0x28: SLC_SLOTARR (SkillSlotLinkerArray)
 *        各技能槽位: +0x5C CurSkillCD, +0x60 CurSkillCDMax
 *    - 装备组件 (EquipLinkerComponent, ActorLinker + 0x30):
 *        + 0x2C: EQ_BUYCOUNT (购买数量)
 *        + 0x40: EQ_C_COMMON (CEquipContainer*, 装备容器)
 *    - 本机玩家判定 (GamePlayerCenter):
 *        HolderClass.static_fields + 0xE0 -> GamePlayerCenter*
 *        GamePlayerCenter + 0x40 -> hostPlayerID (匹配 ActorLinker + 0x558 playerID)
 * ========================================================================================= */

/* =========================================================================================
 * [历史参考 / 已下线] 链路 1: 原生物理层权威链 (libGameCore.so)
 *
 * 1. 结构与寻址路径:
 *    - 基址定位:
 *        遍历进程 VMA 匹配 ELF 头，并通过 offset 0x318 处的 Build-ID 精准鉴别:
 *        [82 2d 2c e9 2a ad fd 8a]
 *    - 全局 Roster 槽位寻址 (纯静态链):
 *        libGameCore_base + 0x53F1810 (GC_ROOT_VA, 即 .bss + 0x182810) -> RootSlot*
 *        RootSlot + 0x250 (GC_ROSTER_PTR_OFF) -> Roster* (句柄数组)
 *    - 遍历英雄条目 (Roster[i], 步长 0x18 / GC_ROSTER_STRIDE):
 *        elem = Roster + i * 0x18
 *        elem + 0x00 -> ActorRoot* (原生实体对象)
 *        句柄代数校验: elem + 0x0C (PH_GENERATION) == ActorRoot + 0x0C (ACTOR_ROOT_GEN)
 *        (代数不一致表示槽位已被死亡/回收实体复用，属于脏数据，需丢弃)
 *        ActorRoot + 0x28 (NA_ID)   -> 英雄 Config ID (1..4000)
 *        ActorRoot + 0x34 (NA_CAMP) -> 阵营 (1 或 2)
 *    - 原生生命值组件 (ActorRoot + 0x1D0):
 *        + 0xC0 -> 当前 HP (int32)
 *        + 0xC8 -> 最大 HP (int32)
 *    - 权威世界坐标链 (物理变换 Transform 链, 帧同步模拟层真实坐标, 迷雾中平滑更新):
 *        ActorRoot + 0xA8 (NA_NODE)   -> Node*
 *        Node + 0x10 (NODE_LINK)      -> Link*
 *        Link + 0x00 (Transform)      -> Transform*
 *        Transform + 0x60             -> p2 (VInt3 定点整数坐标指针)
 *          p2 + 0: int32 X (单位: 毫米, /1000 即为米, /10 即为厘米)
 *          p2 + 4: int32 Y (高度)
 *          p2 + 8: int32 Z
 *
 * 2. 共享二进制流文件输出结构 (hbin_write 历史记录):
 *    - 头部结构体 (struct hb_hdr, 64 字节):
 *        magic (0x4842494E 'HBIN'), version (1), seq (seqlock 奇数写/偶数稳),
 *        timestamp_ms, n (当前活跃英雄数), max_rec (16), rec_size (sizeof(struct hb_rec))
 *    - 记录项结构体 (struct hb_rec, 64 字节):
 *        heroid (u32), camp (u32), hp (i32), hpmax (i32), x/y/z (i32, 厘米),
 *        dead (u8), me (u8, 是否本机玩家)
 * ========================================================================================= */


/* ==================== 从零反推用的两个原语 ====================
 * scanvec <x> <y> <z> [lo_hex hi_hex]  找连续 3 个 int32 == (x,y,z)
 *                                       lo/hi 给定时只扫该区间 (堆区 50MB 只需 <1s)
 * scanptr <hex> [lo_hex hi_hex]        找 8 字节值 == 指针 (裸地址或带 0xb4 顶字节标签)
 * 用途: 已知一个可见英雄的坐标 -> 找到 xyz 地址 -> scanptr 逐级反查 node/actor/roster
 */
static long          g_svec_x, g_svec_y, g_svec_z;
static unsigned long g_svec_lo, g_svec_hi;
static int           g_svec_hits = 0;
static volatile int  g_req_scanvec_valid = 0;
static unsigned long g_sptr_val, g_sptr_lo, g_sptr_hi;
static int           g_sptr_hits = 0;
static volatile int  g_req_scanptr_valid = 0;

static int sv_scan_buf(unsigned long base, int n)
{
    int p;
    if (n < 12) return 0;
    for (p = 0; p + 12 <= n; p += 4) {
        int a, b, c;
        __builtin_memcpy(&a, g_iobuf + p, 4);
        __builtin_memcpy(&b, g_iobuf + p + 4, 4);
        __builtin_memcpy(&c, g_iobuf + p + 8, 4);
        if (a == (int)g_svec_x && b == (int)g_svec_y && c == (int)g_svec_z) {
            pr_info("[hero-reader] scanvec: 0x%lx\n", base + (unsigned long)p);
            if (++g_svec_hits >= 40) return 1;
        }
    }
    return 0;
}

static int sp_scan_buf(unsigned long base, int n)
{
    int p;
    if (n < 8) return 0;
    for (p = 0; p + 8 <= n; p += 8) {
        unsigned long v;
        __builtin_memcpy(&v, g_iobuf + p, 8);
        if (v == g_sptr_val || (v & PTR_MASK) == g_sptr_val) {
            pr_info("[hero-reader] scanptr: 0x%lx (tagged=0x%lx)\n", base + (unsigned long)p, v);
            if (++g_sptr_hits >= 40) return 1;
        }
    }
    return 0;
}

static int sv_cb2(void *udata, unsigned long start, unsigned long end, unsigned long flags)
{
    unsigned long off = 0, total = end - start;
    (void)udata;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && g_svec_hits < 40) {
        unsigned long want = total - off;
        int n;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        n = (int)want;
        if (sv_scan_buf(start + off, n)) return 1;
        off += (unsigned long)(n > 8 ? n - 8 : n);
    }
    return 0;
}

static int sp_cb2(void *udata, unsigned long start, unsigned long end, unsigned long flags)
{
    unsigned long off = 0, total = end - start;
    (void)udata;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && g_sptr_hits < 40) {
        unsigned long want = total - off;
        int n;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        n = (int)want;
        if (sp_scan_buf(start + off, n)) return 1;
        off += (unsigned long)n;
    }
    return 0;
}

static void do_scanvec(void)
{
    unsigned long lo = g_svec_lo, hi = g_svec_hi, a;
    g_svec_hits = 0;
    if (!g_target_mm) { pr_warn("[hero-reader] scanvec: mm 未锁定\n"); return; }
    pr_info("[hero-reader] scanvec (%d,%d,%d) 范围=%s\n", (int)g_svec_x, (int)g_svec_y, (int)g_svec_z,
            (lo && hi) ? "限定" : "全内存");
    if (lo && hi && hi > lo) {
        for (a = lo; a + 12 <= hi && g_svec_hits < 40; a += IO_CHUNK) {
            unsigned long n = hi - a;
            if (n > IO_CHUNK) n = IO_CHUNK;
            if (!rm(g_iobuf, a, (int)n)) continue;
            if (sv_scan_buf(a, (int)n)) break;
        }
    } else {
        vma_walk(sv_cb2, NULL);
    }
    if (!g_svec_hits) pr_warn("[hero-reader] scanvec: 无命中\n");
}

static void do_scanptr(void)
{
    unsigned long lo = g_sptr_lo, hi = g_sptr_hi, a;
    g_sptr_hits = 0;
    if (!g_target_mm) { pr_warn("[hero-reader] scanptr: mm 未锁定\n"); return; }
    pr_info("[hero-reader] scanptr 0x%lx 范围=%s\n", g_sptr_val, (lo && hi) ? "限定" : "全内存");
    if (lo && hi && hi > lo) {
        for (a = lo; a + 8 <= hi && g_sptr_hits < 40; a += IO_CHUNK) {
            unsigned long n = hi - a;
            if (n > IO_CHUNK) n = IO_CHUNK;
            if (!rm(g_iobuf, a, (int)n)) continue;
            if (sp_scan_buf(a, (int)n)) break;
        }
    } else {
        vma_walk(sp_cb2, NULL);
    }
    if (!g_sptr_hits) pr_warn("[hero-reader] scanptr: 无命中\n");
}


/* =========================================================================================
 * [历史参考 / 已下线] 核心对局数据读取链架构与反推记录
 *
 * 链路 1: libGameCore.so 原生物理层权威变换链 (Transform)
 * -----------------------------------------------------------------------------------------
 * 背景说明:
 *   王者荣耀为帧同步架构，本地客户端对战局中全部 10 名英雄跑确定性物理模拟。
 *   在 C# 表现层被迷雾视野剔除时，底层确定性模拟层的物理变换节点 (Transform) 仍然平滑更新，
 *   是获取真实物理世界坐标的唯一权威源。
 *
 * 寻址与数据结构:
 *   1. 模块定位:
 *      - 遍历进程 VMA 寻找 ELF 标识 '\x7fELF'
 *      - 读取 offset 0x318 处的 8 字节 Build-ID 进行唯一性校验:
 *        [82 2d 2c e9 2a ad fd 8a] -> 确认为 libGameCore.so 基址 (gc_base)
 *   2. Roster 句柄数组入口:
 *      - gc_base + 0x53F1810 (即 .bss + 0x182810) -> RootSlot*
 *      - RootSlot + 0x250 (GC_ROSTER_PTR_OFF) -> Roster* (PooledHandle 数组)
 *   3. 槽位遍历与代数防重用校验:
 *      - 数组元素步长 0x18 (24 字节):
 *          elem = Roster + i * 0x18
 *          elem + 0x00 -> ActorRoot* (原生实体对象指针)
 *          elem + 0x0C -> elem_gen (句柄代数)
 *          ActorRoot + 0x0C -> act_gen (实体代数)
 *          校验: elem_gen == act_gen (不匹配则为死亡/回收后的脏槽位，予以丢弃)
 *      - 实体基础属性:
 *          ActorRoot + 0x28 (NA_ID): 英雄 Config ID (1..4000)
 *          ActorRoot + 0x34 (NA_CAMP): 阵营 ID (1 或 2)
 *      - 实体血量组件:
 *          ActorRoot + 0x1D0 -> AttributeComponent*
 *            + 0xC0 -> 当前生命值 (int32 hp)
 *            + 0xC8 -> 最大生命值 (int32 hpmax)
 *   4. 物理世界坐标寻址 (Transform 链):
 *      - ActorRoot + 0xA8 (NA_NODE) -> Node*
 *      - Node + 0x10 (NODE_LINK) -> Link*
 *      - Link + 0x00 -> Transform*
 *      - Transform + 0x60 -> p2 (VInt3 定点三维坐标指针)
 *          p2 + 0: int32 X (单位: 毫米, /1000 为米, /10 为厘米)
 *          p2 + 4: int32 Y (高度)
 *          p2 + 8: int32 Z
 *
 * -----------------------------------------------------------------------------------------
 * 链路 2: IL2CPP C# 托管层业务与组件链 (ActorManager)
 * -----------------------------------------------------------------------------------------
 * 背景说明:
 *   用于获取技能冷却、装备栏、等级、经济、护盾、草丛状态等上层业务数据。
 *
 * 寻址与数据结构:
 *   1. 类表与单例持有类:
 *      - 在 libil2cpp.so 的 .bss 中定位运行时类表 s_TypeInfoTable
 *      - table[39479] (HolderClass)
 *      - *(HolderClass + 0xB8) (CLASS_STATIC_FIELDS) + 0x80 -> ActorManager* (单例实例)
 *   2. 英雄数组展开:
 *      - ActorManager + 0x18 (OFF_AM_HEROACTORS) -> TinyValueList*
 *          TinyValueList + 0x10 -> count (英雄数量)
 *          TinyValueList + 0x08 -> C# 数组对象指针
 *          数组元素起始: 数组对象 + 0x20，元素步长 0x10 (PooledHandle)
 *          元素 + 0x00 -> ActorLinker* (目标英雄 C# 实体)
 *   3. 阵营判定:
 *      - ActorManager + 0x78 (OFF_AM_CAMPSACTORS) -> TinyValueList[]
 *   4. ActorLinker 及其组件关键字段:
 *      - 坐标与运动:
 *          ActorLinker + 0x4C4: float x, y, z (客户端渲染坐标, 迷雾中冻结)
 *          ActorLinker + 0x4B8: float forward x, y, z
 *          ActorLinker + 0x764: float moveSpeed (移动速度)
 *      - 数值组件 (ValueLinkerComponent, ActorLinker + 0x3B8):
 *          + 0x38: actorHp (当前生命值)
 *          + 0x3C: actorHpTotal (最大生命值)
 *          + 0x28 / + 0x2C: 经验 / 升级经验
 *          + 0x30 / + 0x34: 金币 / 每秒金币
 *          + 0x40 / + 0x44: 护盾上限 / 当前护盾
 *          + 0x48 / + 0x4C: 蓄力上限 / 当前蓄力
 *          + 0x58: 等级
 *      - 控制与状态组件 (ObjLinkerWrapper, ActorLinker + 0x3C0):
 *          + 0x28: configID
 *          + 0x39: isDead (死亡标志)
 *          + 0x5A: isGrass (草丛隐身)
 *          + 0x5B: isFreeze (控制/冰冻)
 *          + 0x88: atktarget (普攻锁敌目标 ID)
 *      - 技能组件 (SkillLinkerComponent, ActorLinker + 0x28):
 *          + 0x28: skillSlotLinkerArray
 *          每个槽位: +0x5C CurSkillCD, +0x60 CurSkillCDMax, +0x95 canLevelUp
 *      - 装备组件 (EquipLinkerComponent, ActorLinker + 0x30):
 *          + 0x2C: buyEquipCount
 *          + 0x40: m_commonContainer (CEquipContainer*)
 *      - 本机自身英雄判定:
 *          HolderClass.static_fields + 0xE0 -> GamePlayerCenter*
 *          GamePlayerCenter + 0x40 -> hostPlayerID
 *          与 ActorLinker + 0x558 (playerID) 匹配以锁定本机操作英雄。
 *
 * -----------------------------------------------------------------------------------------
 * 数据输出与通信协议历史记录:
 *   1. 定长二进制 (HR01 - seqlock):
 *      struct hb_hdr { uint magic, version, seq, rec_size, max_rec, n; u64 ts_ms; };
 *      struct hb_rec { uint heroid, camp, objid; int hp, hpmax, ...; int x, y, z; ... };
 *   2. JSON 文件转储: 周期性写入 /data/local/tmp/heroes.json 供外挂界面展示。
 * ========================================================================================= */


struct gcb { unsigned long base; int found; };
static int gcb_cb(void *ud, unsigned long start, unsigned long end, unsigned long flags)
{
    struct gcb *g = ud;
    unsigned int magic = 0;
    unsigned char build_id[8] = {0};
    (void)end;
    if (!(flags & VM_READ) || (flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (!rm(&magic, start, 4) || magic != 0x464C457FU) return 0;   /* ELF magic */
    if (!rm(build_id, start + 0x318UL, 8)) return 0;
    if (build_id[0] != 0x82 || build_id[1] != 0x2d || build_id[2] != 0x2c || build_id[3] != 0xe9 ||
        build_id[4] != 0x2a || build_id[5] != 0xad || build_id[6] != 0xfd || build_id[7] != 0x8a)
        return 0;

    g->base = start; g->found = 1;
    return 1;
}

static unsigned long gc_base(void)
{
    struct gcb g;
    if (g_gc_base) return g_gc_base;
    g.base = 0; g.found = 0;
    vma_walk(gcb_cb, &g);
    if (!g.found) return 0;
    g_gc_base = g.base;
    return g_gc_base;
}

/*
 * GameRoot -> CActorManager -> HeroEntry 间接索引池 -> Hero (1008字节)
 * 严格按照 sub_3CFFEF8 与 sub_45ACA90 机器汇编实现
 */

static void hbin_write(void)
{
    void *f = NULL, *old_cred = NULL;
    struct hb_hdr *H = (struct hb_hdr *)g_iobuf;
    unsigned long hdr_sz = sizeof(struct hb_hdr), rec_sz = sizeof(struct hb_rec);
    unsigned long total = hdr_sz + HB_MAXREC * rec_sz;
    long long p = 0;
    int first = !g_bin_created;

    if (!g_bin_path[0] || total > sizeof(g_iobuf)) return;
    if (!p_filp_open || !p_kernel_write || !p_filp_close) return;

    memset(g_iobuf, 0, total);
    H->magic = HB_MAGIC;
    H->version = HB_VERSION;
    H->rec_size = (unsigned int)rec_sz;
    H->max_rec = HB_MAXREC;
    H->n = g_bin_n;
    H->ts_ms = (uint64_t)g_bin_ts++;
    H->flags = 0;
    H->seq = g_bin_seq;

    if (g_bin_n) memcpy(g_iobuf + hdr_sz, g_bin_rec, g_bin_n * rec_sz);

    if (g_io_cred && p_override_creds) old_cred = p_override_creds(g_io_cred);
    f = p_filp_open(g_bin_path, KPM_O_WRONLY | KPM_O_CREAT | (first ? KPM_O_TRUNC : 0), 0644);
    if (!f || (unsigned long)f >= (unsigned long)-4095UL) {
        if (old_cred && p_revert_creds) p_revert_creds(old_cred);
        return;
    }
    g_bin_created = 1;

    if (first) {
        p = 0; p_kernel_write(f, g_iobuf, total, &p);
    } else {
        unsigned int odd = g_bin_seq + 1, even = g_bin_seq + 2;
        p = 8;  p_kernel_write(f, &odd, 4, &p);           /* seq = 奇 (写入中) */
        p = 0;  p_kernel_write(f, g_iobuf, 8, &p);        /* magic/version */
        p = 12; p_kernel_write(f, g_iobuf + 12, total - 12, &p);
        g_bin_seq = even;
        p = 8;  p_kernel_write(f, &even, 4, &p);          /* seq = 偶 (稳定) */
    }
    p_filp_close(f, NULL);
    if (old_cred && p_revert_creds) p_revert_creds(old_cred);
}

static int get_actor_coords(unsigned long actor, int *ox, int *oy, int *oz)
{
    unsigned long node = 0, link = 0, tr = 0, p2 = 0;
    unsigned long node2 = 0, link2 = 0;
    int xx = 0, yy = 0, zz = 0;

    /* 唯一路径: 权威物理变换链 Transform (帧同步模拟层权威真值, 迷雾不冻结)
     * ★ 不再回调到 +32/+40/+44 (SetSpawnPosition 是出生点缓存, 开局后不更新)
     * ★ seqlock: 读完整个链路后重读 node/link 比对一致性
     */
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

    /* 读 VInt3 三字段 (毫米, ÷10 = 厘米) */
    rm(&xx, p2 + 0, 4);
    rm(&yy, p2 + 4, 4);
    rm(&zz, p2 + 8, 4);

    /* seqlock: 重读 node/link 比对,确认中间未被物理引擎切换 */
    rm(&node2, actor + 0xA8UL, 8);
    node2 = untag(node2);
    if (node2 != node) return 0;   /* node 已换,读到的坐标可能跨期 → 丢弃 */
    rm(&link2, node + 0x10UL, 8);
    link2 = untag(link2);
    if (link2 != link) return 0;   /* link 已换, 丢弃 */

    /* 数值合理性检查 (地图 ±30km; Z 通常 < 2km 但是容许) */
    if (xx == 0 && zz == 0) return 0;
    if (xx < -3000000 || xx > 3000000) return 0;
    if (zz < -3000000 || zz > 3000000) return 0;

    /* 单位转换: 毫米 → 厘米 */
    *ox = xx / 10;
    *oy = yy / 10;
    *oz = zz / 10;
    return 1;

    /* ★ 绝不再 fallback 到路径 2 (+32/+40/+44 = SetSpawnPosition, 开局后不更新) */
}

/*
 * GameRoot -> CActorManager -> HeroEntry 间接索引池 -> Hero (1008字节)
 * 严格按照 sub_3CFFEF8 与 sub_45ACA90 机器汇编实现，并写入 heroes.bin
 */
static int read_rootactor_chain(void)
{
    unsigned long b = 0, p_root_slot = 0, game_root = 0, actor_mgr = 0;
    unsigned long pool_base = 0, index_buf = 0;
    unsigned int flag = 0, count = 0, valid = 0;
    unsigned long count_off = 0;
    int i;

    if (!g_target_mm) return -1;
    b = gc_base();
    if (!b) return -2;

    /* Level 0: [base + 0x51EA4D0] -> p_root_slot (sub_3CFFEF8: ldr x8, [x8, #0x520]; ldr x23, [x8]) */
    if (!rm(&p_root_slot, b + 0x51EA4D0UL, 8)) return -3;
    p_root_slot = untag(p_root_slot);
    if (!p_root_slot || p_root_slot < 0x100000000UL) return -4;

    /* Level 1: *p_root_slot -> GameRoot* (sub_3CFFEF8: ldr x8, [x23]) */
    if (!rm(&game_root, p_root_slot, 8)) return -5;
    game_root = untag(game_root);
    if (!game_root || game_root < 0x100000000UL) return -6;

    /* Level 2: *(GameRoot + 0x388) -> CActorManager* (sub_3CFFEF8: ldr x0, [x8, #0x388]) */
    if (!rm(&actor_mgr, game_root + 0x388UL, 8)) return -7;
    actor_mgr = untag(actor_mgr);
    if (!actor_mgr || actor_mgr < 0x100000000UL) return -8;

    /* Level 3: 计数标志与有效数量 (sub_45ACA90: ldr w8, [x26, #0x2eb0]; csel x8, x9, x8, eq) */
    rm(&flag, actor_mgr + 0x2EB0UL, 4);
    count_off = (flag == 0) ? 0x2E8CUL : 0x2EACUL;
    rm(&count, actor_mgr + count_off, 4);
    pr_info("[hero-reader] rootactor: gc_base=0x%lx root=0x%lx am=0x%lx flag=%u off=0x%lx count=%u\n",
            b, game_root, actor_mgr, flag, count_off, count);
    if (count == 0 || count > 512) return -9;

    /* 间接索引表与对象池基址 */
    rm(&index_buf, actor_mgr + 0x2E90UL, 8);
    if (!rm(&pool_base, actor_mgr + 0x2E70UL, 8)) return -10;
    index_buf = untag(index_buf);
    pool_base = untag(pool_base);
    pr_info("[hero-reader] rootactor: flag=%u count=%u pool=0x%lx idx=0x%lx\n", flag, count, pool_base, index_buf);
    if (!pool_base || pool_base < 0x100000000UL) return -11;

    memset(g_bin_rec, 0, sizeof(g_bin_rec));

    /* Level 4: 查表遍历 (flag==0 时为直接步进 i, flag!=0 时查 index_buf) */
    for (i = 0; i < (int)count && valid < HB_MAXREC; i++) {
        int rel_idx = 0, slot = 0;
        unsigned long entry_addr = 0, hero_ptr = 0;
        int config_id = 0, runtime_id = 0, real_x = 0, real_y = 0, real_z = 0;
        unsigned int enabled_flag = 0, state_code = 0;
        unsigned char is_in_grass = 0;
        unsigned int camp_raw = 0;
        struct hb_rec *rb;

        if (flag == 0 || !index_buf) {
            slot = i;
        } else {
            if (!rm(&rel_idx, index_buf + (unsigned long)i * 4, 4)) continue;
            slot = rel_idx + i;
        }
        if (slot < 0 || slot >= 512) continue;

        entry_addr = pool_base + (unsigned long)slot * 32UL;
        if (!rm(&hero_ptr, entry_addr + 8UL, 8)) continue;
        hero_ptr = untag(hero_ptr);
        if (!hero_ptr || hero_ptr < 0x100000000UL || hero_ptr >= 0x800000000000UL) continue;

        rm(&runtime_id, hero_ptr + 8UL, 4);
        rm(&config_id, hero_ptr + 0x28UL, 4);
        rm(&camp_raw, hero_ptr + 0x34UL, 4);
        rm(&enabled_flag, hero_ptr + 88UL, 4);
        rm(&state_code, hero_ptr + 92UL, 4);
        rm(&is_in_grass, hero_ptr + 712UL, 1);

        /* 过滤：王者荣耀英雄ID通常在 100~700 之间 (如105廉颇..585元流之子) */
        if (config_id < 100 || config_id > 700) continue;

        get_actor_coords(hero_ptr, &real_x, &real_y, &real_z);

        pr_info("[hero-reader]   [#%02d] slot=%d hero=0x%lx cfg=%d camp=%u rt=%d pos=(%d,%d) cm en=%u st=%u grass=%u\n",
                valid, slot, hero_ptr, config_id, camp_raw, runtime_id, real_x, real_z, enabled_flag, state_code, is_in_grass);

        rb = &g_bin_rec[valid];
        rb->heroid = (uint32_t)config_id;
        rb->objid = (uint32_t)runtime_id;
        rb->x = real_x;
        rb->y = real_y;
        rb->z = real_z;
        rb->mx = real_x;
        rb->mz = real_z;
        rb->dead = 0;   /* 对局英雄默认标记存活 */
