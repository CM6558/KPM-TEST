/* hr_internal.h — 内联头 — 宏/常数/类型/全局声明/最底层 rm/r32/rstr 原语 */

#ifndef HR_INTERNAL_H
#define HR_INTERNAL_H

/*
 * hero_reader.kpm — 内核态 IL2CPP 读取 / global-metadata 转储  v6.0.0
 *
 * 设计红线 (用户要求, 必须全部满足):
 *   1. 不使用任何 hook。
 *   2. 不做任何可能阻塞目标渲染/调度的操作:
 *      - 读内存不走 access_remote_vm / access_process_vm (它们会 mmap_read_lock 目标 mm,
 *        高频调用会饿死目标 mmap_write_lock → 卡渲染/GC/JIT)。
 *        改为 **页表 + 物理内存** 直读: pgtable_phys(pgd,va) → 线性映射 VA → memcpy。
 *        全程不进入目标地址空间、不取目标 mmap 锁、不触发缺页。
 *      - 不做整地址空间扫描。只在**有界**范围读取 (metadata 段、.bss、指定地址)。
 *      - 重活分批 + msleep 让出 CPU。
 *   3. 反检测: 无 hook、无 /proc、无 ptrace、默认静默 (无周期日志)。
 *   4. 稳定: 符号判空、长度有界、mm 引用单点持有/释放、卸载与作业互斥。
 *
 * 能力: dumpmeta (global-metadata 完整转储), findmeta, walk, chain, dump/peek。
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <common.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>   /* mm_struct_offset (pgd 偏移) */
#include <asm/current.h>
/* #include "heromap.h" -- 英雄ID -> 英雄名静态表 (原对局数据链使用，现已随链路下线转入注释) */

#define PTR_MASK            0x0000FFFFFFFFFFFFUL
static inline unsigned long untag(unsigned long p) { return p & PTR_MASK; }

#ifndef VM_READ
#define VM_READ   0x00000001UL
#define VM_WRITE  0x00000002UL
#define VM_EXEC   0x00000004UL
#endif

#define KPM_O_WRONLY     01
#define KPM_O_CREAT      0100
#define KPM_O_TRUNC      01000

#ifndef HR_MOD_NAME
#define HR_MOD_NAME "hero-reader"
#endif
KPM_NAME(HR_MOD_NAME);
KPM_VERSION("6.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("analyst");
KPM_DESCRIPTION("Kernel-side IL2CPP reader (page-table physical reads, no hook, no blocking)");

/* ---- 游戏侧偏移 (真机验证) ---- */
#define S_DOMAIN_ADDR            0xE344EA0UL      /* s_domain 结构体地址 */
#define S_METADATA_SLOT0         0xE345000UL      /* s_GlobalMetadataHeader 指针槽 */
#define S_METADATA_SLOT1         0xE340010UL
#define DOMAIN_ASM_BEGIN         0x18UL
#define DOMAIN_ASM_END           0x20UL
#define ASM_IMAGE                0x00UL
#define IMAGE_NAME               0x00UL
#define IMAGE_CLASS_COUNT        0x18UL

/*
 * [历史参考 / 已废弃] 旧版 libGameCore.so UnitLabel 链与 GameRoot/CActorManager 探索记录:
 * 该部分代码在早期版本中通过 Capstone/IDA 反汇编分析得到，现已废弃，仅保留在注释中供逆向参考:
 *
 * 1. UnitLabel 链 (历史路径: sub_24B2590 UnitLabelFinder):
 *    libGameCore.so + 0x53ddb90 (GC_MANAGER_BSS_OFF) -> GameTacticsManager*
 *      + 0x220 (GC_OBJ_UNIT_LABEL_FINDER) -> UnitLabelFinder*
 *        + 0xC8 (GC_ULF_ARRAY_BEGIN) -> UnitLabel 数组 begin
 *        + 0xD0 (GC_ULF_ARRAY_END)   -> UnitLabel 数组 end
 *        步长 0xB8 (184 字节, UNIT_LABEL_SIZE)
 *          + 0x00: type_id (u32)
 *          + 0x04: runtime (u32)
 *          + 0x0C: camp_id (u32)
 *          + 0x14: x_pos (u32)
 *          + 0x1C: z_pos (u32)
 *          + 0x2C: hp (u32, >= 1 有效)
 *          + 0x34: max_hp (u32)
 *
 * 2. GameRoot / CActorManager 探索路径 (历史记录):
 *    [off_51EA4D0] = GameRoot** (g_game_root)
 *      *off_51EA4D0 = GameRoot*
 *        + 0x388 (+904) -> CActorManager*
 *          + 0x2E70 (+11888) -> HeroEntry* 数组 (步长 0x20, +0x08 为 Hero*)
 *          或 CActorManager + 0x30 (ActorRootArr), + 0x50 (IndexBuffer), + 0x70 (Flag)
 *          Hero (1008 字节): +0x04 cfg_id, +0x08 runtime_id, +0x20 real_x, +0x28 real_y, +0x2C real_z...
 *
 * 当前版本实际工作链:
 *    Native 物理变换权威链 (GC_ROOT_VA 0x53F1810 -> Roster -> Transform -> VInt3 坐标)
 *    与 C# 托管层链 (s_TypeInfoTable[39479] -> ActorManager -> TinyValueList -> ActorLinker)
 */

/* ---- test.so / libGameCore.so 核心世界与单例静态偏移 (2026-10 实测) ---- */
#define GC_GAMEWORLD_BSS_OFF     0x053EC610UL   /* .bss 段 USGMobaWorld* 全局单例 */
#define GC_ACTOR_MGR_BSS_OFF     0x052739E0UL   /* .bss 段 CActorManager* 全局单例 */
#define GC_SEC_TRANSFORM_BSS_OFF 0x05272138UL   /* .bss 段 Physics::SecurityTransform* 全局单例 */

#define PH_GENERATION            0x0CUL         /* 句柄代数校验 */
#define ACTOR_ROOT_GEN           0x0CUL         /* ActorRoot->generation */

/* ---- metadata (IL2CPP v29) ---- */
#define IL2CPP_MAGIC             0xFAB11BAF
#define IL2CPP_VERSION_MIN       21
#define IL2CPP_VERSION_MAX       31
#define MD_HEADER_SIZE           0x100
#define MD_HEADER_PAIRS          31
#define MD_MAX_SIZE              (1024UL << 20)

struct md_tbl_ent { unsigned int hoff; unsigned int elem; const char *name; };
static const struct md_tbl_ent g_v29[MD_HEADER_PAIRS] = {
    { 0x08,  8, "stringLiteral" },          { 0x10,  1, "stringLiteralData" },
    { 0x18,  1, "string" },                 { 0x20, 24, "events" },
    { 0x28, 20, "properties" },             { 0x30, 32, "methods" },
    { 0x38, 12, "parameterDefaultValues" }, { 0x40, 12, "fieldDefaultValues" },
    { 0x48,  1, "fieldAndParameterDefaultValueData" }, { 0x50, 12, "fieldMarshaledSizes" },
    { 0x58, 12, "parameters" },             { 0x60, 12, "fields" },
    { 0x68, 16, "genericParameters" },      { 0x70,  4, "genericParameterConstraints" },
    { 0x78, 16, "genericContainers" },      { 0x80,  4, "nestedTypes" },
    { 0x88,  4, "interfaces" },             { 0x90,  4, "vtableMethods" },
    { 0x98,  8, "interfaceOffsets" },       { 0xA0, 88, "typeDefinitions" },
    { 0xA8, 40, "images" },                 { 0xB0, 64, "assemblies" },
    { 0xB8,  8, "fieldRefs" },              { 0xC0,  4, "referencedAssemblies" },
    { 0xC8,  1, "attributeData" },          { 0xD0,  8, "attributeDataRange" },
    { 0xD8,  4, "unresolvedVirtualCallParameterTypes" }, { 0xE0, 8, "unresolvedVirtualCallParameterRanges" },
    { 0xE8,  8, "windowsRuntimeTypeNames" },{ 0xF0,  1, "windowsRuntimeStrings" },
    { 0xF8,  4, "exportedTypeDefinitions" },
};

/* ---- 运行时符号 ---- */
static void *(*p_find_task_by_vpid)(pid_t);
static void  (*p_rcu_read_lock)(void);
static void  (*p_rcu_read_unlock)(void);
static void *(*p_get_task_mm)(void *);
static void  (*p_mmput)(void *);
static void *(*p_find_vma)(void *, unsigned long);
static void  (*p_mmap_read_lock)(void *);     /* 保护无锁 find_vma (maple tree 并发不安全) */
static void  (*p_mmap_read_unlock)(void *);
/* 本模块不使用 access_remote_vm / get_user_pages / ptrace:
 * 所有游戏内存读取只走页表物理读 (rm -> my_pgtable_phys), 不拿目标 mmap_lock。 */
/* KP 导出符号 (直接引用, 由 KPM loader 解析, 不走 kallsyms): 页表→物理地址 */
extern unsigned long pgtable_phys(unsigned long pgd, unsigned long va);

static void *(*p_kthread_create_on_node)(int (*)(void *), void *, int, const char *, ...);
static int   (*p_wake_up_process)(void *);
static int   (*p_kthread_should_stop)(void);
static int   (*p_kthread_stop)(void *);
static void  (*p_msleep)(unsigned int);

static void *(*p_filp_open)(const char *, int, int);
static long  (*p_kernel_write)(void *, const void *, unsigned long, long long *);
static int   (*p_filp_close)(void *, void *);
static void *(*p_override_creds)(void *);
static void  (*p_revert_creds)(void *);
static void *(*p_get_task_cred)(void *);
static void  (*p_put_cred)(void *);

/* ---- 物理读环境 ---- */
static unsigned long g_memstart_addr = 0;   /* &memstart_addr (... 的值) */
static unsigned long g_pa_to_va_delta  = 0; /* PAGE_OFFSET - memstart_addr */
static int           g_page_shift      = 12;
static int           g_page_level      = 3;  /* 页表级数 (4 - page_level = 起始 lv) */

/* ---- 状态 ---- */
static pid_t          g_target_pid = 0;
static void          *g_target_mm  = NULL;
static pid_t          g_mm_pid     = 0;
static char           g_target_comm[64] = {0};   /* 非空 = 内核态按进程名自动定位 pid */

/* 页表翻译缓存: 同一 VA 页的重复读不再逐级 walk (64 项直接映射) */
static unsigned long  g_ptc_va[64], g_ptc_pa[64];
static unsigned long  g_pgd        = 0;
static unsigned long  g_base       = 0;
static unsigned long  g_gc_base    = 0;
static int            g_verbose    = 0;
static int            g_allow_scan = 0;   /* 默认禁用重扫 (dumpall/findobj); 需 'unsafe on' */
static int            g_diag       = 0;   /* 默认禁用诊断命令; 需 'diag on' */
static int            g_scan_wide  = 0;

/* 诊断类命令前缀 (默认关闭) */
static int is_diag_cmd(const char *a)
{
    static const char *k[] = { "peek ", "dump ", "name ", "fields ", "classinfo ",
                               "findfield ", "findstatic ", "findpid ", "scanseq ", "scanval ", "scanlive ", "scanrec ", "scanids ", "tabdump ", "native", "scanvec ", "scanptr ", "hwbp ", "hwbpslot ", "hwbpslot4 ", "hwbpxva ", "fullchain", "nativescan ", "nscorr ", "cscan ", "cad ", "cams ", "camcal ", "pairscan ", "wide ", "walk", "chain", "dumpall", "dump ", "gcwatch ", 0 };
    int i;
    for (i = 0; k[i]; i++) { unsigned long n = (unsigned long)strlen(k[i]); if (!strncmp(a, k[i], n)) return 1; }
    return 0;
}
static void          *g_kthread    = NULL;
static void          *g_io_cred    = NULL;
static unsigned long  g_meta_addr  = 0;
static unsigned long  g_meta_size  = 0;
static unsigned int   g_meta_ver   = 0;
static unsigned long  g_dump_bytes = 0;
static int            g_dump_done  = 0;
static unsigned long  g_tbl = 0, g_tbl_n = 0;
static unsigned long  g_tbl_slot = 0;    /* .bss 里存放类表指针的槽地址 (可 base 相对固定) */

static volatile int           g_req_reset      = 0;
static volatile pid_t         g_req_pid        = 0;
static volatile int           g_req_pid_valid  = 0;
static volatile unsigned long g_req_base       = 0;
static volatile int           g_req_base_valid = 0;
static volatile int           g_req_dumpmeta   = 0;
static volatile unsigned long g_req_dump_size  = 0;
static char                   g_req_dump_path[160];
static volatile int           g_req_findmeta   = 0;
static volatile int           g_req_dumpall    = 0;
static char                   g_req_dumpall_path[160];
static volatile int           g_req_classinfo  = 0;
static char                   g_req_ci_name[40];
static char                   g_req_ff_name[48];
static volatile int           g_req_findfield = 0;
static volatile int           g_req_findstatic = 0;
static volatile unsigned long g_req_fs_addr = 0;
static volatile unsigned long g_req_fields_addr = 0;
static volatile int           g_req_fields_valid = 0;
static volatile unsigned long g_req_scanseq_stride = 0;
static volatile int           g_req_scanseq_valid = 0;
static volatile unsigned int  g_req_scanval_val = 0;
static volatile int           g_req_scanval_valid = 0;
static volatile int           g_req_findobj    = 0;
static char                   g_req_fo_name[48];
static volatile int           g_req_findpid    = 0;
static char                   g_req_fp_name[64];
/*
 * [历史参考 / 已下线] 对局英雄数据读取相关状态、请求变量与导出协议:
 *
 * 1. JSON 导出 schema (_doc):
 *    {
 *      "seq": 输出序号,每次+1, "n": 角色总数, "heroes": [
 *        { "i": 下标, "a": actor内存地址, "camp": 阵营(1左/2右), "objid": 对象ID, "hero": 英雄ID,
 *          "hp": 当前血量, "hpmax": 最大血量, "exp": 经验, "lvl": 等级, "gold": 金币,
 *          "x": 坐标X(厘米), "y": 坐标Y, "z": 坐标Z, "move": 移速, "dead": 死亡标志, "grass": 草丛,
 *          "skills": [ {"s": 槽位0..5, "cd": 当前CD毫秒, "cdmax": 最大CD毫秒, "ready": 是否可用} ],
 *          "eq": [ [装备ID, 数量] ] }
 *      ]
 *    }
 *
 * 2. 定长二进制共享协议 (HR01 - seqlock):
 *    struct hb_hdr: magic 0x48523031, version 1, seq (写时奇数/稳态偶数), rec_size 64, max_rec 16, n 英雄数
 *    struct hb_rec: heroid, camp, hp, hpmax, x, y, z (厘米), dead, me (本机), skills[6], equips[8]
 *
 * 现已下线所有对局数据的后台常驻读取与写入。
 */

static volatile int           g_req_walk       = 0;
static volatile unsigned long g_req_peek_addr  = 0;
static volatile int           g_req_peek_count = 0;
static volatile int           g_req_peek_valid = 0;
static volatile unsigned long g_req_name_addr  = 0;
static volatile int           g_req_name_valid = 0;
static volatile unsigned long g_req_dump_addr  = 0;
static volatile int           g_req_dump_words = 0;
static volatile int           g_req_dump_valid = 0;
/* gcwatch: 高频监视 GameCore 通知流 (SGamePInvoke 静态区) */
static volatile unsigned long g_req_gcw_sf    = 0;
static volatile int           g_req_gcw_ms    = 0;
static volatile long          g_req_gcw_sec   = 0;
static volatile int           g_req_gcw_valid = 0;

#define IO_CHUNK  (1u << 17)   /* 128KB: 原来 1MB 会把整个 .bss 顶到 ~1.02MB(模块内存上限), 再加静态量就崩 */
static char g_iobuf[IO_CHUNK];

/* ===== 方案2: 定长二进制 + seqlock (供 hero_bridge 与 App 高频消费) ===== */
#define HB_MAGIC   0x48523031u   /* "HR01" */
#define HB_VERSION 1u
#define HB_MAXREC  16
struct __attribute__((packed)) hb_eq { uint16_t id, cnt; };
struct __attribute__((packed)) hb_sk {
    uint8_t lvl, ready, lvlup, bean;
    int32_t cd, cdmax, power, powermax, tgt, hit;
};
struct __attribute__((packed)) hb_rec {
    uint32_t heroid, camp, objid;
    int32_t hp, hpmax, exp, expmax, lvl, gold, incgold;
    int32_t charge, chargemax, shield, shieldmax;
    int32_t x, y, z, fx, fz, move, groundy;
    int32_t mx, mz;                 /* 小地图 / 真实物理位置 */
    int32_t ad, def, res;
    uint32_t atktarget;
    uint8_t dead, dying, grass, freeze, battle, nomove, inroom, fantasy, autoai, lvis, cam, me;
    uint32_t eqn;
    struct hb_eq eq[8];
    struct hb_sk sk[6];
};
struct __attribute__((packed)) hb_hdr {
    uint32_t magic, version, seq, rec_size, max_rec, n;
    uint64_t ts_ms;
    uint32_t flags, rsv[7];
};

static char                   g_bin_path[160] = "/data/local/tmp/heroes.bin";
static int                    g_bin_interval  = 100; /* ms, 默认 100ms 刷新 */
static unsigned int           g_bin_seq       = 0;
static int                    g_bin_created   = 0;
static unsigned int           g_bin_ts        = 0;
static struct hb_rec          g_bin_rec[HB_MAXREC];
static unsigned int           g_bin_n         = 0;
static unsigned int           g_manual_me_hero = 0;
static unsigned int           g_manual_me_camp = 0;


/* ============================================================ 页表/物理读 (不取目标 mmap 锁) */
static inline unsigned long pa_to_kva(unsigned long pa)
{
    return pa + g_pa_to_va_delta;   /* PAGE_OFFSET - memstart_addr */
}

/* 模块自带的页表遍历: 等价 KP 的 pgtable_phys, 但**不做**它每次调用的
 * __flush_dcache_area(pgd, page_size)。那句 flush 在 ARM64 上是真的刷 4KB D-cache,
 * 而"读目标内存"每读一页都要调一次 -> 每 200ms 一轮 ≈600 次 = 2.4MB cache
 * clean+invalidate, 周期性打断游戏 cache/TLB (真机表现: 固定间隔卡顿)。
 * KP 自己另一套遍历 lkm/kpm/symbols.c:kp_kpm_pgtable_entry 全程也不做任何 cache
 * 维护照样正常, 原作者注释也写明那句只是"插一次函数调用" -> 不需要。 */
static unsigned long my_pgtable_phys(unsigned long pgd, unsigned long va)
{
    unsigned long pxd_bits = (unsigned long)g_page_shift - 3;
    unsigned long pxd_ptrs = 1UL << pxd_bits;
    unsigned long pxd_pa = 0, pxd_va = pgd;
    int lv;
    if (!pgd) return 0;
    __asm__ __volatile__("" ::: "memory");      /* 编译器屏障, 替代原来那次函数调用 */
    for (lv = 4 - g_page_level; lv < 4; lv++) {
        unsigned long shift = pxd_bits * (unsigned long)(4 - lv) + 3;
        unsigned long idx = (va >> shift) & (pxd_ptrs - 1);
        unsigned long desc = ((volatile unsigned long *)pxd_va)[idx];
        if ((desc & 3UL) == 3UL) {               /* table */
            pxd_pa = desc & (((1UL << (48 - g_page_shift)) - 1) << g_page_shift);
        } else if ((desc & 3UL) == 1UL) {        /* block */
            unsigned long bits = (unsigned long)(3 - lv) * pxd_bits;
            unsigned long block_bits = bits + (unsigned long)g_page_shift;
            pxd_pa = (desc & (((1UL << (48 - block_bits)) - 1) << block_bits)) +
                     (va & (((1UL << bits) - 1) << g_page_shift));
            break;
        } else {
            return 0;
        }
        pxd_va = pa_to_kva(pxd_pa);
    }
    return pxd_pa ? (pxd_pa + (va & ((1UL << g_page_shift) - 1))) : 0;
}

/* 页表翻译缓存: 一次采集内同一个页只走一次 pgtable_phys。
 * pgtable_phys 每次调用开头都会 __flush_dcache_area(pgd, 4096) (刷 4KB D-cache),
 * 一轮 do_heroes 要读几百个字段 -> 不缓存就会刷几百次, 周期性干扰游戏 cache/TLB。
 * 每轮 reader 循环开头整体失效 (最长陈旧 ~200ms)。 */
/* 读目标内存: 逐页 pgtable_phys → 线性映射 → memcpy。不可读页补零。 */
static int rm(void *dst, unsigned long uaddr, int len)
{
    unsigned char *d = (unsigned char *)dst;

    if (!g_pgd || len <= 0)
        return 0;
    while (len > 0) {
        unsigned long pgsz = 1UL << g_page_shift;
        unsigned long pgoff = uaddr & (pgsz - 1);
        unsigned long chunk = pgsz - pgoff;
        unsigned long va_page = uaddr & ~(pgsz - 1);
        unsigned long pa;
        unsigned idx = (unsigned int)((va_page >> 12) & 63UL);
        if (chunk > (unsigned long)len)
            chunk = (unsigned long)len;
        if (g_ptc_va[idx] == va_page)
            pa = g_ptc_pa[idx] + pgoff;
        else {
            pa = my_pgtable_phys(g_pgd, uaddr);
            if (pa) { g_ptc_pa[idx] = pa & ~(pgsz - 1); g_ptc_va[idx] = va_page; }
        }
        if (pa) {
            memcpy(d, (void *)pa_to_kva(pa & ~(pgsz - 1)) + pgoff, chunk);   /* -> kf_memcpy */
        } else {
            memset(d, 0, chunk);
        }
        d += chunk;
        uaddr += chunk;
        len -= (int)chunk;
    }
    return 1;
}

static unsigned long rptr(unsigned long addr)
{
    unsigned long v = 0;
    rm(&v, addr, 8);
    return untag(v);
}
static int r32(unsigned long addr, unsigned int *out) { return rm(out, addr, 4); }

static int rstr(unsigned long addr, char *buf, int maxlen)
{
    int i = 0;
    if (!addr || maxlen <= 1) { if (maxlen > 0) buf[0] = 0; return 0; }

#endif /* HR_INTERNAL_H */
