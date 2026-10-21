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
    while (i < maxlen - 1) {
        int want = maxlen - 1 - i;
        if (want > 64) want = 64;
        rm(buf + i, addr + (unsigned long)i, want);
        {
            int k;
            for (k = 0; k < want; k++) if (buf[i + k] == 0) { buf[i + k] = 0; return i + k; }
        }
        i += want;
    }
    buf[i] = 0;
    return i;
}

/* ---- 解析工具 ---- */
static int parse_dec(const char *s, long *out)
{
    long v = 0; int any = 0;
    while (*s == ' ') s++;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); any = 1; s++; }
    if (!any) return 0; *out = v; return 1;
}
static int parse_hex(const char *s, unsigned long *out)
{
    unsigned long v = 0; int any = 0;
    while (*s == ' ') s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    for (;;) {
        char c = *s; int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = v * 16 + (unsigned long)d; any = 1; s++;
    }
    if (!any) return 0; *out = v; return 1;
}

/* ============================================================ VMA
 * find_vma 是"调用者需持 mmap_lock"的裸函数 (6.6 为 maple tree, 无锁并发遍历可能 oops)。
 * 我们只在**有界遍历**期间持 mmap_read_lock, 很快释放; 不做 access_remote_vm 那种反复抢锁。 */
#define VMA_VM_START_OFF 0x00UL
#define VMA_VM_END_OFF   0x08UL
#define VMA_VM_FLAGS_OFF 0x20UL
#define VMA_WALK_MAX     20000

static void vma_fields(void *vma, unsigned long *s, unsigned long *e, unsigned long *fl)
{
    unsigned long a = 0, b = 0, c = 0;
    __builtin_memcpy(&a, (char *)vma + VMA_VM_START_OFF, 8);
    __builtin_memcpy(&b, (char *)vma + VMA_VM_END_OFF, 8);
    __builtin_memcpy(&c, (char *)vma + VMA_VM_FLAGS_OFF, 8);
    if (s) *s = a; if (e) *e = b; if (fl) *fl = c;
}

/* 找到包含 addr 的 VMA */
static int vma_containing(unsigned long addr, unsigned long *start,
                          unsigned long *end, unsigned long *flags)
{
    void *vma; unsigned long vs = 0, ve = 0, fl = 0;
    int locked = 0;
    if (!g_target_mm || !p_find_vma) return 0;
    if (p_mmap_read_lock && p_mmap_read_unlock) { p_mmap_read_lock(g_target_mm); locked = 1; }
    vma = p_find_vma(g_target_mm, addr);
    if (!vma) { if (locked) p_mmap_read_unlock(g_target_mm); return 0; }
    vma_fields(vma, &vs, &ve, &fl);
    if (locked) p_mmap_read_unlock(g_target_mm);
    if (addr < vs || addr >= ve) return 0;
    if (start) *start = vs; if (end) *end = ve; if (flags) *flags = fl;
    return 1;
}

/* ============================================================ base 定位 (ELF magic + assemblies 验证) */
typedef int (*vma_cb_t)(void *, unsigned long, unsigned long, unsigned long);

static int vma_walk(vma_cb_t cb, void *udata)
{
    unsigned long addr = 0; int count = 0;
    int locked = 0;
    if (!g_target_mm || !p_find_vma) return 0;
    /* find_vma 需持 mmap_read_lock (maple tree 无锁并发遍历可能 oops)。持锁仅限本次有界遍历,
     * 很快释放, 不会像 access_remote_vm 那样反复抢锁。 */
    if (p_mmap_read_lock && p_mmap_read_unlock) {
        p_mmap_read_lock(g_target_mm);
        locked = 1;
    }
    while (count < VMA_WALK_MAX) {
        void *vma = p_find_vma(g_target_mm, addr);
        unsigned long vs = 0, ve = 0, fl = 0;
        if (!vma) break;
        vma_fields(vma, &vs, &ve, &fl);
        if (!vs || ve <= vs || vs < addr) break;
        count++;
        if (cb && cb(udata, vs, ve, fl)) break;
        addr = ve;
        if ((count & 0x3ff) == 0 && p_kthread_should_stop && p_kthread_should_stop()) break;
    }
    if (locked) p_mmap_read_unlock(g_target_mm);
    return count;
}

static int elf_base_cb(void *udata, unsigned long start, unsigned long vend, unsigned long flags)
{
    unsigned long *out = udata;
    unsigned char magic[4] = {0};
    unsigned long dom, beg = 0, end = 0;

    if (!(flags & VM_READ) || (flags & VM_EXEC)) return 0;
    if (vend - start < (4UL << 20)) return 0;       /* 大库预筛 */
    rm(magic, start, 4);
    if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') return 0;
    dom = start + S_DOMAIN_ADDR;
    rm(&beg, dom + DOMAIN_ASM_BEGIN, 8);
    rm(&end, dom + DOMAIN_ASM_END, 8);
    beg = untag(beg); end = untag(end);
    if (beg < 0x100000000UL || end <= beg) return 0;
    if ((end - beg) % 8 != 0 || (end - beg) / 8 > 4000) return 0;
    *out = start;
    return 1;
}

/* [历史参考] 原 gc_base_cb (通过 GC_MANAGER_BSS_OFF 0x53ddb90 + UnitLabelFinder 定位 libGameCore.so 基址，已废弃，现使用 gcb_cb 的 ELF Build-ID 精确定位) */

static int base_looks_valid(unsigned long b)
{
    unsigned long beg = 0, end = 0;
    if (!b || b < 0x100000000UL) return 0;
    rm(&beg, b + S_DOMAIN_ADDR + DOMAIN_ASM_BEGIN, 8);
    rm(&end, b + S_DOMAIN_ADDR + DOMAIN_ASM_END, 8);
    beg = untag(beg); end = untag(end);
    if (beg < 0x100000000UL || end <= beg) return 0;
    if ((end - beg) % 8 != 0 || (end - beg) / 8 > 4000) return 0;
    return 1;
}

static void find_base(void)
{
    unsigned long found = 0;
    if (g_base || !g_target_mm || !p_find_vma) return;
    vma_walk(elf_base_cb, &found);
    if (found) {
        g_base = found;
        if (g_verbose) pr_info("[hero-reader] libil2cpp base=0x%lx\n", g_base);
    }
}

/* ============================================================ metadata 定位/校验/大小 */
static int md_validate(unsigned long md, unsigned int *ver_out, unsigned long span)
{
    unsigned int magic = 0, ver = 0;
    if (!md || span < MD_HEADER_SIZE) return 0;
    if (!r32(md, &magic) || magic != IL2CPP_MAGIC) return 0;
    if (!r32(md + 4, &ver) || ver < IL2CPP_VERSION_MIN || ver > IL2CPP_VERSION_MAX) return 0;
    {
        unsigned int cand[2] = { 0x18, 0x10 };
        unsigned int stroff = 0, strcnt = 0, stridx;
        char tmp[64]; int ci, ok = 0;
        for (ci = 0; ci < 2 && !ok; ci++) {
            if (!r32(md + cand[ci], &stroff) || !r32(md + cand[ci] + 4, &strcnt)) continue;
            if (stroff < MD_HEADER_SIZE || strcnt == 0 || stroff >= span) continue;
            stridx = stroff;
            if (rstr(md + stridx, tmp, sizeof(tmp)) <= 0) continue;
            {
                int i, printable = 0;
                for (i = 0; tmp[i] && i < 32; i++)
                    if ((unsigned char)tmp[i] >= 0x20 && (unsigned char)tmp[i] < 0x7f) { printable = 1; break; }
                if (printable) ok = 1;
            }
        }
        if (!ok) return 0;
    }
    if (ver_out) *ver_out = ver;
    return 1;
}

static int md_compute_size(unsigned long md, unsigned int ver, unsigned long span, unsigned long *out)
{
    unsigned char hdr[MD_HEADER_SIZE];
    unsigned long total = 0, maxoff = 0;
    int i, any = 0;
    if (!rm(hdr, md, sizeof(hdr))) return 0;
    if (ver == 29) {
        unsigned int toff = 0, tsz = 0, ioff = 0, isz = 0;
        __builtin_memcpy(&toff, hdr + 0xA0, 4); __builtin_memcpy(&tsz, hdr + 0xA4, 4);
        __builtin_memcpy(&ioff, hdr + 0xA8, 4); __builtin_memcpy(&isz, hdr + 0xAC, 4);
        if (toff < MD_HEADER_SIZE || toff >= span) return 0;
        if (tsz / 88 < 200 || tsz / 88 > 2000000) return 0;
        if ((unsigned long)toff + (unsigned long)tsz > span) return 0;
        if (ioff < MD_HEADER_SIZE || ioff >= span) return 0;
        if (isz / 40 < 1 || isz / 40 > 200000) return 0;
        for (i = 0; i < MD_HEADER_PAIRS; i++) {
            unsigned int off = 0, sz = 0;
            unsigned long end;
            __builtin_memcpy(&off, hdr + g_v29[i].hoff, 4);
            __builtin_memcpy(&sz, hdr + g_v29[i].hoff + 4, 4);
            if (off == 0 && sz == 0) continue;
            if (off < MD_HEADER_SIZE || off >= span) return 0;
            end = (unsigned long)off + (unsigned long)sz;
            if (end > total) total = end;
            if (off > maxoff) maxoff = off;
            any = 1;
        }
        if (any && total >= maxoff && total <= span) { *out = total; return 1; }
    }
    for (i = 0; i + 8 <= MD_HEADER_SIZE; i += 8) {
        unsigned int off = 0;
        __builtin_memcpy(&off, hdr + i, 4);
        if (off >= MD_HEADER_SIZE && off < span && off > maxoff) maxoff = off;
    }
    if (!maxoff) return 0;
    *out = span;
    return 1;
}

static unsigned long md_try_slot(unsigned long base, unsigned long off)
{
    unsigned long md = 0, ve = 0;
    if (!base) return 0;
    rm(&md, base + off, 8);
    md = untag(md);
    if (!md || md < 0x100000000UL) return 0;
    if (!vma_containing(md, NULL, &ve, NULL)) return 0;
    if (!md_validate(md, NULL, ve - md)) return 0;
    return md;
}

/* 有界: 只扫 s_domain 所在的 RW 区 (.bss, 约 18MB), 找指向 metadata 的指针 */
static unsigned long md_from_bss_scan(void)
{
    unsigned long vs = 0, ve = 0, off;
    if (!g_base || !vma_containing(g_base + S_DOMAIN_ADDR, &vs, &ve, NULL)) return 0;
    off = vs & ~7UL;
    while (off < ve) {
        unsigned long want = ve - off;
        int n, k;
        if (want > IO_CHUNK) want = IO_CHUNK;
        n = rm(g_iobuf, off, (int)want) ? (int)want : 0;
        if (n <= 0) break;
        for (k = 0; k + 8 <= n; k += 8) {
            unsigned long v, ve2 = 0;
            unsigned int magic = 0;
            __builtin_memcpy(&v, g_iobuf + k, 8);
            v = untag(v);
            if (v < 0x100000000UL || v > 0x20000000000UL) continue;
            if (!r32(v, &magic) || magic != IL2CPP_MAGIC) continue;
            if (vma_containing(v, NULL, &ve2, NULL) && md_validate(v, NULL, ve2 - v)) return v;
        }
        off += (unsigned long)n;
    }
    return 0;
}

static unsigned long md_locate(void)
{
    unsigned long md = 0;
    if (g_base) {
        md = md_try_slot(g_base, S_METADATA_SLOT0);
        if (!md) md = md_try_slot(g_base, S_METADATA_SLOT1);
    }
    if (!md) md = md_from_bss_scan();
    return md;
}

/* ============================================================ metadata 转储 (分批, 让出 CPU) */
static long md_dump(const char *path, unsigned long forced_size)
{
    void *f = NULL, *old_cred = NULL;
    long long pos = 0;
    unsigned long md, size = 0, off = 0, span = 0;
    unsigned int ver = 0;
    unsigned long written = 0, gaps = 0;
    int rc = 0;

    if (!g_target_mm) { pr_warn("[hero-reader] dumpmeta: mm 未锁定\n"); return -1; }
    md = md_locate();
    if (!md) { pr_warn("[hero-reader] dumpmeta: 未找到 metadata\n"); return -2; }
    if (!vma_containing(md, NULL, &span, NULL)) { pr_warn("[hero-reader] dumpmeta: VMA ?\n"); return -3; }
    span -= md;
    if (!md_validate(md, &ver, span)) { pr_warn("[hero-reader] dumpmeta: 校验失败\n"); return -4; }
    if (forced_size) size = forced_size;
    else if (!md_compute_size(md, ver, span, &size)) size = span;
    if (size == 0 || size > MD_MAX_SIZE) size = span;
    if (size > span) size = span;

    g_meta_addr = md; g_meta_size = size; g_meta_ver = ver;

    if (!p_filp_open || !p_kernel_write || !p_filp_close) return -5;
    if (g_io_cred && p_override_creds) old_cred = p_override_creds(g_io_cred);
    f = p_filp_open(path, KPM_O_WRONLY | KPM_O_CREAT | KPM_O_TRUNC, 0644);
    if (!f || (unsigned long)f >= (unsigned long)-4095UL) {
        if (old_cred && p_revert_creds) p_revert_creds(old_cred);
        pr_warn("[hero-reader] dumpmeta: 打开 '%s' 失败 (%lx)\n", path, (unsigned long)f);
        return -6;
    }
    while (off < size) {
        unsigned long want = size - off;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (p_kthread_should_stop && p_kthread_should_stop()) { rc = -7; break; }
        rm(g_iobuf, md + off, (int)want);                 /* 页表物理读, 不阻塞目标 */
        /* 统计不可读页 (rm 会补零) */
        {
            unsigned long p;
            for (p = 0; p < want; p += (1UL << g_page_shift)) {
                unsigned long pl = (want - p) > (1UL << g_page_shift) ? (1UL << g_page_shift) : (want - p);
                if (!my_pgtable_phys(g_pgd, md + off + p)) gaps += pl;
            }
        }
        if (p_kernel_write(f, g_iobuf, want, &pos) != (long)want) { rc = -8; break; }
        off += want; written += want;
        p_msleep(1);                                      /* 让出 CPU, 避免长时间占用 */
    }
    p_filp_close(f, NULL);
    if (old_cred && p_revert_creds) p_revert_creds(old_cred);
    g_dump_bytes = written; g_dump_done = 1;
    pr_info("[hero-reader] dumpmeta: %s metadata@0x%lx ver=%u size=%lu written=%lu gaps=%lu rc=%d\n",
            rc ? "中止" : "完成", md, ver, size, written, gaps, rc);
    return rc ? rc : (long)written;
}

/* ============================================================ 类/字段导出 (定点结构读, 无全内存扫描)
 * 偏移来源: 运行时 Il2CppClass->fields (每个 Il2CppField.offset@+0x18)。
 * 枚举方式: 在 .bss (有界结构区) 内定位全局类表 s_TypeInfoTable (指向一串 class 指针的数组),
 * 再逐个类读字段。全程页表物理读, 不取目标 mmap 锁, 不阻塞渲染。 */
#define CLASS_NAME_O   0x10UL
#define CLASS_NS_O     0x18UL
#define CLASS_FIELDS_O 0x80UL
#define CLASS_FCNT_O   0x124UL
#define CLASS_STATIC_FIELDS 0xB8UL   /* il2cpp_class_get_static_field_data */
#define FIELD_NAME_O   0x00UL
#define FIELD_TYPE_O   0x08UL
#define FIELD_OFF_O    0x18UL
#define PTR_LO         0x4000000000UL
#define PTR_HI         0x0000FFFFFFFFFFFFUL   /* 用户态 48 位上限; 之前 0x7200000000 太低, ASLR 高地址会误杀 */

static int cname_ok(unsigned long c)
{
    char nm[80];
    c = untag(c);
    if (c < PTR_LO || c > PTR_HI) return 0;
    if (rstr(rptr(c + CLASS_NAME_O), nm, sizeof(nm)) <= 0) return 0;
    return nm[0] != 0;
}

/* 类表校验: typeDef[0] 通常是 <Module>, 其槽位可能是 NULL, 不能只看 [0];
 * 只要前 8 项里存在任意一个合法类, 就认为这是一个类表。 */
static int table_ok(unsigned long t)
{
    int i;
    t = untag(t);
    if (t < PTR_LO || t > PTR_HI) return 0;
    for (i = 0; i < 8; i++) {
        unsigned long c = rptr(t + (unsigned long)i * 8);
        if (c && cname_ok(c)) return 1;
    }
    return 0;
}

/* 用一个 typeDef 索引的期望类名 (来自 metadata) 校验类表对齐 (强判据) */
static int table_name_at(unsigned long md, unsigned long stroff, unsigned long tdoff,
                         unsigned long table, unsigned long idx)
{
    unsigned int ni = 0;
    unsigned long c, np;
    char exp[96], act[96];
    if (!rm(&ni, md + tdoff + idx * 88, 4)) return 0;
    if (rstr(md + stroff + ni, exp, sizeof(exp)) <= 0) return 0;
    c = rptr(table + idx * 8);
    if (!c) return 0;
    np = rptr(c + CLASS_NAME_O);
    if (rstr(np, act, sizeof(act)) <= 0) return 0;
    return strcmp(exp, act) == 0;
}

/* 在 .bss 找指向"类指针数组"(s_TypeInfoTable, 按 typeDef 索引) 的指针。
 * 若已定位 metadata, 用 metadata 的期望类名做强对齐校验; 否则退回"连续类"启发式。 */
static unsigned long find_typeinfo_table(unsigned long *cnt)
{
    unsigned long vs = 0, ve = 0, off, best = 0, bestlen = 0;
    unsigned long md;
    unsigned long stroff = 0, tdoff = 0;
    int have_md = 0;
    /* 零扫描快路径: 类表指针存放在固定 .bss 槽 base+0xE345028 */
    if (g_base) {
        unsigned long t = rptr(g_base + 0xE345028UL);
        if (t && t == g_tbl) { if (cnt) *cnt = g_tbl_n ? g_tbl_n : 70000; return t; }   /* 已校验过, 零读 */
        { int ok = t ? table_ok(t) : 0;
          if (g_verbose) pr_info("[hero-reader] 零扫描? base+0xE345028 -> 0x%lx ok=%d\n", t, ok);
          if (ok) { if (!g_tbl_n) g_tbl_n = 70000; g_tbl = t; if (cnt) *cnt = g_tbl_n; return t; } }
    }
    /* 缓存: 类表已解析且仍有效 → 直接返回, 不再扫 .bss */
    if (g_tbl && table_ok(g_tbl)) {
        if (cnt) *cnt = g_tbl_n;
        return g_tbl;
    }
    md = g_meta_addr ? g_meta_addr : md_locate();
    if (md) {
        if (rm(&stroff, md + 0x18, 4) && rm(&tdoff, md + 0xA0, 4) && stroff && tdoff)
            have_md = 1;
    }
    if (!g_base || !vma_containing(g_base + S_DOMAIN_ADDR, &vs, &ve, NULL))
        return 0;
    for (off = vs & ~7UL; off < ve; off += IO_CHUNK) {
        unsigned long want = ve - off;
        int n, k;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, off, (int)want)) break;
        n = (int)want;
        for (k = 0; k + 8 <= n; k += 8) {
            unsigned long w;
            __builtin_memcpy(&w, g_iobuf + k, 8);
            w = untag(w);
            if (w < PTR_LO || w > PTR_HI) continue;
            if (!table_ok(w)) continue;                  /* 前若干项里要有合法类 ([0] 可能为 NULL) */

            if (have_md) {
                /* 强判据: 多个 typeDef 索引处 名字必须与 metadata 一致 */
                static const unsigned long idxs[] = { 1, 3000, 15000, 30000, 45000, 60000 };
                int pi, ok = 0, tried = 0;
                for (pi = 0; pi < 6; pi++) {
                    unsigned long idx = idxs[pi];
                    unsigned long c = rptr(w + idx * 8);
                    if (!c) continue;                    /* 该 typeDef 无类, 跳过 */
                    tried++;
                    if (table_name_at(md, stroff, tdoff, w, idx)) ok++;
                }
                if (tried >= 3 && ok == tried) {
                    /* 计一次全表有效类数, 作为长度参考 */
                    unsigned long i, valid = 0;
                    for (i = 0; i < 70000; i++)
                        if (cname_ok(rptr(w + i * 8))) valid++;
                    best = w; bestlen = valid;
                    g_tbl_slot = off + (unsigned long)k;   /* 记录槽地址 */
                    goto done;
                }
            } else {
                static const unsigned long probe[] = { 1, 2, 100, 1000, 10000, 60000 };
                unsigned long hits = 0;
                int pi;
                for (pi = 0; pi < 6; pi++) {
                    if (cname_ok(rptr(w + probe[pi] * 8))) hits++;
                    else break;
                }
                if (hits >= 5) {
                    unsigned long len = 0, i;
                    for (i = 0; i < 70000; i++) {
                        if (cname_ok(rptr(w + i * 8))) len++;
                        else if (i > len + 64) break;
                    }
                    if (len > bestlen) { bestlen = len; best = w; }
                }
            }
        }
    }
done:
    if (cnt) *cnt = bestlen;
    if (best) { g_tbl = best; g_tbl_n = bestlen; }   /* 缓存 */
    if (best && g_verbose)
        pr_info("[hero-reader] 类表 0x%lx 有效类=%lu (md=%d)\n", best, bestlen, have_md);
    return best;
}

static int name_printable(const char *s)
{
    int i;
    if (!s[0]) return 0;
    for (i = 0; s[i] && i < 64; i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] == 0x7f) return 0;
    return 1;
}

static const struct { unsigned char et; const char *nm; } g_prim[] = {
    { 1, "void" }, { 2, "bool" }, { 3, "char" }, { 4, "sbyte" }, { 5, "byte" },
    { 6, "short" }, { 7, "ushort" }, { 8, "int" }, { 9, "uint" }, { 10, "long" },
    { 11, "ulong" }, { 12, "float" }, { 13, "double" }, { 14, "string" },
    { 22, "TypedReference" }, { 24, "IntPtr" }, { 25, "UIntPtr" }, { 28, "object" },
    { 0, 0 }
};

static void klass_full_name(unsigned long k, char *out, int n)
{
    char ns[64], nm[64];
    out[0] = 0; ns[0] = 0; nm[0] = 0;
    k = untag(k);
    if (!k) return;
    if (rstr(rptr(k + CLASS_NS_O), ns, sizeof(ns)) < 0) ns[0] = 0;
    if (rstr(rptr(k + CLASS_NAME_O), nm, sizeof(nm)) < 0) nm[0] = 0;
    if (ns[0]) snprintf(out, n, "%s.%s", ns, nm);
    else       snprintf(out, n, "%s", nm);
}

static void field_type_name(unsigned long tp, char *out, int n, int d)
{
    unsigned long data = 0;
    unsigned int bits = 0;
    int et, i;
    char sub[96];
    out[0] = 0;
    if (!tp || d > 4) { snprintf(out, n, "?"); return; }
    if (!r32(tp + 8, &bits)) { snprintf(out, n, "?"); return; }
    et = (bits >> 16) & 0xff;
    for (i = 0; g_prim[i].nm; i++)
        if (g_prim[i].et == et) { snprintf(out, n, "%s", g_prim[i].nm); return; }
    if (!rm(&data, tp, 8)) { snprintf(out, n, "?"); return; }
    data = untag(data);
    if (et == 0x11 || et == 0x12) { klass_full_name(data, out, n); if (!out[0]) snprintf(out, n, "VT:0x%lx", data); return; }
    if (et == 0x0f) { field_type_name(data, sub, sizeof(sub), d + 1); snprintf(out, n, "%s*", sub); return; }
    if (et == 0x1d) { field_type_name(data, sub, sizeof(sub), d + 1); snprintf(out, n, "%s[]", sub); return; }
    if (et == 0x15) {   /* GENERICINST: Il2CppGenericClass { typeDefinitionIndex; class_inst@+8; method_inst; cached_class@+0x18 } */
        unsigned long ci = rptr(data + 8), cls = rptr(data + 0x18), argv = 0;
        unsigned int argc = 0, k;
        int pos;
        char base[64] = "gen";
        if (cls) { char tmp[64]; rstr(rptr(cls + CLASS_NAME_O), tmp, sizeof(tmp)); if (tmp[0]) snprintf(base, sizeof(base), "%s", tmp); }
        if (ci) { rm(&argc, ci, 4); argv = rptr(ci + 8); }
        pos = snprintf(out, n, "%s", base);
        if (pos < 0) pos = 0;
        if (argv && argc >= 1 && argc <= 8) {
            if (pos < n) pos += snprintf(out + pos, (size_t)(n - pos), "<");
            for (k = 0; k < argc && pos < n - 1; k++) {
                char sub[96];
                int w;
                field_type_name(rptr(argv + k * 8), sub, sizeof(sub), d + 1);
                w = snprintf(out + pos, (size_t)(n - pos), "%s%s", k ? "," : "", sub);
                if (w > 0) pos += (pos + w < n) ? w : (n - pos - 1);
            }
            if (pos < n) snprintf(out + pos, (size_t)(n - pos), ">");
        }
        return;
    }
    snprintf(out, n, "type<%d>", et);
}

struct dumpall_ctx { void *f; long long pos; unsigned long classes, fields, written, uninit, namemiss; int failed; };

static int dwrite(struct dumpall_ctx *c, const char *s, int len)
{
    if (c->failed || len <= 0) return 0;
    if (p_kernel_write(c->f, s, (unsigned long)len, &c->pos) != len) { c->failed = 1; return 0; }
    c->written += (unsigned long)len;
    return 1;
}

static long do_dumpall(const char *path)
{
    void *f = NULL, *old_cred = NULL;
    struct dumpall_ctx ctx;
    unsigned long table, total = 0, i;

    if (!g_target_mm) { pr_warn("[hero-reader] dumpall: mm 未锁定\n"); return -1; }
    if (!g_base) find_base();
    if (!g_base) { pr_warn("[hero-reader] dumpall: base 未就绪\n"); return -1; }
    if (!p_filp_open || !p_kernel_write || !p_filp_close) return -1;

    /* 类名/字段名都来自 metadata 字符串表 (file-backed); 页表物理读不触发缺页,
     * 已驻留的页可直接读, 未驻留的会读成 0 (由 name_printable/cname_ok 过滤)。 */
    {
        unsigned long md = g_meta_addr ? g_meta_addr : md_locate();
        if (md) g_meta_addr = md;
    }
    table = find_typeinfo_table(&total);
    if (!table) { pr_warn("[hero-reader] dumpall: 未找到类表\n"); return -1; }
    pr_info("[hero-reader] dumpall: 类表=0x%lx 约 %lu 类\n", table, total);

    if (g_io_cred && p_override_creds) old_cred = p_override_creds(g_io_cred);
    f = p_filp_open(path, KPM_O_WRONLY | KPM_O_CREAT | KPM_O_TRUNC, 0644);
    if (!f || (unsigned long)f >= (unsigned long)-4095UL) {
        if (old_cred && p_revert_creds) p_revert_creds(old_cred);
        pr_warn("[hero-reader] dumpall: 打开 '%s' 失败\n", path);
        return -1;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.f = f;

    for (i = 0; i < 70000 && !ctx.failed; i++) {
        unsigned long c = rptr(table + i * 8);
        unsigned int fc = 0;
        unsigned long fields;
        char nm[80], ns[64], line[400];
        if (!cname_ok(c)) continue;
        if (p_kthread_should_stop && p_kthread_should_stop()) break;
        rstr(rptr(c + CLASS_NAME_O), nm, sizeof(nm));
        ns[0] = 0; rstr(rptr(c + CLASS_NS_O), ns, sizeof(ns));
        rm(&fc, c + CLASS_FCNT_O, 2);
        if (fc > 2000) continue;
        fields = rptr(c + CLASS_FIELDS_O);
        if (fc > 0 && !fields) ctx.uninit++;
        snprintf(line, sizeof(line), "\n// 0x%lx\npublic class %s { // ns=%s fields=%u\n",
                 c, nm, ns, fc);
        dwrite(&ctx, line, (int)strlen(line));
        {
            unsigned int k;
            for (k = 0; fields && k < fc && k < 300; k++) {
                unsigned long fl = fields + (unsigned long)k * 0x20;  /* FieldInfo = 32B 结构数组 */
                unsigned long np, tp;
                char fname[96], tname[96];
                int foff = 0; unsigned int attrs = 0;
                if (!fl) continue;
                np = rptr(fl + FIELD_NAME_O);
                if (rstr(np, fname, sizeof(fname)) <= 0 || !name_printable(fname)) { ctx.namemiss++; continue; }
                tp = rptr(fl + FIELD_TYPE_O);
                field_type_name(tp, tname, sizeof(tname), 0);
                rm(&foff, fl + FIELD_OFF_O, 4);
                r32((tp & PTR_MASK) + 8, &attrs);
                snprintf(line, sizeof(line), "    // 0x%X %s %s %s;\n",
                         (unsigned)foff, (attrs & 0x10) ? "static" : "      ", tname, fname);
                dwrite(&ctx, line, (int)strlen(line));
                ctx.fields++;
            }
        }
        dwrite(&ctx, "}\n", 2);
        ctx.classes++;
        if ((ctx.classes & 0x3f) == 0) p_msleep(1);
    }

    p_filp_close(f, NULL);
    if (old_cred && p_revert_creds) p_revert_creds(old_cred);
    pr_info("[hero-reader] dumpall: %s classes=%lu fields=%lu uninit=%lu namemiss=%lu written=%lu -> %s\n",
            ctx.failed ? "中止" : "完成", ctx.classes, ctx.fields, ctx.uninit, ctx.namemiss, ctx.written, path);
    return ctx.failed ? -1 : (long)ctx.classes;
}

/* 定点打印某个类的字段(偏移/类型/名); 名字子串匹配。用于对局内快速查看。 */
static void do_classinfo(const char *q)
{
    unsigned long table, total = 0, i;
    unsigned long md = g_meta_addr ? g_meta_addr : md_locate();
    int printed = 0;
    if (!g_target_mm) { pr_warn("[hero-reader] classinfo: mm 未锁定\n"); return; }
    if (!g_base) find_base();
    if (!md) { pr_warn("[hero-reader] classinfo: metadata 未就绪\n"); return; }
    g_meta_addr = md;
    table = find_typeinfo_table(&total);
    if (!table) { pr_warn("[hero-reader] classinfo: 未找到类表\n"); return; }
    for (i = 0; i < 70000 && printed < 8; i++) {
        unsigned long c = rptr(table + i * 8), fields, sf = 0;
        char nm[96], ns[64];
        unsigned int fc = 0, k;
        if (!c) continue;
        if (rstr(rptr(c + CLASS_NAME_O), nm, sizeof(nm)) <= 0) continue;
        if (!strstr(nm, q)) continue;
        ns[0] = 0; rstr(rptr(c + CLASS_NS_O), ns, sizeof(ns));
        rm(&fc, c + CLASS_FCNT_O, 2);
        fields = rptr(c + CLASS_FIELDS_O);
        rm(&sf, c + CLASS_STATIC_FIELDS, 8);
        pr_info("[hero-reader] classinfo: %s.%s class=0x%lx static_fields=0x%lx fields=%u\n",
                ns, nm, c, untag(sf), fc);
        for (k = 0; fields && k < fc && k < 120; k++) {
            unsigned long fl = fields + (unsigned long)k * 0x20;
            unsigned long np = rptr(fl + FIELD_NAME_O), tp = rptr(fl + FIELD_TYPE_O);
            char fname[96], tname[96];
            int foff = 0; unsigned int attrs = 0;
            if (rstr(np, fname, sizeof(fname)) <= 0 || !name_printable(fname)) continue;
            field_type_name(tp, tname, sizeof(tname), 0);
            rm(&foff, fl + FIELD_OFF_O, 4);
            r32((tp & PTR_MASK) + 8, &attrs);
            pr_info("[hero-reader]   0x%-4X %s %s %s\n", (unsigned)foff,
                    (attrs & 0x10) ? "static" : "      ", tname, fname);
        }
        printed++;
    }
    if (!printed)
        pr_warn("[hero-reader] classinfo: 未找到类 (子串 '%s')\n", q);
}

/* 按字段名子串搜类 (遍历类表)。用于定位 攻击/防御 等属性字段。 */
static void do_findfield(const char *q)
{
    unsigned long table, total = 0, i;
    unsigned long md = g_meta_addr ? g_meta_addr : md_locate();
    int printed = 0;
    if (!g_target_mm) { pr_warn("[hero-reader] findfield: mm 未锁定\n"); return; }
    if (!g_base) find_base();
    if (md) g_meta_addr = md;
    table = find_typeinfo_table(&total);
    if (!table) { pr_warn("[hero-reader] findfield: 未找到类表\n"); return; }
    for (i = 0; i < 70000 && printed < 80; i++) {
        unsigned long c = rptr(table + i * 8), fields;
        char nm[96], ns[64];
        unsigned int fc = 0, k;
        if (!c) continue;
        if (rstr(rptr(c + CLASS_NAME_O), nm, sizeof(nm)) <= 0) continue;
        rm(&fc, c + CLASS_FCNT_O, 2);
        if (!fc) continue;
        fields = rptr(c + CLASS_FIELDS_O);
        if (!fields) continue;
        for (k = 0; k < fc && k < 120; k++) {
            unsigned long fl = fields + (unsigned long)k * 0x20;
            unsigned long np = rptr(fl + FIELD_NAME_O);
            char fname[96];
            int foff = 0;
            if (rstr(np, fname, sizeof(fname)) <= 0) continue;
            if (!strstr(fname, q)) continue;
            ns[0] = 0; rstr(rptr(c + CLASS_NS_O), ns, sizeof(ns));
            rm(&foff, fl + FIELD_OFF_O, 4);
            pr_info("[hero-reader] fld: %s.%s +0x%X %s\n", ns, nm, (unsigned)foff, fname);
            if (++printed >= 80) break;
        }
    }
    if (!printed)
        pr_warn("[hero-reader] findfield: 无匹配 '%s'\n", q);
}

/* 遍历类表的"静态字段"，找出值指向目标类实例的那些静态槽 (无堆扫描)。
 * 用法: findstatic 0x<类地址>   例: findstatic 0x76711e1780  (CameraSystem) */
static void do_findstatic(unsigned long target)
{
    unsigned long table, total = 0, i;
    int printed = 0;
    if (!g_target_mm) { pr_warn("[hero-reader] findstatic: mm 未锁定\n"); return; }
    if (!g_base) find_base();
    table = find_typeinfo_table(&total);
    if (!table) { pr_warn("[hero-reader] findstatic: 未找到类表\n"); return; }
    for (i = 0; i < 70000 && printed < 40; i++) {
        unsigned long c = rptr(table + i * 8), fields, sf;
        char nm[96], ns[64];
        unsigned int fc = 0, k;
        if (!c || !cname_ok(c)) continue;
        if (rstr(rptr(c + CLASS_NAME_O), nm, sizeof(nm)) <= 0) continue;
        rm(&fc, c + CLASS_FCNT_O, 2);
        if (!fc || fc > 2000) continue;
        fields = rptr(c + CLASS_FIELDS_O);
        sf = rptr(c + CLASS_STATIC_FIELDS);
        if (!fields || !sf) continue;
        for (k = 0; k < fc && k < 300 && printed < 40; k++) {
            unsigned long fl = fields + (unsigned long)k * 0x20;
            unsigned long tp, v = 0;
            unsigned int attrs = 0;
            int foff = 0;
            char fname[96];
            if (rstr(rptr(fl + FIELD_NAME_O), fname, sizeof(fname)) <= 0) continue;
            tp = rptr(fl + FIELD_TYPE_O);
            if (tp) r32((tp & PTR_MASK) + 8, &attrs);
            if (!(attrs & 0x10)) continue;            /* 只看 static */
            rm(&foff, fl + FIELD_OFF_O, 4);
            if (foff < 0 || foff > 0x8000) continue;
            if (!rm(&v, sf + (unsigned long)foff, 8)) continue;
            if (untag(v) != target) continue;
            ns[0] = 0; rstr(rptr(c + CLASS_NS_O), ns, sizeof(ns));
            pr_info("[hero-reader] static: %s.%s +0x%X -> 0x%lx (cls 0x%lx sf 0x%lx)\n",
                    ns, nm, (unsigned)foff, untag(v), c, sf);
            printed++;
        }
    }
    if (!printed)
        pr_warn("[hero-reader] findstatic: 0x%lx 无静态引用 (类表 %lu 项)\n", target, total);
    else
        pr_info("[hero-reader] findstatic: 0x%lx 命中 %d\n", target, printed);
}

/* 按类指针导出字段 (绕过按名匹配)。 */
static void do_fields(unsigned long c)
{
    unsigned int fc = 0, k;
    unsigned long fields;
    char nm[96], ns[64];
    if (!c) return;
    if (rstr(rptr(c + CLASS_NAME_O), nm, sizeof(nm)) <= 0) nm[0] = 0;
    ns[0] = 0; rstr(rptr(c + CLASS_NS_O), ns, sizeof(ns));
    rm(&fc, c + CLASS_FCNT_O, 2);
    fields = rptr(c + CLASS_FIELDS_O);
    pr_info("[hero-reader] fields class=0x%lx %s.%s fields=%u\n", c, ns, nm, fc);
    for (k = 0; fields && k < fc && k < 160; k++) {
        unsigned long fl = fields + (unsigned long)k * 0x20;
        unsigned long np = rptr(fl + FIELD_NAME_O), tp = rptr(fl + FIELD_TYPE_O);
        char fname[96], tname[96];
        int foff = 0;
        if (rstr(np, fname, sizeof(fname)) <= 0) continue;
        field_type_name(tp, tname, sizeof(tname), 0);
        rm(&foff, fl + FIELD_OFF_O, 4);
        pr_info("[hero-reader]   0x%-4X %s %s\n", (unsigned)foff, tname, fname);
    }
}

/* ===== C1b: 扫描 rw 内存, 找"按固定步长递增的 ID 列"(英雄配置数组特征) ===== */
struct ss_ctx { unsigned long stride; int hits; };

static int ss_cb(void *udata, unsigned long start, unsigned long end, unsigned long flags)
{
    struct ss_ctx *c = udata;
    unsigned long S = c->stride, off = 0, total = end - start;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && c->hits < 16) {
        unsigned long want = total - off, p;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        for (p = 0; p + 100 * S + 4 <= want; p += 4) {
            unsigned int v0, prev; int i, ok = 1;
            __builtin_memcpy(&v0, g_iobuf + p, 4);
            if (v0 < 1 || v0 > 500) continue;
            prev = v0;
            for (i = 1; i < 100; i++) {
                unsigned int v;
                __builtin_memcpy(&v, g_iobuf + p + (unsigned long)i * S, 4);
                if (v <= prev || v - prev > 200) { ok = 0; break; }
                prev = v;
            }
            if (ok) {
                pr_info("[hero-reader] scanseq: base=0x%lx stride=0x%lx v0=%u vN=%u\n",
                        start + off + p, S, v0, prev);
                if (++c->hits >= 16) return 1;
            }
        }
        off += (unsigned long)want;
    }
    return 0;
}

static void do_scanseq(unsigned long stride)
{
    struct ss_ctx c;
    if (!g_target_mm) { pr_warn("[hero-reader] scanseq: mm 未锁定\n"); return; }
    if (stride < 0x8 || stride > 0x4000) { pr_warn("[hero-reader] scanseq: stride 非法\n"); return; }
    c.stride = stride; c.hits = 0;
    vma_walk(ss_cb, &c);
    if (!c.hits) pr_warn("[hero-reader] scanseq: stride=0x%lx 无命中\n", stride);
}

/* 扫描 rw 内存找某个 4 字节整数值 (定位运行时属性用) */
static unsigned int g_sv_val; static int g_sv_hits;
static int sv_cb(void *udata, unsigned long start, unsigned long end, unsigned long flags)
{
    unsigned long off = 0, total = end - start;
    (void)udata;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && g_sv_hits < 60) {
        unsigned long want = total - off, p;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        for (p = 0; p + 4 <= want; p += 4) {
            unsigned int v;
            __builtin_memcpy(&v, g_iobuf + p, 4);
            if (v == g_sv_val) {
                unsigned int nxt = 0;
                if (p + 8 <= want) __builtin_memcpy(&nxt, g_iobuf + p + 8, 4);
                if (nxt == g_sv_val + 1) continue;   /* 跳过 递增数组 误报 */
                pr_info("[hero-reader] scanval %u: 0x%lx\n", g_sv_val, start + off + p);
                if (++g_sv_hits >= 60) return 1;
            }
        }
        off += (unsigned long)want;
    }
    return 0;
}

/* scanids <stride_hex> <id_off_hex> <id1> <id2> <id3> <id4>(hex):
 * 找"原生 actor 表": 连续 4 条记录(步长 S)的 +id_off 恰好等于这 4 个 objid (任意顺序).
 * 随机命中率 ~ (4/2^32)^4, 极高选择性. */
static unsigned long g_si_stride = 0, g_si_idoff = 0;
static unsigned int  g_si_ids[4];
static int           g_si_hits = 0;
static volatile int  g_req_scanids_valid = 0;

static int si_cb(void *udata, unsigned long start, unsigned long end, unsigned long flags)
{
    unsigned long off = 0, total = end - start, S = g_si_stride, D = g_si_idoff;
    (void)udata;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && g_si_hits < 40) {
        unsigned long want = total - off, p;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        for (p = 0; p + D + S * 3 + 4 <= want; p += 4) {
            unsigned int seen = 0; int k, ok = 1;
            for (k = 0; k < 4; k++) {
                unsigned int v; int j, hit = -1;
                __builtin_memcpy(&v, g_iobuf + p + D + S * (unsigned long)k, 4);
                for (j = 0; j < 4; j++) if (g_si_ids[j] == v) { hit = j; break; }
                if (hit < 0 || (seen & (1u << hit))) { ok = 0; break; }
                seen |= (1u << hit);
            }
            if (!ok) continue;
            pr_info("[hero-reader] scanids: 表 @0x%lx stride=0x%lx idoff=0x%lx\n",
                    start + off + p, S, D);
            if (++g_si_hits >= 40) return 1;
        }
        off += want;
    }
    return 0;
}

static void do_scanids(unsigned long S, unsigned long D)
{
    if (!g_target_mm) { pr_warn("[hero-reader] scanids: mm 未锁定\n"); return; }
    if (S < 0x10 || S > 0x10000) { pr_warn("[hero-reader] scanids: stride 非法\n"); return; }
    g_si_stride = S; g_si_idoff = D; g_si_hits = 0;
    pr_info("[hero-reader] scanids 开始: stride=0x%lx idoff=0x%lx ids=%u,%u,%u,%u\n",
            S, D, g_si_ids[0], g_si_ids[1], g_si_ids[2], g_si_ids[3]);
    vma_walk(si_cb, NULL);
    if (!g_si_hits) pr_warn("[hero-reader] scanids: 无命中\n");
}


/* tabdump <base_hex> <stride_hex> <n>: 打印"原生 actor 记录"关键字段 */
static unsigned long g_td_base = 0, g_td_S = 0; static int g_td_n = 0;
static volatile int  g_req_tabdump_valid = 0;
static void do_tabdump(unsigned long base, unsigned long S, int n)
{
    int k;
    if (!base || !S) { pr_warn("[hero-reader] tabdump: 参数\n"); return; }
    if (n <= 0 || n > 64) n = 16;
    pr_info("[hero-reader] tabdump base=0x%lx stride=0x%lx n=%d\n", base, S, n);
    for (k = 0; k < n; k++) {
        unsigned long r = base + (unsigned long)k * S, bmp = 0;
        unsigned int t = 0, a = 0, b = 0, x = 0, y = 0, z = 0, f = 0, blen = 0;
        r32(r + 4, &t); r32(r + 0x14, &a); r32(r + 0x18, &b);
        r32(r + 0x20, &x); r32(r + 0x24, &y); r32(r + 0x28, &z);
        r32(r + 0x358, &f);
        bmp = rptr(r + 0x230); r32(r + 0x238, &blen);
        pr_info("[hero-reader]  [%2d] 0x%lx type=%-4u id14=%-4u id18=%-4u int20=%-8d int24=%-8d int28=%-8d bmp=0x%lx blen=%-3u f358=%u\n",
                k, r, t, a, b, (int)x, (int)y, (int)z, bmp, blen, f);
    }
}

static void do_scanval(unsigned int val)
{
    if (!g_target_mm) { pr_warn("[hero-reader] scanval: mm 未锁定\n"); return; }
    g_sv_val = val; g_sv_hits = 0;
    vma_walk(sv_cb, NULL);
    if (!g_sv_hits) pr_warn("[hero-reader] scanval %u: 无命中\n", val);
}

/* scanrec <stride_hex> [t1_hex] [t2_hex]: 找"原生 actor 表"数组
 * 指纹: 连续 3 条记录(步长 stride)的 +4 字段都 ∈ {t1,t2}  (默认 0x348 / 0x74 / 0x99)
 * 依据 libGameCore.so 反汇编: rec+4 是 actor 类型, 只处理 0x74/0x99 */
static unsigned long g_sr_stride = 0;
static unsigned int  g_sr_t1 = 0x74, g_sr_t2 = 0x99;
static int           g_sr_bm = 1;   /* 1=再校验 位图指针@+0x230 / 长度@+0x238 */
static int           g_sr_pm = 0;   /* 1=再校验 +0x20/+0x28 是 ±60000 量级坐标 int */
static int           g_sr_nrun = 6; /* 需连续匹配的记录数 */

static int sr_sane_i(unsigned int u)
{
    int v;
    __builtin_memcpy(&v, &u, 4);
    if (v < 0) v = (v == (int)0x80000000) ? 0x7FFFFFFF : -v;
    return (v >= 0x20 && v <= 0x12000);
}
static int           g_sr_hits = 0;
static volatile int  g_req_scanrec_valid = 0;

static int sr_cb(void *udata, unsigned long start, unsigned long end, unsigned long flags)
{
    unsigned long off = 0, total = end - start;
    unsigned long S = g_sr_stride;
    (void)udata;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && g_sr_hits < 40) {
        unsigned long want = total - off, p;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        for (p = 0; p + 4 + S * (unsigned long)(g_sr_nrun - 1) + 4 <= want; p += 4) {
            int ok = 1, k;
            for (k = 0; k < g_sr_nrun && ok; k++) {
                unsigned long rb = p + S * (unsigned long)k;
                unsigned int t;
                __builtin_memcpy(&t, g_iobuf + rb + 4, 4);
                if (t != g_sr_t1 && t != g_sr_t2) { ok = 0; break; }
                if (g_sr_pm) {
                    unsigned int vx, vy, vz;
                    __builtin_memcpy(&vx, g_iobuf + rb + 0x20, 4);
                    __builtin_memcpy(&vy, g_iobuf + rb + 0x24, 4);
                    __builtin_memcpy(&vz, g_iobuf + rb + 0x28, 4);
                    if (!sr_sane_i(vx) || !sr_sane_i(vz) || vy > 0x100) { ok = 0; break; }
                }
            }
            if (!ok) continue;
            if (g_sr_bm) {
                unsigned long sp = 0; unsigned int sc = 0;
                __builtin_memcpy(&sp, g_iobuf + p + 0x230, 8);
                if (sp < 0x100000000UL || sp > 0x800000000000UL) continue;
                __builtin_memcpy(&sc, g_iobuf + p + 0x238, 4);
                if (sc < 1 || sc > 0x1000) continue;
            }
            pr_info("[hero-reader] scanrec: 表 @0x%lx stride=0x%lx run=%d\n",
                    start + off + p, S, g_sr_nrun);
            if (++g_sr_hits >= 40) return 1;
        }
        off += want;
    }
    return 0;
}

static void do_scanrec(unsigned long S, unsigned int t1, unsigned int t2)
{
    if (!g_target_mm) { pr_warn("[hero-reader] scanrec: mm 未锁定\n"); return; }
    if (S < 0x10 || S > 0x10000) { pr_warn("[hero-reader] scanrec: stride 非法\n"); return; }
    g_sr_stride = S; g_sr_t1 = t1; g_sr_t2 = t2; g_sr_hits = 0;
    pr_info("[hero-reader] scanrec 开始: stride=0x%lx type=%u/%u\n", S, t1, t2);
    vma_walk(sr_cb, NULL);
    if (!g_sr_hits) pr_warn("[hero-reader] scanrec: 无命中\n");
}

/* scanlive: "未知值两遍扫描" — 找雾里仍在变化的坐标对 =====
 * 传入 x/z 的上下界(单调化后的 float 位模式), 找 (x, y≈0, z) 三连 float 向量。
 * y 限制为 |y|<=1 (用固定 key 区间)。 */
#define SL_YLO 0x407FFFFFu   /* key(-1.0f) */
#define SL_YHI 0xBF800000u   /* key(+1.0f) */
static unsigned int  g_sl_xlo, g_sl_xhi, g_sl_zlo, g_sl_zhi;
static int           g_sl_mode = 0;   /* 0=float(单调key) 1=int(直接比原始u32, y 必须为 0) */
static long          g_sl_wait = 5000;
static volatile int  g_req_scanlive_valid = 0;
static unsigned long g_sl_addrs[30000];
static int           g_sl_n = 0;

/* 把 float 位模式映射成单调递增的 unsigned (跨 0 也成立), 便于范围比较 */
static unsigned int sl_key(unsigned int v)
{
    return (v & 0x80000000u) ? ~v : (v | 0x80000000u);
}

static int sl_in(unsigned int v, unsigned int lo, unsigned int hi)
{
    unsigned int k = (g_sl_mode == 1) ? v : sl_key(v);
    return (k >= lo && k <= hi);
}

/* y 检查: float 模式 |y|<=1; int 模式必须恰好为 0 */
static int sl_yok(unsigned int by)
{
    if (g_sl_mode == 1) return (by == 0);
    return sl_in(by, SL_YLO, SL_YHI);
}

static int sl_cb(void *ud, unsigned long start, unsigned long end, unsigned long flags)
{
    unsigned long off = 0, total = end - start;
    (void)ud;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && g_sl_n < 30000) {
        unsigned long want = total - off;
        int n, p;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        n = (int)want;
        /* 按 4 字节步进找 (x, y≈0, z) 三连 float — 比"任意 8 字节对"强得多 */
        for (p = 0; p + 12 <= n; p += 4) {
            unsigned int bx, by, bz;
            int oy = (g_sl_mode == 2) ? 0 : 4;
            int oz = (g_sl_mode == 2) ? 4 : 8;
            __builtin_memcpy(&bx, g_iobuf + p, 4);
            __builtin_memcpy(&by, g_iobuf + p + oy, 4);
            __builtin_memcpy(&bz, g_iobuf + p + oz, 4);
            if (!sl_in(bx, g_sl_xlo, g_sl_xhi)) continue;
            if (!sl_in(bz, g_sl_zlo, g_sl_zhi)) continue;
            if (g_sl_mode != 2 && !sl_yok(by)) continue;
            g_sl_addrs[g_sl_n++] = start + off + (unsigned long)p;
            if (g_sl_n >= 30000) return 1;
        }
        off += (unsigned long)n;
    }
    return 0;
}

static void do_scanlive(void)
{
    int i, changed = 0;
    if (!g_target_mm) { pr_warn("[hero-reader] scanlive: mm 未锁定\n"); return; }
    g_sl_n = 0;
    vma_walk(sl_cb, NULL);
    pr_info("[hero-reader] scanlive: 候选 %d 个, 等 %ld ms 后回读...\n", g_sl_n, g_sl_wait);
    p_msleep((unsigned int)g_sl_wait);
    for (i = 0; i < g_sl_n && changed < 60; i++) {
        unsigned long a = g_sl_addrs[i];
        unsigned int bx = 0, by = 0, bz = 0;
        int oz = (g_sl_mode == 2) ? 4 : 8;
        if (!rm(&bx, a, 4)) continue;
        if (g_sl_mode != 2 && !rm(&by, a + 4, 4)) continue;
        if (!rm(&bz, a + oz, 4)) continue;
        if (sl_in(bx, g_sl_xlo, g_sl_xhi) && sl_in(bz, g_sl_zlo, g_sl_zhi) &&
            (g_sl_mode == 2 || sl_yok(by)))
            continue;
        pr_info("[hero-reader] scanlive 变化: 0x%lx [x %08x y %08x z %08x]\n", a, bx, by, bz);
        changed++;
    }
    pr_info("[hero-reader] scanlive 结束: 候选 %d, 变化 %d\n", g_sl_n, changed);
}

/* touch 命令已移除: 本模块不做任何 access_remote_vm / 缺页触发,
 * 只读已驻留页 (未驻留页读成 0, 由调用方校验过滤)。 */

/* 在 rw 内存里找某个类(按名)的对象实例: 对象首字段 == class 指针。物理读, 非阻塞。 */
static int  g_fo_hits;
static unsigned long g_fo_addrs[600];
static long g_fo_off[3] = {0,0,0};   /* >0: 额外要求 对象+off[i] 处都是合法指针 */
static int fobj_cb(void *udata, unsigned long start, unsigned long end, unsigned long flags)
{
    unsigned long klass = *(unsigned long *)udata, off = 0, total = end - start;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && g_fo_hits < 600) {
        unsigned long want = total - off;
        int n, k;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        n = (int)want;
        for (k = 0; k + 8 <= n; k += 8) {
            unsigned long w;
            __builtin_memcpy(&w, g_iobuf + k, 8);
            if (untag(w) == klass) {
                unsigned long obase = start + off + (unsigned long)k;
                int fi, ok = 1;
                for (fi = 0; fi < 3; fi++) {
                    if (g_fo_off[fi] > 0) {       /* 过滤: 对象+off 处必须是合法指针 */
                        unsigned long v = 0;
                        if (!rm(&v, obase + (unsigned long)g_fo_off[fi], 8)) { ok = 0; break; }
                        v = untag(v);
                        if (v < 0x4000000000UL || v > 0x0000FFFFFFFFFFFFUL) { ok = 0; break; }
                    }
                }
                /* 给了 3 个偏移时: 还要求这 3 个目标对象的 klass 相同 (同一个泛型类, 如 List<Vector3>) */
                if (ok && g_fo_off[0] > 0 && g_fo_off[1] > 0 && g_fo_off[2] > 0) {
                    unsigned long ks[3] = {0, 0, 0};
                    for (fi = 0; fi < 3; fi++) {
                        unsigned long v = 0, kk = 0;
                        if (!rm(&v, obase + (unsigned long)g_fo_off[fi], 8)) { ok = 0; break; }
                        v = untag(v);
                        if (!rm(&kk, v, 8)) { ok = 0; break; }
                        ks[fi] = untag(kk);
                    }
                    if (ok && !(ks[0] && ks[0] == ks[1] && ks[1] == ks[2])) ok = 0;
                }
                if (!ok) continue;
                g_fo_addrs[g_fo_hits++] = obase;
                if (g_fo_hits >= 600) return 1;
            }
        }
        off += (unsigned long)n;
    }
    return 0;
}

static void do_findobj(const char *q)
{
    unsigned long table, total = 0, i, klass = 0;
    unsigned long md = g_meta_addr ? g_meta_addr : md_locate();
    if (!g_target_mm) { pr_warn("[hero-reader] findobj: mm 未锁定\n"); return; }
    if (!g_base) find_base();
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
    int xx = 0, yy = 0, zz = 0;

    /* 路径 1: 权威物理变换链 Transform (帧同步模拟层真实世界坐标)
     * 单位: 毫米 (mm)，转换给上层使用时转为厘米 (/10)。
     * 地图边界约为 ±60000 毫米 (±60米)。 */
    if (rm(&node, actor + 0xA8UL, 8)) {
        node = untag(node);
        if (node > 0x100000000UL && node < 0x800000000000UL) {
            if (rm(&link, node + 0x10UL, 8)) {
                link = untag(link);
                if (link > 0x100000000UL && link < 0x800000000000UL) {
                    if (rm(&tr, link + 0x00UL, 8)) {
                        tr = untag(tr);
                        if (tr > 0x100000000UL && tr < 0x800000000000UL) {
                            if (rm(&p2, tr + 0x60UL, 8)) {
                                p2 = untag(p2);
                                if (p2 > 0x100000000UL && p2 < 0x800000000000UL) {
                                    rm(&xx, p2 + 0, 4);
                                    rm(&yy, p2 + 4, 4);
                                    rm(&zz, p2 + 8, 4);
                                    if (xx != 0 || zz != 0) {
                                        *ox = xx / 10;   /* 毫米转厘米 */
                                        *oy = yy / 10;
                                        *oz = zz / 10;
                                        return 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /* 路径 2: 结构体直读 +32 / +40 / +44 (兜底) */
    rm(&xx, actor + 32UL, 4);
    rm(&yy, actor + 40UL, 4);
    rm(&zz, actor + 44UL, 2);
    if (xx != 0 || zz != 0) {
        *ox = xx; *oy = yy; *oz = (int)zz;
        return 2;
    }
    return 0;
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
    memset(g_ptc_va, 0, sizeof(g_ptc_va));
    memset(g_ptc_pa, 0, sizeof(g_ptc_pa));
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

        /* 存活判定: enabled_flag 正常>=1 且 state_code!=1 (死亡态) */
        int is_dead = (enabled_flag < 1 || state_code == 1);

        pr_info("[hero-reader]   [#%02d] slot=%d hero=0x%lx cfg=%d camp=%u rt=%d pos=(%d,%d) cm en=%u st=%u dead=%d\n",
                valid, slot, hero_ptr, config_id, camp_raw, runtime_id, real_x, real_z, enabled_flag, state_code, is_dead);

        rb = &g_bin_rec[valid];
        rb->heroid = (uint32_t)config_id;
        rb->objid = (uint32_t)runtime_id;
        rb->x = real_x;
        rb->y = real_y;
        rb->z = real_z;
        rb->mx = real_x;
        rb->mz = real_z;
        rb->dead = (uint8_t)is_dead;
        rb->grass = is_in_grass;

        /* 阵营判定: 优先信任官方字段 camp_raw (+0x34) */
        if (camp_raw == 1 || camp_raw == 2) {
            rb->camp = camp_raw;
        } else {
            /* 蓝方左下负, 红方右上正 */
            rb->camp = (real_x + real_z >= 0) ? 2 : 1;
        }

        /* 本机玩家匹配 */
        if (g_manual_me_hero && (uint32_t)config_id == g_manual_me_hero) {
            rb->me = 1;
            if (g_manual_me_camp) rb->camp = g_manual_me_camp;
        }

        valid++;
    }

    g_bin_n = valid;
    if (g_bin_path[0]) {
        hbin_write();
    }
    return (int)valid;
}

/* ============================================================ findposarray — 搜索真实位置数组
 * 在游戏堆中搜索 ViewManager 使用的英雄位置数组:
 *   连续 10 个 entry, 步长 0x3F0 (1008 bytes)
 *   entry+0x04 = config_id (100~700)
 *   entry+0x20 = x 坐标 (int32, 非0, ±60000)
 *   entry+0x24 = y 坐标 (int32)
 *   entry+0x28 = z 坐标 (int32, 非0, ±60000)
 *   entry+0x358 = is_in_grass (byte, 0/1)
 * 找到后输出 base 地址, 后续直接读 entry+0x20 即为真实坐标
 */

struct fpa_ctx {
    unsigned long found_base;
    int found;
    int scanned;
    /* 用于校验的 config_id 集合 */
    int ref_cfg[10];
    int ref_n;
    int ref_valid;
};

/* 从 CActorManager 获取当前对局的 config_id 列表 (用于交叉校验) */
static void fpa_get_ref_cfgs(struct fpa_ctx *ctx)
{
    unsigned long b = 0, p_root_slot = 0, game_root = 0, actor_mgr = 0;
    unsigned long pool_base = 0, index_buf = 0;
    unsigned int flag = 0, count = 0, valid = 0;
    unsigned long count_off = 0;
    int i;

    ctx->ref_n = 0;
    ctx->ref_valid = 0;
    memset(ctx->ref_cfg, 0, sizeof(ctx->ref_cfg));

    if (!g_target_mm) return;
    b = gc_base();
    if (!b) return;

    if (!rm(&p_root_slot, b + 0x51EA4D0UL, 8)) return;
    p_root_slot = untag(p_root_slot);
    if (!p_root_slot || p_root_slot < 0x100000000UL) return;

    if (!rm(&game_root, p_root_slot, 8)) return;
    game_root = untag(game_root);
    if (!game_root || game_root < 0x100000000UL) return;

    if (!rm(&actor_mgr, game_root + 0x388UL, 8)) return;
    actor_mgr = untag(actor_mgr);
    if (!actor_mgr || actor_mgr < 0x100000000UL) return;

    rm(&flag, actor_mgr + 0x2EB0UL, 4);
    count_off = (flag == 0) ? 0x2E8CUL : 0x2EACUL;
    rm(&count, actor_mgr + count_off, 4);
    if (count == 0 || count > 512) return;

    rm(&index_buf, actor_mgr + 0x2E90UL, 8);
    if (!rm(&pool_base, actor_mgr + 0x2E70UL, 8)) return;
    index_buf = untag(index_buf);
    pool_base = untag(pool_base);
    if (!pool_base || pool_base < 0x100000000UL) return;

    for (i = 0; i < (int)count && valid < 10; i++) {
        int slot = 0;
        unsigned long entry_addr = 0, hero_ptr = 0;
        int config_id = 0;
        unsigned int camp_raw = 0;

        if (flag == 0 || !index_buf) {
            slot = i;
        } else {
            int rel_idx = 0;
            if (!rm(&rel_idx, index_buf + (unsigned long)i * 4, 4)) continue;
            slot = rel_idx + i;
        }
        if (slot < 0 || slot >= 512) continue;

        entry_addr = pool_base + (unsigned long)slot * 32UL;
        if (!rm(&hero_ptr, entry_addr + 8UL, 8)) continue;
        hero_ptr = untag(hero_ptr);
        if (!hero_ptr || hero_ptr < 0x100000000UL || hero_ptr >= 0x800000000000UL) continue;

        rm(&config_id, hero_ptr + 0x28UL, 4);
        rm(&camp_raw, hero_ptr + 0x34UL, 4);
        if (config_id < 100 || config_id > 700) continue;

        ctx->ref_cfg[valid] = config_id;
        valid++;
    }
    ctx->ref_n = (int)valid;
    ctx->ref_valid = (valid >= 5);  /* 至少找到 5 个英雄才可信 */
}

/* 检查一块内存是否是位置数组 (至少匹配 8/10 个 config_id 且 +0x20/+0x28 非零) */
static int fpa_check_entry(unsigned long base, struct fpa_ctx *ctx)
{
    int match_cfg = 0;
    int nonzero_pos = 0;
    int i;

    for (i = 0; i < 10; i++) {
        unsigned long entry = base + (unsigned long)i * 0x3F0UL;
        int cfg = 0;
        int x = 0, z = 0;
        unsigned char grass = 0;

        rm(&cfg, entry + 4UL, 4);
        rm(&x, entry + 0x20UL, 4);
        rm(&z, entry + 0x28UL, 4);
        rm(&grass, entry + 0x358UL, 1);

        /* config_id 匹配 (不要求顺序一致) */
        {
            int k;
            for (k = 0; k < ctx->ref_n; k++) {
                if (ctx->ref_cfg[k] == cfg) { match_cfg++; break; }
            }
        }

        /* 坐标非零且在合理范围 */
        if (x != 0 && z != 0 && x > -60000 && x < 60000 && z > -60000 && z < 60000)
            nonzero_pos++;

        /* is_in_grass 应该是 0 或小的正数 */
        if (grass > 200) return 0;
    }

    return (match_cfg >= 8 && nonzero_pos >= 8);
}

/* VMA 遍历回调: 在 rw 内存中搜索 */
static int fpa_scan_cb(void *ud, unsigned long start, unsigned long end, unsigned long flags)
{
    struct fpa_ctx *ctx = (struct fpa_ctx *)ud;
    unsigned long addr, chunk_size;
    unsigned char *buf = (unsigned char *)g_iobuf;

    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (ctx->found) return 1;  /* already found */

    /* 只扫堆区 (跳过太小和太大的区域) */
    chunk_size = end - start;
    if (chunk_size < 0x10000 || chunk_size > 0x10000000) return 0;

    ctx->scanned++;

    for (addr = start; addr < end && !ctx->found; addr += IO_CHUNK) {
        unsigned long read_size = IO_CHUNK;
        unsigned long off;

        if (addr + read_size > end) read_size = end - addr;
        if (read_size < 0x3F0 * 10) continue;  /* 不够放 10 个 entry */

        if (!rm(buf, addr, (int)read_size)) continue;

        /* 在缓冲区中搜索: 检查每个可能的对齐位置 */
        for (off = 0; off + 0x3F0 * 10 <= read_size; off += 8) {
            unsigned long candidate = addr + off;

            /* 快速预检: 第一个 entry 的 config_id */
            {
                int cfg0 = 0;
                __builtin_memcpy(&cfg0, buf + off + 4, 4);
                if (cfg0 < 100 || cfg0 > 700) continue;
            }

            /* 完整检查 */
            if (fpa_check_entry(candidate, ctx)) {
                ctx->found_base = candidate;
                ctx->found = 1;
                pr_info("[hero-reader] findposarray: ★ 找到位置数组 base=0x%lx (VMA 0x%lx+%lx)\n",
                        candidate, start, off);
                return 1;
            }
        }
    }
    return 0;
}

static struct fpa_ctx g_fpa;

static int do_findposarray(void)
{
    unsigned long b;
    unsigned long game_root, actor_mgr;
    unsigned long am_31e8 = 0;  /* [x19+0x31E8] 保存的 entry 指针 */
    int result = 0;

    if (!g_target_mm) { pr_warn("[hero-reader] findposarray: mm 未锁定\n"); return -1; }

    memset(&g_fpa, 0, sizeof(g_fpa));
    memset(g_ptc_va, 0, sizeof(g_ptc_va));
    memset(g_ptc_pa, 0, sizeof(g_ptc_pa));

    /* 1. 获取当前对局的 config_id 集合 */
    fpa_get_ref_cfgs(&g_fpa);
    if (!g_fpa.ref_valid) {
        pr_warn("[hero-reader] findposarray: 无法从 CActorManager 获取参考 config_id\n");
        return -2;
    }
    pr_info("[hero-reader] findposarray: 参考英雄 %d 个: %d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
            g_fpa.ref_n,
            g_fpa.ref_cfg[0], g_fpa.ref_cfg[1], g_fpa.ref_cfg[2], g_fpa.ref_cfg[3],
            g_fpa.ref_cfg[4], g_fpa.ref_cfg[5], g_fpa.ref_cfg[6], g_fpa.ref_cfg[7],
            g_fpa.ref_cfg[8], g_fpa.ref_cfg[9]);

    /* 2. 先尝试快速路径: 通过 [x19+0x31E8] 获取 */
    b = gc_base();
    if (b) {
        if (rm(&game_root, untag(rptr(b + 0x51EA4D0UL)), 8)) {
            game_root = untag(game_root);
            if (game_root > 0x100000000UL) {
                if (rm(&actor_mgr, game_root + 0x388UL, 8)) {
                    actor_mgr = untag(actor_mgr);
                    if (actor_mgr > 0x100000000UL) {
                        /* 尝试读取 actor_mgr 附近区域的 0x31E8 偏移 */
                        /* 注意: x19 在 ViewManager 调用中是主上下文, 不一定是 actor_mgr */
                        /* 这里只是尝试, 不确定偏移 */
                        rm(&am_31e8, actor_mgr + 0x31E8UL, 8);
                        am_31e8 = untag(am_31e8);
                        if (am_31e8 > 0x100000000UL) {
                            if (fpa_check_entry(am_31e8, &g_fpa)) {
                                g_fpa.found_base = am_31e8;
                                g_fpa.found = 1;
                                pr_info("[hero-reader] findposarray: 快速路径命中! base=0x%lx (actor_mgr+0x31E8)\n", am_31e8);
                            }
                        }
                    }
                }
            }
        }
    }

    /* 3. 快速路径失败 → 全堆搜索 */
    if (!g_fpa.found) {
        pr_info("[hero-reader] findposarray: 快速路径未命中, 开始堆搜索...\n");
        vma_walk(fpa_scan_cb, &g_fpa);
    }

    if (g_fpa.found) {
        /* 4. 输出找到的数组内容 */
        int i;
        pr_info("[hero-reader] findposarray: ★★★ 位置数组 base=0x%lx ★★★\n", g_fpa.found_base);
        for (i = 0; i < 10; i++) {
            unsigned long entry = g_fpa.found_base + (unsigned long)i * 0x3F0UL;
            int cfg = 0, x = 0, y = 0, z = 0;
            unsigned int camp = 0;
            unsigned char grass = 0;
            rm(&cfg, entry + 4UL, 4);
            rm(&camp, entry + 0x18UL, 4);
            rm(&x, entry + 0x20UL, 4);
            rm(&y, entry + 0x24UL, 4);
            rm(&z, entry + 0x28UL, 4);
            rm(&grass, entry + 0x358UL, 1);
            pr_info("[hero-reader]   [%d] cfg=%d camp=%u pos=(%d,%d,%d) grass=%u\n",
                    i, cfg, camp, x, y, z, grass);
        }
        result = 1;
    } else {
        pr_warn("[hero-reader] findposarray: 未找到位置数组 (扫描了 %d 个 VMA)\n", g_fpa.scanned);
        result = 0;
    }

    return result;
}

/* ============================================================ 文件重定向 dump (不依赖 dmesg)
 * herostat <path>   — 写英雄摘要到文件 (count / cfg / camp / pos / dead)
 * dumpphase <tag> <path> — 写所有英雄完整 1008 字节 + Transform 链到文件
 * 全部同步执行, 直接写文件, 脚本零 dmesg 依赖
 */

/* 内部: 打开文件 (override_creds) */
static void *hr_file_open(const char *path, void **old_cred)
{
    void *f;
    *old_cred = NULL;
    if (!p_filp_open || !p_kernel_write || !p_filp_close) return NULL;
    if (g_io_cred && p_override_creds) *old_cred = p_override_creds(g_io_cred);
    f = p_filp_open(path, KPM_O_WRONLY | KPM_O_CREAT | KPM_O_TRUNC, 0644);
    if (!f || (unsigned long)f >= (unsigned long)-4095UL) {
        if (*old_cred && p_revert_creds) p_revert_creds(*old_cred);
        *old_cred = NULL;
        return NULL;
    }
    return f;
}

static void hr_file_close(void *f, void *old_cred)
{
    if (f && p_filp_close) p_filp_close(f, NULL);
    if (old_cred && p_revert_creds) p_revert_creds(old_cred);
}

/* 内部: 遍历 rootactor 链, 对每个有效英雄调用回调 */
typedef int (*hr_hero_cb)(void *ud, unsigned long hero_ptr, int config_id,
                          int runtime_id, unsigned int camp_raw,
                          unsigned int enabled_flag, unsigned int state_code,
                          unsigned char is_in_grass, int slot, int index);

static int hr_walk_heroes(hr_hero_cb cb, void *ud)
{
    unsigned long b = 0, p_root_slot = 0, game_root = 0, actor_mgr = 0;
    unsigned long pool_base = 0, index_buf = 0;
    unsigned int flag = 0, count = 0, valid = 0;
    unsigned long count_off = 0;
    int i, ret = 0;

    if (!g_target_mm) return -1;
    /* 清空页表翻译缓存: 游戏运行中会重新映射内存页, 缓存的 PA 会过期 */
    memset(g_ptc_va, 0, sizeof(g_ptc_va));
    memset(g_ptc_pa, 0, sizeof(g_ptc_pa));
    b = gc_base();
    if (!b) return -2;

    if (!rm(&p_root_slot, b + 0x51EA4D0UL, 8)) return -3;
    p_root_slot = untag(p_root_slot);
    if (!p_root_slot || p_root_slot < 0x100000000UL) return -4;

    if (!rm(&game_root, p_root_slot, 8)) return -5;
    game_root = untag(game_root);
    if (!game_root || game_root < 0x100000000UL) return -6;

    if (!rm(&actor_mgr, game_root + 0x388UL, 8)) return -7;
    actor_mgr = untag(actor_mgr);
    if (!actor_mgr || actor_mgr < 0x100000000UL) return -8;

    rm(&flag, actor_mgr + 0x2EB0UL, 4);
    count_off = (flag == 0) ? 0x2E8CUL : 0x2EACUL;
    rm(&count, actor_mgr + count_off, 4);
    if (count == 0 || count > 512) return -9;

    rm(&index_buf, actor_mgr + 0x2E90UL, 8);
    if (!rm(&pool_base, actor_mgr + 0x2E70UL, 8)) return -10;
    index_buf = untag(index_buf);
    pool_base = untag(pool_base);
    if (!pool_base || pool_base < 0x100000000UL) return -11;

    for (i = 0; i < (int)count && valid < HB_MAXREC; i++) {
        int rel_idx = 0, slot = 0;
        unsigned long entry_addr = 0, hero_ptr = 0;
        int config_id = 0, runtime_id = 0;
        unsigned int enabled_flag = 0, state_code = 0, camp_raw = 0;
        unsigned char is_in_grass = 0;
        int r;

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

        if (config_id < 100 || config_id > 700) continue;

        r = cb(ud, hero_ptr, config_id, runtime_id, camp_raw,
               enabled_flag, state_code, is_in_grass, slot, valid);
        if (r < 0) return r;
        valid++;
    }
    ret = (int)valid;
    return ret;
}

/* --- herostat: 写摘要到文件 --- */
struct hr_stat_ctx { void *f; long long pos; int err; };

static int hr_stat_cb(void *ud, unsigned long hero_ptr, int config_id,
                      int runtime_id, unsigned int camp_raw,
                      unsigned int enabled_flag, unsigned int state_code,
                      unsigned char is_in_grass, int slot, int index)
{
    struct hr_stat_ctx *ctx = (struct hr_stat_ctx *)ud;
    unsigned long node = 0, link = 0, tr = 0, p2 = 0;
    int xx = 0, yy = 0, zz = 0;
    char line[200];
    int n;
    int is_dead = (enabled_flag < 1 || state_code == 1);

    /* Transform 坐标 */
    if (rm(&node, hero_ptr + 0xA8UL, 8)) {
        node = untag(node);
        if (node > 0x100000000UL && node < 0x800000000000UL) {
            if (rm(&link, node + 0x10UL, 8)) {
                link = untag(link);
                if (link > 0x100000000UL && link < 0x800000000000UL) {
                    if (rm(&tr, link + 0x00UL, 8)) {
                        tr = untag(tr);
                        if (tr > 0x100000000UL && tr < 0x800000000000UL) {
                            if (rm(&p2, tr + 0x60UL, 8)) {
                                p2 = untag(p2);
                                if (p2 > 0x100000000UL && p2 < 0x800000000000UL) {
                                    rm(&xx, p2 + 0, 4);
                                    rm(&yy, p2 + 4, 4);
                                    rm(&zz, p2 + 8, 4);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    n = snprintf(line, sizeof(line),
        "hero[%d] ptr=0x%lx cfg=%d camp=%u rt=%d pos=(%d,%d) mm=(%d,%d,%d) dead=%d grass=%u slot=%d\n",
        index, hero_ptr, config_id, camp_raw, runtime_id,
        xx / 10, zz / 10, xx, yy, zz, is_dead, is_in_grass, slot);
    if (p_kernel_write(ctx->f, line, n, &ctx->pos) < 0) { ctx->err = 1; return -1; }
    return 0;
}

/* --- dumpphase: 完整 dump 到文件 --- */
struct hr_dump_ctx { void *f; long long pos; int err; };

static int hr_dump_hero_cb(void *ud, unsigned long hero_ptr, int config_id,
                           int runtime_id, unsigned int camp_raw,
                           unsigned int enabled_flag, unsigned int state_code,
                           unsigned char is_in_grass, int slot, int index)
{
    struct hr_dump_ctx *ctx = (struct hr_dump_ctx *)ud;
    char line[160];
    int n, w, k;
    int is_dead = (enabled_flag < 1 || state_code == 1);

    /* 头 */
    n = snprintf(line, sizeof(line),
        "\n=== Hero[%d] ptr=0x%lx cfg=%d camp=%u rt=%d dead=%d grass=%u slot=%d ===\n",
        index, hero_ptr, config_id, camp_raw, runtime_id, is_dead, is_in_grass, slot);
    p_kernel_write(ctx->f, line, n, &ctx->pos);

    /* Hero 本体 252 words (1008 bytes), 每行 4 words */
    n = snprintf(line, sizeof(line), "--- [HERO] 252 words ---\n");
    p_kernel_write(ctx->f, line, n, &ctx->pos);
    for (w = 0; w < 252; w += 4) {
        unsigned int v[4] = {0, 0, 0, 0};
        for (k = 0; k < 4 && w + k < 252; k++)
            rm(&v[k], hero_ptr + (unsigned long)(w + k) * 4, 4);
        n = snprintf(line, sizeof(line), "+0x%04x: %08x %08x %08x %08x\n",
                     w * 4, v[0], v[1], v[2], v[3]);
        p_kernel_write(ctx->f, line, n, &ctx->pos);
    }

    /* Transform 链 */
    {
        unsigned long node = 0, link = 0, tr = 0, p2 = 0;
        n = snprintf(line, sizeof(line), "--- [TRANSFORM] chain ---\n");
        p_kernel_write(ctx->f, line, n, &ctx->pos);

        rm(&node, hero_ptr + 0xA8UL, 8);
        node = untag(node);
        n = snprintf(line, sizeof(line), "Node = 0x%lx\n", node);
        p_kernel_write(ctx->f, line, n, &ctx->pos);
        if (node > 0x100000000UL && node < 0x800000000000UL) {
            /* Node 32 words */
            for (w = 0; w < 32; w += 4) {
                unsigned int v[4] = {0, 0, 0, 0};
                for (k = 0; k < 4 && w + k < 32; k++)
                    rm(&v[k], node + (unsigned long)(w + k) * 4, 4);
                n = snprintf(line, sizeof(line), "  node+0x%03x: %08x %08x %08x %08x\n",
                             w * 4, v[0], v[1], v[2], v[3]);
                p_kernel_write(ctx->f, line, n, &ctx->pos);
            }
            rm(&link, node + 0x10UL, 8);
            link = untag(link);
            n = snprintf(line, sizeof(line), "Link = 0x%lx\n", link);
            p_kernel_write(ctx->f, line, n, &ctx->pos);
            if (link > 0x100000000UL && link < 0x800000000000UL) {
                /* Link 32 words */
                for (w = 0; w < 32; w += 4) {
                    unsigned int v[4] = {0, 0, 0, 0};
                    for (k = 0; k < 4 && w + k < 32; k++)
                        rm(&v[k], link + (unsigned long)(w + k) * 4, 4);
                    n = snprintf(line, sizeof(line), "  link+0x%03x: %08x %08x %08x %08x\n",
                                 w * 4, v[0], v[1], v[2], v[3]);
                    p_kernel_write(ctx->f, line, n, &ctx->pos);
                }
                rm(&tr, link + 0x00UL, 8);
                tr = untag(tr);
                n = snprintf(line, sizeof(line), "Transform = 0x%lx\n", tr);
                p_kernel_write(ctx->f, line, n, &ctx->pos);
                if (tr > 0x100000000UL && tr < 0x800000000000UL) {
                    rm(&p2, tr + 0x60UL, 8);
                    p2 = untag(p2);
                    n = snprintf(line, sizeof(line), "VInt3 = 0x%lx\n", p2);
                    p_kernel_write(ctx->f, line, n, &ctx->pos);
                    if (p2 > 0x100000000UL && p2 < 0x800000000000UL) {
                        unsigned int vx = 0, vy = 0, vz = 0;
                        rm(&vx, p2 + 0, 4);
                        rm(&vy, p2 + 4, 4);
                        rm(&vz, p2 + 8, 4);
                        n = snprintf(line, sizeof(line), "  VInt3: x=%d y=%d z=%d (mm) cm=(%d,%d,%d)\n",
                                     vx, vy, vz, vx / 10, vy / 10, vz / 10);
                        p_kernel_write(ctx->f, line, n, &ctx->pos);
                    }
                }
            }
        }
    }

    n = snprintf(line, sizeof(line), "--- End Hero[%d] ---\n", index);
    p_kernel_write(ctx->f, line, n, &ctx->pos);
    return 0;
}

/* --- ctl0: herostat <path> --- */
static int do_herostat(const char *path)
{
    struct hr_stat_ctx ctx;
    void *f, *old_cred;
    char line[80];
    int n, count;

    if (!g_target_mm) return -1;
    f = hr_file_open(path, &old_cred);
    if (!f) return -2;
    ctx.f = f; ctx.pos = 0; ctx.err = 0;
    count = hr_walk_heroes(hr_stat_cb, &ctx);
    n = snprintf(line, sizeof(line), "count=%d\n", count > 0 ? count : 0);
    p_kernel_write(f, line, n, &ctx.pos);
    hr_file_close(f, old_cred);
    return count;
}

/* --- ctl0: dumpphase <tag> <path> --- */
static int do_dumpphase(const char *tag, const char *path)
{
    struct hr_dump_ctx ctx;
    void *f, *old_cred;
    char line[160];
    int n, count;

    if (!g_target_mm) return -1;
    f = hr_file_open(path, &old_cred);
    if (!f) return -2;
    ctx.f = f; ctx.pos = 0; ctx.err = 0;

    n = snprintf(line, sizeof(line), "=== %s dump %s ===\n", tag, path);
    p_kernel_write(f, line, n, &ctx.pos);

    count = hr_walk_heroes(hr_dump_hero_cb, &ctx);

    n = snprintf(line, sizeof(line), "\n=== total=%d heroes ===\n", count > 0 ? count : 0);
    p_kernel_write(f, line, n, &ctx.pos);

    hr_file_close(f, old_cred);
    return count;
}

/* ============================================================ 诊断 (全部有界) */
static void do_walk(int maxprint)
{
    unsigned long dom, begin = 0, end = 0, n, i;
    if (!g_target_mm) { pr_warn("[hero-reader] walk: mm 未锁定\n"); return; }
    if (!g_base) find_base();
    if (!g_base) { pr_warn("[hero-reader] walk: base 未就绪\n"); return; }
    dom = untag(g_base + S_DOMAIN_ADDR);
    rm(&begin, dom + DOMAIN_ASM_BEGIN, 8);
    rm(&end, dom + DOMAIN_ASM_END, 8);
    begin = untag(begin); end = untag(end);
    if (!begin || end <= begin) { pr_warn("[hero-reader] walk: assemblies 区间异常\n"); return; }
    n = (end - begin) / 8;
    pr_info("[hero-reader] walk: domain=0x%lx assemblies=0x%lx-0x%lx (%lu)\n", dom, begin, end, n);
    if (n > 1000) n = 1000;
    for (i = 0; i < n && (maxprint <= 0 || (int)i < maxprint); i++) {
        unsigned long asm_p = rptr(begin + i * 8), image, namep;
        unsigned int cc = 0;
        char name[64];
        if (!asm_p) continue;
        image = rptr(asm_p + ASM_IMAGE);
        if (!image) continue;
        namep = rptr(image + IMAGE_NAME);
        rstr(namep, name, sizeof(name));
        r32(image + IMAGE_CLASS_COUNT, &cc);
        pr_info("[hero-reader]   asm[%lu] image=0x%lx classes=%u name=%s\n", i, image, cc, name);
    }
}

/*
 * [历史参考] 旧版 read_chain():
 * 早期版本用于遍历 libGameCore.so 的 UnitLabel 数组:
 *   manager = *(gc_base + 0x53ddb90);
 *   ulf = *(manager + 0x220);
 *   begin = *(ulf + 0xC8); end = *(ulf + 0xD0);
 *   步长 184 (0xB8): camp@+0x0C, x@+0x14, z@+0x1C, hp@+0x2C (hp >= 1 有效)
 * 因游戏更新后 0x53ddb90 偏移失效，已由 Native 物理链 (nat_collect / fullchain) 与 C# 托管链全面替代。
 * 此处代码已废弃下线，逻辑保留于此注释备查。
 */

/*
 * [历史参考] read_gameworld() 诊断读取函数:
 *   libGameCore Base + GC_GAMEWORLD_BSS_OFF -> USGMobaWorld
 *   libGameCore Base + GC_SEC_TRANSFORM_BSS_OFF -> SecurityTransform
 *   libGameCore Base + GC_ACTOR_MGR_BSS_OFF -> CActorManager
 *   libGameCore Base + GC_ROOT_VA (0x53f1810) -> RosterRoot -> Roster[i] -> ActorRoot
 * 此函数现已下线，逻辑保留于此注释备查。
 */

static void do_peek(unsigned long addr, int count)
{
    int i;
    if (count <= 0) count = 8;
    if (count > 64) count = 64;
    pr_info("[hero-reader] peek 0x%lx x%d:\n", addr, count);
    for (i = 0; i < count; i++) {
        unsigned int v = 0;
        r32(addr + (unsigned long)i * 4, &v);
        pr_info("[hero-reader]   +0x%04x: %08x\n", i * 4, v);
    }
}

/* 打印对象/类的类名 (对象 +0 = klass) */
static void do_name(unsigned long addr)
{
    unsigned long klass, np;
    char nm[96], ns[64];
    if (!addr) return;
    klass = rptr(addr);
    np = klass ? rptr(klass + CLASS_NAME_O) : 0;
    ns[0] = 0;
    if (rstr(np, nm, sizeof(nm)) <= 0) {
        pr_info("[hero-reader] name 0x%lx: klass=0x%lx <无名字>\n", addr, klass);
        return;
    }
    rstr(rptr(klass + CLASS_NS_O), ns, sizeof(ns));
    pr_info("[hero-reader] name 0x%lx: klass=0x%lx %s.%s\n", addr, klass, ns, nm);
}

static void do_dump(unsigned long addr, int words)
{
    int i;
    if (words <= 0) words = 16;
    if (words > 256) words = 256;
    pr_info("[hero-reader] dump 0x%lx x%d:\n", addr, words);
    for (i = 0; i < words; i += 8) {
        int k; char line[200]; int pos = 0;
        for (k = 0; k < 8 && i + k < words; k++) {
            unsigned int v = 0;
            r32(addr + (unsigned long)(i + k) * 4, &v);
            pos += snprintf(line + pos, sizeof(line) - (unsigned)pos, "%08x ", v);
        }
        pr_info("[hero-reader]   +0x%04x: %s\n", i * 4, line);
    }
}

/* gcwatch <sf_addr> <period_ms> <secs>: 高频采样 GameCore 通知流 (SGamePInvoke 静态区)
 *   sf+0x08 cppBuffer(u64)   sf+0x38 coreProcessBufferLen   sf+0x3C remainProcessBufferLen
 *   sf+0x40 MaxProcessSize   sf+0x44 curMaxProcessSize      sf+0x4C lastProcessNotifyLength
 *   sf+0x50 usingMsgId  (当前正在处理的通知 ID)
 * 每次"msg/长度/首字"变化就打印一行: ID + 长度 + 负载前 6 个 u32 */
static void do_gcwatch(unsigned long sf, int ms, long secs)
{
    unsigned long base = 0, start;
    unsigned int prev_msg = 0xFFFFFFFFu, prev_cpl = 0xFFFFFFFFu, prev_rpl = 0xFFFFFFFFu, prev_head = 0xFFFFFFFFu;
    long i, budget, lines = 0;
    if (!sf) { pr_warn("[hero-reader] gcwatch: 需要 sf 地址\n"); return; }
    if (ms < 1) ms = 1;
    if (ms > 500) ms = 500;
    if (secs <= 0) secs = 15;
    if (secs > 180) secs = 180;
    budget = (secs * 1000) / ms;
    if (budget > 90000) budget = 90000;
    base = rptr(sf + 0x8);
    pr_info("[hero-reader] gcwatch: sf=0x%lx cppBuffer=0x%lx ms=%d secs=%ld\n", sf, base, ms, secs);
    for (i = 0; i < budget && lines < 2000; i++) {
        unsigned int msg = 0, cpl = 0, rpl = 0, lpn = 0, mps = 0, cmps = 0, head = 0;
        r32(sf + 0x50, &msg);
        r32(sf + 0x38, &cpl);
        r32(sf + 0x3C, &rpl);
        r32(sf + 0x4C, &lpn);
        r32(sf + 0x40, &mps);
        r32(sf + 0x44, &cmps);
        start = base + (cpl > rpl ? (cpl - rpl) : 0);
        if (start) r32(start, &head);
        if (msg != prev_msg || head != prev_head || cpl != prev_cpl || rpl != prev_rpl) {
            unsigned int w[6]; int k;
            for (k = 0; k < 6; k++) { w[k] = 0; if (start) r32(start + (unsigned long)k * 4, &w[k]); }
            pr_info("[hero-reader] gc msg=%-6u cpl=%-7u rpl=%-7u lpn=%-5u mps=%u cmps=%u off=+0x%lx : %08x %08x %08x %08x %08x %08x\n",
                    msg, cpl, rpl, lpn, mps, cmps, (base && start > base) ? (start - base) : 0,
                    w[0], w[1], w[2], w[3], w[4], w[5]);
            lines++;
            prev_msg = msg; prev_head = head; prev_cpl = cpl; prev_rpl = rpl;
        }
        p_msleep((unsigned int)ms);
    }
    pr_info("[hero-reader] gcwatch: 结束 采样=%ld 行=%ld\n", i, lines);
}

/* ============================================================ 内核态进程名定位
 * 替代用户态 pidof:
 *   · 不需要 task 链表偏移 (本内核导出的 tasks_offset = -1)
 *   · 只需要 comm 偏移 (KP 运行时已解析, 实测 0x830)
 *   · 在 RCU 下按 pid 1..pid_max 调 find_task_by_vpid, 比对 comm
 * 全程内核态, 不读 /proc, 不碰目标内存。 */
static int g_fp_scanned = 0;

/* comm 在 task_struct 里只有 16 字节 (最大 15 字符), Android 取包名的后 15 位。
 * 这里允许调用方直接传完整包名, 内部自动只比对尾部。 */
static const char *comm_tail(const char *name)
{
    int n = 0;
    while (name[n]) n++;
    return (n > 15) ? name + (n - 15) : name;
}

static int find_pid_by_comm(const char *want)
{
    int pid, found = 0;
    const char *tail;

    g_fp_scanned = 0;
    if (!want || !*want) return 0;
    if (!p_find_task_by_vpid || task_struct_offset.comm_offset <= 0) return 0;
    tail = comm_tail(want);

    if (p_rcu_read_lock) p_rcu_read_lock();
    for (pid = 1; pid <= 32768; pid++) {
        void *tsk = p_find_task_by_vpid(pid);
        const char *nm;
        if (!tsk) continue;
        g_fp_scanned++;
        nm = (const char *)tsk + task_struct_offset.comm_offset;
        if (!strncmp(nm, tail, 15)) { found = pid; break; }
    }
    if (p_rcu_read_unlock) p_rcu_read_unlock();

    return found;
}

static void do_findpid(const char *name)
{
    int pid;
    pr_info("[hero-reader] task_off comm=0x%x (pid_max=32768)\n",
            task_struct_offset.comm_offset);
    pid = find_pid_by_comm(name);
    if (pid > 0) pr_info("[hero-reader] findpid '%s' -> %d (扫 %d 个 pid)\n", name, pid, g_fp_scanned);
    else         pr_warn("[hero-reader] findpid '%s' 未找到 (扫 %d 个 pid)\n", name, g_fp_scanned);
}

/* pid 是否仍存在且 comm 仍是目标名 (防 pid 复用 / 游戏重启) */
static int pid_comm_matches(pid_t pid, const char *want)
{
    void *tsk;
    int ok = 0;
    if (!p_find_task_by_vpid || !want || !*want) return 1;
    if (task_struct_offset.comm_offset <= 0) return 1;
    if (p_rcu_read_lock) p_rcu_read_lock();
    tsk = p_find_task_by_vpid(pid);
    if (tsk) {
        const char *nm = (const char *)tsk + task_struct_offset.comm_offset;
        ok = !strncmp(nm, comm_tail(want), 15);
    }
    if (p_rcu_read_unlock) p_rcu_read_unlock();
    return ok;
}

/* ============================================================ 生命周期 */
static void *pin_mm(pid_t pid)
{
    void *tsk = NULL, *mm = NULL;
    if (!p_find_task_by_vpid || !p_get_task_mm) return NULL;
    if (p_rcu_read_lock && p_rcu_read_unlock) {
        p_rcu_read_lock();
        tsk = p_find_task_by_vpid(pid);
        if (tsk) mm = p_get_task_mm(tsk);
        p_rcu_read_unlock();
    } else {
        tsk = p_find_task_by_vpid(pid);
        if (tsk) mm = p_get_task_mm(tsk);
    }
    return mm;
}

static void refresh_pgd(void)
{
    g_pgd = 0;
    if (g_target_mm && mm_struct_offset.pgd_offset > 0)
        __builtin_memcpy(&g_pgd, (char *)g_target_mm + mm_struct_offset.pgd_offset, 8);
    memset(g_ptc_va, 0, sizeof(g_ptc_va));   /* 换 mm / 重锁后翻译缓存必须失效 */
    memset(g_ptc_pa, 0, sizeof(g_ptc_pa));
}

static void reset_state(void)
{
    if (g_target_mm) { p_mmput(g_target_mm); g_target_mm = NULL; }
    g_mm_pid = 0; g_pgd = 0; g_base = 0; g_gc_base = 0;
    g_meta_addr = 0; g_meta_size = 0; g_meta_ver = 0;
    g_dump_done = 0; g_dump_bytes = 0;
    g_tbl = 0; g_tbl_n = 0;
}

static int reader_thread(void *data)
{
    int pin_fail = 0;
    unsigned int res_tick = 0;
    (void)data;
    while (!p_kthread_should_stop()) {
        if (g_req_reset) {
            g_req_reset = 0; reset_state(); g_target_pid = 0; pin_fail = 0;
        }
        if (g_req_pid_valid) {
            g_req_pid_valid = 0; reset_state();
            g_target_pid = g_req_pid; pin_fail = 0;
            pr_info("[hero-reader] 目标 pid=%d\n", g_target_pid);
        }
        if (g_target_pid && g_target_comm[0] && !pid_comm_matches(g_target_pid, g_target_comm)) {
            pr_info("[hero-reader] pid=%d 已失效 (游戏重启?), 重新定位 %s\n", g_target_pid, g_target_comm);
            reset_state(); g_target_pid = 0; pin_fail = 0;
        }
        if (!g_target_pid && g_target_comm[0] && (++res_tick % 5) == 0) {
            int np = find_pid_by_comm(g_target_comm);
            if (np > 0) {
                g_target_pid = (pid_t)np;
                pin_fail = 0;
                pr_info("[hero-reader] 内核定位 %s -> pid=%d\n", g_target_comm, np);
            }
        }
        if (g_target_pid) {
            if (!g_target_mm) {
                g_target_mm = pin_mm(g_target_pid);
                if (g_target_mm) { g_mm_pid = g_target_pid; pin_fail = 0; refresh_pgd(); }
                else if (++pin_fail >= 40) { g_target_pid = 0; pin_fail = 0; }
            } else if (g_mm_pid != g_target_pid) {
                reset_state();
            }
            if (g_target_mm) {
                if (g_req_base_valid) {
                    g_req_base_valid = 0;
                    if (base_looks_valid(g_req_base)) g_base = g_req_base;
                    else pr_warn("[hero-reader] 提供的 base 0x%lx 校验失败, 改内核自定位\n", g_req_base);
                }
                /* 不再主动调用全局扫描 find_base / findmeta，完全杜绝 Maple Tree VMA 锁竞争与卡死闪退 */
            }
        }

        if (g_req_dumpmeta) { g_req_dumpmeta = 0;
            md_dump(g_req_dump_path[0] ? g_req_dump_path : "/data/local/tmp/global-metadata.dat",
                    g_req_dump_size); }
        if (g_req_findmeta) { g_req_findmeta = 0; {
            unsigned long md = md_locate(); unsigned long ve = 0; unsigned int ver = 0; unsigned long sz = 0;
            if (md && vma_containing(md, NULL, &ve, NULL) && md_validate(md, &ver, ve - md)) {
                if (!md_compute_size(md, ver, ve - md, &sz)) sz = ve - md;
                g_meta_addr = md; g_meta_ver = ver; g_meta_size = sz;
                pr_info("[hero-reader] findmeta: metadata@0x%lx ver=%u size=%lu VMA可用=%lu\n",
                        md, ver, sz, ve - md);
            } else {
                pr_warn("[hero-reader] findmeta: 未找到 metadata\n");
            }
        } }
        if (g_req_dumpall) { g_req_dumpall = 0; if (g_allow_scan) do_dumpall(g_req_dumpall_path); else pr_warn("[hero-reader] dumpall 已禁用 (需 ctl0 'unsafe on')\n"); }
        if (g_req_classinfo) { g_req_classinfo = 0; do_classinfo(g_req_ci_name); }
        if (g_req_findfield) { g_req_findfield = 0; do_findfield(g_req_ff_name); }
        if (g_req_findstatic) { g_req_findstatic = 0; do_findstatic(g_req_fs_addr); }
        if (g_req_fields_valid) { g_req_fields_valid = 0; do_fields(g_req_fields_addr); }
        if (g_req_scanseq_valid) { g_req_scanseq_valid = 0; do_scanseq(g_req_scanseq_stride); }
        if (g_req_scanval_valid) { g_req_scanval_valid = 0; do_scanval(g_req_scanval_val); }
        if (g_req_scanrec_valid) { g_req_scanrec_valid = 0; do_scanrec(g_sr_stride, g_sr_t1, g_sr_t2); }
        if (g_req_scanids_valid) { g_req_scanids_valid = 0; do_scanids(g_si_stride, g_si_idoff); }
        if (g_req_tabdump_valid) { g_req_tabdump_valid = 0; do_tabdump(g_td_base, g_td_S, g_td_n); }
        if (g_req_scanlive_valid) { g_req_scanlive_valid = 0; if (g_allow_scan) do_scanlive(); else pr_warn("[hero-reader] scanlive 已禁用 (需 ctl0 'unsafe on')\n"); }
        if (g_req_findpid) { g_req_findpid = 0; do_findpid(g_req_fp_name); }
        if (g_req_findobj) { g_req_findobj = 0; if (g_allow_scan) do_findobj(g_req_fo_name); else pr_warn("[hero-reader] findobj 已禁用 (需 ctl0 'unsafe on')\n"); }
        if (g_req_scanvec_valid) { g_req_scanvec_valid = 0; do_scanvec(); }
        if (g_req_scanptr_valid) { g_req_scanptr_valid = 0; do_scanptr(); }
        if (g_req_walk)   { g_req_walk = 0; do_walk(40); }
        if (g_req_peek_valid) { g_req_peek_valid = 0; do_peek(g_req_peek_addr, g_req_peek_count); }
        if (g_req_name_valid) { g_req_name_valid = 0; do_name(g_req_name_addr); }
        if (g_req_dump_valid) { g_req_dump_valid = 0; do_dump(g_req_dump_addr, g_req_dump_words); }
        if (g_req_gcw_valid)  { g_req_gcw_valid = 0; do_gcwatch(g_req_gcw_sf, g_req_gcw_ms, g_req_gcw_sec); }

                if (g_target_pid && g_target_mm && g_bin_path[0] && g_bin_interval > 0) {
            read_rootactor_chain();
        }
        p_msleep(g_bin_interval > 0 ? (unsigned int)g_bin_interval : 1000);
    }
    return 0;
}

static void kick(void) { if (g_kthread && p_wake_up_process) p_wake_up_process(g_kthread); }

static long hero_init(const char *args, const char *event, void *reserved)
{
    void *k;
    (void)reserved;
    if (!kallsyms_lookup_name) return -1;

#define KSYM_REQ(t, var, name) do { \
        p_##var = (t)kallsyms_lookup_name(name); \
        if (!p_##var) { pr_err("[hero-reader] FATAL 缺符号: " name "\n"); return -1; } } while (0)
#define KSYM_OPT(t, var, name) do { p_##var = (t)kallsyms_lookup_name(name); } while (0)

    KSYM_REQ(void *(*)(pid_t), find_task_by_vpid, "find_task_by_vpid");
    KSYM_REQ(void *(*)(void *), get_task_mm, "get_task_mm");
    /* 对局数据链及硬件断点符号已随链路下线移除 */
    KSYM_REQ(void (*)(void *), mmput, "mmput");
    KSYM_REQ(void *(*)(int (*)(void *), void *, int, const char *, ...), kthread_create_on_node, "kthread_create_on_node");
    KSYM_REQ(int (*)(void *), wake_up_process, "wake_up_process");
    KSYM_REQ(int (*)(void), kthread_should_stop, "kthread_should_stop");
    KSYM_REQ(int (*)(void *), kthread_stop, "kthread_stop");
    KSYM_REQ(void (*)(unsigned int), msleep, "msleep");
    KSYM_REQ(void *(*)(const char *, int, int), filp_open, "filp_open");
    KSYM_REQ(long (*)(void *, const void *, unsigned long, long long *), kernel_write, "kernel_write");
    KSYM_REQ(int (*)(void *, void *), filp_close, "filp_close");
    KSYM_OPT(void (*)(void), rcu_read_lock, "__rcu_read_lock");
    KSYM_OPT(void (*)(void), rcu_read_unlock, "__rcu_read_unlock");
    KSYM_OPT(void *(*)(void *, unsigned long), find_vma, "find_vma");
    KSYM_OPT(void (*)(void *), mmap_read_lock, "mmap_read_lock");
    KSYM_OPT(void (*)(void *), mmap_read_unlock, "mmap_read_unlock");
    if (!p_mmap_read_lock || !p_mmap_read_unlock)
        pr_warn("[hero-reader] mmap_read_lock 缺失: VMA 遍历为无锁 (有并发风险)\n");
    KSYM_OPT(void *(*)(void *), override_creds, "override_creds");
    KSYM_OPT(void (*)(void *), revert_creds, "revert_creds");
    KSYM_OPT(void *(*)(void *), get_task_cred, "get_task_cred");
    KSYM_OPT(void (*)(void *), put_cred, "put_cred");

    /* 物理读环境: memstart_addr + PAGE_OFFSET(va_bits) + page_shift */
    {
        unsigned long *ms = (unsigned long *)kallsyms_lookup_name("memstart_addr");
        unsigned long tcr = 0;
        unsigned long va_bits;
        asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
        va_bits = 64 - ((tcr >> 16) & 0x3f);
        if (va_bits < 32 || va_bits > 52) va_bits = 48;
        {
            unsigned long tg1 = (tcr >> 30) & 0x3;
            g_page_shift = (tg1 == 1) ? 14 : (tg1 == 3) ? 16 : 12;
        }
        /* 页表级数: 与 KP 一致 page_level = (va_bits - 4) / (page_shift - 3) */
        {
            int lv = (int)((va_bits - 4UL) / ((unsigned long)g_page_shift - 3));
            if (lv < 2 || lv > 4) lv = 3;
            g_page_level = lv;
        }
        if (ms) {
            g_memstart_addr = *ms;
            g_pa_to_va_delta = (~0UL << va_bits) - g_memstart_addr;
        } else {
            g_pa_to_va_delta = (~0UL << va_bits);
        }
        if (g_verbose)
            pr_info("[hero-reader] phys: memstart=0x%lx delta=0x%lx page_shift=%d pgd_off=%d\n",
                    g_memstart_addr, g_pa_to_va_delta, g_page_shift, mm_struct_offset.pgd_offset);
    }
    if (mm_struct_offset.pgd_offset <= 0) {
        pr_err("[hero-reader] FATAL pgd_offset 未解析 (%d)\n", mm_struct_offset.pgd_offset);
        return -1;
    }

    if (args && *args) {
        const char *p = args; long pidv = 0; unsigned long b = 0;
        if (parse_dec(p, &pidv) && pidv > 0) {
            g_target_pid = (pid_t)pidv;
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') p++;
            if (parse_hex(p, &b) && b) { g_req_base = b; g_req_base_valid = 1; }
        }
        if (strstr(args, "verbose")) g_verbose = 1;
    }
    /* 默认自动定位目标游戏包名，重启后无需手动下发 set */
    if (!g_target_comm[0]) {
        snprintf(g_target_comm, sizeof(g_target_comm), "com.tencent.tmgp.sgame");
    }
    /* 链路已下线: 不再初始化定长共享二进制文件 */
    if (p_get_task_cred) g_io_cred = p_get_task_cred(current);

    k = p_kthread_create_on_node(reader_thread, NULL, -1, "kworker/0:1H");
    if (!k || (unsigned long)k >= (unsigned long)-4095UL) {
        pr_err("[hero-reader] FATAL kthread 创建失败\n");
        return -1;
    }
    p_wake_up_process(k);
    g_kthread = k;
    if (g_verbose) pr_info("[hero-reader] v6 init 就绪 (pid=%d)\n", g_target_pid);
    return 0;
}

static long hero_exit(void *reserved)
{
    (void)reserved;
    if (g_kthread) { p_kthread_stop(g_kthread); g_kthread = NULL; }
    /* 链路已下线: 无驻留硬件断点与共享文件需释放 */
    if (g_target_mm) { p_mmput(g_target_mm); g_target_mm = NULL; }
    if (g_io_cred && p_put_cred) { p_put_cred(g_io_cred); g_io_cred = NULL; }
    return 0;
}

/* ============================================================ ctl0 */
static long hero_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char resp[220];
    if (!args || !*args) args = "status";
    resp[0] = 0;

    if (!strncmp(args, "diag", 4)) {
        const char *p = args + 4;
        while (*p == ' ') p++;
        if (*p) g_diag = (strstr(p, "off") != NULL) ? 0 : 1;
        else g_diag = !g_diag;
        snprintf(resp, sizeof(resp), "diag=%d (%s)", g_diag, g_diag ? "诊断命令可用" : "诊断命令已禁用");
    } else if (!g_diag && is_diag_cmd(args)) {
        snprintf(resp, sizeof(resp), "诊断命令已禁用 (需 ctl0 'diag on')");
    } else if (!strcmp(args, "status") || !strcmp(args, "info")) {
        snprintf(resp, sizeof(resp),
                 "pid=%d mm=%d pgd=0x%lx base=0x%lx meta=0x%lx/%lu v=%u dumped=%lu comm=%s",
                 g_target_pid, g_target_mm ? 1 : 0, g_pgd, g_base, g_meta_addr, g_meta_size, g_meta_ver, g_dump_bytes,
                 g_target_comm[0] ? g_target_comm : "-");
    } else if (!strncmp(args, "setme", 5)) {
        const char *p = args + 5; long hid = 0, cmp = 0;
        while (*p == ' ') p++;
        if (parse_dec(p, &hid) && hid > 0) {
            g_manual_me_hero = (unsigned int)hid;
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
            if (parse_dec(p, &cmp) && (cmp == 1 || cmp == 2)) g_manual_me_camp = (unsigned int)cmp;
            snprintf(resp, sizeof(resp), "setme: 已锁定本机英雄 ID=%ld 阵营=%u", hid, g_manual_me_camp);
        } else {
            g_manual_me_hero = 0; g_manual_me_camp = 0;
            snprintf(resp, sizeof(resp), "setme: 已清除手动英雄锁定");
        }
    } else if (!strncmp(args, "herobin", 7)) {
        const char *p = args + 7;
        while (*p == ' ') p++;
        if (!strncmp(p, "stop", 4)) {
            g_bin_interval = 0; g_bin_path[0] = 0;
            snprintf(resp, sizeof(resp), "herobin 周期输出已停止");
        } else {
            int l = 0;
            g_bin_path[0] = 0; g_bin_interval = 0;
            if (*p) {
                while (*p && *p != ' ' && l < (int)sizeof(g_bin_path) - 1) g_bin_path[l++] = *p++;
                g_bin_path[l] = 0;
                while (*p == ' ') p++;
                { long iv = 0; if (parse_dec(p, &iv) && iv > 0) g_bin_interval = (int)iv; }
            }
            if (!g_bin_path[0])
                snprintf(resp, sizeof(resp), "herobin 用法: herobin <path> [ms] | herobin stop");
            else
                snprintf(resp, sizeof(resp), "herobin -> %s (%dms 周期刷新)", g_bin_path, g_bin_interval);
        }
    } else if (!strncmp(args, "set ", 4)) {
        const char *p = args + 4; long pidv = 0; unsigned long b = 0;
        if (parse_dec(p, &pidv) && pidv > 0) {
            g_req_pid = (pid_t)pidv; g_req_pid_valid = 1;
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') p++;
            if (parse_hex(p, &b) && b) { g_req_base = b; g_req_base_valid = 1; }
            snprintf(resp, sizeof(resp), "set pid=%ld", pidv);
        } else snprintf(resp, sizeof(resp), "set: 'set <pid> [base_hex]'");
    } else if (!strncmp(args, "dumpmeta", 8)) {
        const char *p = args + 8; int l = 0; unsigned long sz = 0;
        while (*p == ' ') p++;
        if (parse_hex(p, &sz)) { g_req_dump_size = sz; while (*p && *p != ' ') p++; while (*p == ' ') p++; }
        else g_req_dump_size = 0;
        g_req_dump_path[l] = 0;
        while (*p && l < (int)sizeof(g_req_dump_path) - 1) g_req_dump_path[l++] = *p++;
        g_req_dump_path[l] = 0;
        if (!g_io_cred && p_get_task_cred) g_io_cred = p_get_task_cred(current);
        g_req_dumpmeta = 1;
        snprintf(resp, sizeof(resp), "dumpmeta 入队 -> %s",
                 g_req_dump_path[0] ? g_req_dump_path : "/data/local/tmp/global-metadata.dat");
    } else if (!strncmp(args, "dumpall", 7)) {
        const char *p = args + 7; int l = 0;
        while (*p == ' ') p++;
        while (*p && l < (int)sizeof(g_req_dumpall_path) - 1) g_req_dumpall_path[l++] = *p++;
        g_req_dumpall_path[l] = 0;
        if (!g_req_dumpall_path[0])
            snprintf(g_req_dumpall_path, sizeof(g_req_dumpall_path), "/data/local/tmp/il2cpp_dump.cs");
        if (!g_io_cred && p_get_task_cred) g_io_cred = p_get_task_cred(current);
        g_req_dumpall = 1;
        snprintf(resp, sizeof(resp), "dumpall -> %s", g_req_dumpall_path);
    } else if (!strncmp(args, "unsafe", 6)) {
        const char *p = args + 6; long v = 0;
        while (*p == ' ') p++;
        if (parse_dec(p, &v)) g_allow_scan = (int)v;
        else if (strstr(p, "on")) g_allow_scan = 1;
        else if (strstr(p, "off")) g_allow_scan = 0;
        else g_allow_scan = !g_allow_scan;
        snprintf(resp, sizeof(resp), "unsafe(重扫)=%d (%s)", g_allow_scan,
                 g_allow_scan ? "dumpall/findobj 可用" : "dumpall/findobj 已禁用");
    } else if (!strncmp(args, "findobj ", 8)) {
        const char *p = args + 8; int l = 0, fi = 0; unsigned long off = 0;
        while (*p == ' ') p++;
        while (p[l] && p[l] != ' ' && l < 47) { g_req_fo_name[l] = p[l]; l++; }
        g_req_fo_name[l] = 0;
        for (fi = 0; fi < 3; fi++) g_fo_off[fi] = 0;
        fi = 0;
        while (fi < 3) {
            while (*p == ' ') p++;
            if (!*p) break;
            if (!parse_hex(p, &off) || off == 0) break;
            g_fo_off[fi++] = (long)off;
            while (*p && *p != ' ') p++;
        }
        if (!g_io_cred && p_get_task_cred) g_io_cred = p_get_task_cred(current);
        g_req_findobj = 1;
        snprintf(resp, sizeof(resp), "findobj '%s' off=%ld,%ld,%ld 入队",
                 g_req_fo_name, g_fo_off[0], g_fo_off[1], g_fo_off[2]);
    } else if (!strncmp(args, "classinfo ", 10)) {
        const char *p = args + 10; int l = 0;
        while (*p == ' ') p++;
        while (p[l] && l < 39) { g_req_ci_name[l] = p[l]; l++; }
        g_req_ci_name[l] = 0;
        if (!g_io_cred && p_get_task_cred) g_io_cred = p_get_task_cred(current);
        g_req_classinfo = 1;
        snprintf(resp, sizeof(resp), "classinfo '%s' 入队", g_req_ci_name);
    } else if (!strncmp(args, "findfield ", 10)) {
        const char *p = args + 10; int l = 0;
        while (*p == ' ') p++;
        while (p[l] && l < 47) { g_req_ff_name[l] = p[l]; l++; }
        g_req_ff_name[l] = 0;
        if (!g_io_cred && p_get_task_cred) g_io_cred = p_get_task_cred(current);
        g_req_findfield = 1;
        snprintf(resp, sizeof(resp), "findfield '%s' 入队", g_req_ff_name);
    } else if (!strncmp(args, "findstatic ", 11)) {
        unsigned long a = 0;
        const char *p = args + 11;
        while (*p == ' ') p++;
        if (!parse_hex(p, &a) || !a) {
            snprintf(resp, sizeof(resp), "findstatic 用法: findstatic 0x<类地址>");
        } else {
            g_req_fs_addr = a;
            g_req_findstatic = 1;
            snprintf(resp, sizeof(resp), "findstatic 0x%lx 入队", a);
        }
    } else if (!strcmp(args, "findmeta")) {
        g_req_findmeta = 1;
        snprintf(resp, sizeof(resp), "findmeta 入队");
    } else if (!strcmp(args, "walk")) {
        g_req_walk = 1; snprintf(resp, sizeof(resp), "walk 入队");
    } else if (!strcmp(args, "rootactor") || !strcmp(args, "actorchain")) {
        int v = read_rootactor_chain();
        if (v >= 0) snprintf(resp, sizeof(resp), "rootactor: 读取成功 (有效英雄=%d, 详见 dmesg)", v);
        else snprintf(resp, sizeof(resp), "rootactor: 读取失败 rc=%d (详见 dmesg)", v);
    } else if (!strcmp(args, "chain")) {
        snprintf(resp, sizeof(resp), "chain: 历史 UnitLabel 链已废弃 (详见注释)，请用 fullchain/heroes/gameworld");
    } else if (!strcmp(args, "gw") || !strcmp(args, "gameworld")) {
        snprintf(resp, sizeof(resp), "gameworld: 链路已下线并转为注释备查");
    } else if (!strncmp(args, "herostat ", 9)) {
        const char *p = args + 9; char path[160]; int l = 0, v;
        while (*p == ' ') p++;
        while (*p && l < (int)sizeof(path) - 1) path[l++] = *p++;
        path[l] = 0;
        if (!path[0]) {
            snprintf(resp, sizeof(resp), "herostat: 'herostat <path>'");
        } else {
            v = do_herostat(path);
            if (v >= 0) snprintf(resp, sizeof(resp), "herostat: %d heroes -> %s", v, path);
            else snprintf(resp, sizeof(resp), "herostat: 失败 rc=%d", v);
        }
    } else if (!strncmp(args, "dumpphase ", 10)) {
        const char *p = args + 10; char tag[32], path[160]; int l = 0, v;
        while (*p == ' ') p++;
        l = 0;
        while (*p && *p != ' ' && l < (int)sizeof(tag) - 1) tag[l++] = *p++;
        tag[l] = 0;
        while (*p == ' ') p++;
        l = 0;
        while (*p && l < (int)sizeof(path) - 1) path[l++] = *p++;
        path[l] = 0;
        if (!tag[0] || !path[0]) {
            snprintf(resp, sizeof(resp), "dumpphase: 'dumpphase <tag> <path>'");
        } else {
            v = do_dumpphase(tag, path);
            if (v >= 0) snprintf(resp, sizeof(resp), "dumpphase %s: %d heroes -> %s", tag, v, path);
            else snprintf(resp, sizeof(resp), "dumpphase %s: 失败 rc=%d", tag, v);
        }
    } else if (!strcmp(args, "findposarray") || !strcmp(args, "fpa")) {
        int v = do_findposarray();
        if (v > 0) snprintf(resp, sizeof(resp), "findposarray: 找到位置数组! (详见 dmesg)");
        else if (v == 0) snprintf(resp, sizeof(resp), "findposarray: 未找到 (可能不在对局中)");
        else snprintf(resp, sizeof(resp), "findposarray: 失败 rc=%d", v);
    } else if (!strncmp(args, "peek ", 5)) {
        const char *p = args + 5; unsigned long a = 0; long cnt = 0;
        if (parse_hex(p, &a) && a) {
            while (*p && *p != ' ') p++; parse_dec(p, &cnt);
            g_req_peek_addr = a; g_req_peek_count = (int)cnt; g_req_peek_valid = 1;
            snprintf(resp, sizeof(resp), "peek 0x%lx 入队", a);
        } else snprintf(resp, sizeof(resp), "peek: 'peek <hex> [n]'");
    } else if (!strncmp(args, "fields ", 7)) {
        const char *p = args + 7; unsigned long a = 0;
        if (parse_hex(p, &a) && a) {
            g_req_fields_addr = a; g_req_fields_valid = 1;
            snprintf(resp, sizeof(resp), "fields 0x%lx 入队", a);
        } else snprintf(resp, sizeof(resp), "fields: 'fields <hex_class>'");
    } else if (!strncmp(args, "scanseq ", 8)) {
        const char *p = args + 8; unsigned long s = 0;
        if (parse_hex(p, &s) && s) {
            g_req_scanseq_stride = s; g_req_scanseq_valid = 1;
            snprintf(resp, sizeof(resp), "scanseq stride=0x%lx 入队", s);
        } else snprintf(resp, sizeof(resp), "scanseq: 'scanseq <stride_hex>'");
    } else if (!strncmp(args, "scanval ", 8)) {
        const char *p = args + 8; long v = 0;
        if (parse_dec(p, &v) && v > 0) {
            g_req_scanval_val = (unsigned int)v; g_req_scanval_valid = 1;
            snprintf(resp, sizeof(resp), "scanval %ld 入队", v);
        } else snprintf(resp, sizeof(resp), "scanval: 'scanval <dec>'");
    } else if (!strncmp(args, "scanids ", 8)) {
        const char *p = args + 8; unsigned long v[6]; int k = 0;
        while (*p == ' ') p++;
        while (k < 6) {
            while (*p == ' ') p++;
            if (!*p || !parse_hex(p, &v[k])) break;
            k++;
            while (*p && *p != ' ') p++;
        }
        if (k == 6) {
            g_si_stride = v[0]; g_si_idoff = v[1];
            g_si_ids[0] = (unsigned int)v[2]; g_si_ids[1] = (unsigned int)v[3];
            g_si_ids[2] = (unsigned int)v[4]; g_si_ids[3] = (unsigned int)v[5];
            g_req_scanids_valid = 1;
            snprintf(resp, sizeof(resp), "scanids S=0x%lx D=0x%lx ids=%u,%u,%u,%u 入队",
                     g_si_stride, g_si_idoff, g_si_ids[0], g_si_ids[1], g_si_ids[2], g_si_ids[3]);
        } else snprintf(resp, sizeof(resp), "scanids: 'scanids <stride_hex> <idoff_hex> <id1..4_hex>'");
    } else if (!strncmp(args, "tabdump ", 8)) {
        const char *p = args + 8; unsigned long v[3]; int k = 0;
        while (*p == ' ') p++;
        while (k < 3) {
            while (*p == ' ') p++;
            if (!*p) break;
            if (k < 2) { if (!parse_hex(p, &v[k])) break; }
            else { long nn = 0; if (!parse_dec(p, &nn)) break; v[k] = (unsigned long)nn; }
            k++;
            while (*p && *p != ' ') p++;
        }
        if (k == 3 && v[0] && v[1]) {
            g_td_base = v[0]; g_td_S = v[1]; g_td_n = (int)v[2]; g_req_tabdump_valid = 1;
            snprintf(resp, sizeof(resp), "tabdump 0x%lx S=0x%lx n=%d 入队", g_td_base, g_td_S, g_td_n);
        } else snprintf(resp, sizeof(resp), "tabdump: 'tabdump <base_hex> <stride_hex> <n>'");
    } else if (!strcmp(args, "heroes") || !strncmp(args, "heroes", 6) || !strcmp(args, "rawheroes") ||
               !strcmp(args, "native") || !strcmp(args, "fullchain") ||
               !strcmp(args, "natx2") || !strcmp(args, "nat3") || !strcmp(args, "natchain") || !strncmp(args, "natfind", 7) ||
               !strncmp(args, "herobin", 7) || !strcmp(args, "binflush") || !strncmp(args, "natgate", 7) ||
               !strncmp(args, "hwbpxva", 7) || !strncmp(args, "hwbpslot", 8) || !strncmp(args, "hwbp", 4) ||
               !strncmp(args, "pairscan", 8) || !strncmp(args, "camcal", 6) || !strcmp(args, "cams") || !strcmp(args, "cad") ||
               !strncmp(args, "cscan", 5) || !strncmp(args, "nscorr", 6) || !strncmp(args, "nativescan", 10)) {
        snprintf(resp, sizeof(resp), "链路已下线: 对局数据读取链已停用并转为注释备查");
    } else if (!strncmp(args, "scanvec ", 8)) {
        const char *p = args + 8; long v[3]; int k = 0;
        while (k < 3) {
            int neg = 0; long x = 0;
            while (*p == ' ') p++;
            if (*p == '-') { neg = 1; p++; }
            if (*p < '0' || *p > '9') break;
            while (*p >= '0' && *p <= '9') { x = x * 10 + (*p - '0'); p++; }
            v[k++] = neg ? -x : x;
        }
        if (k == 3) {
            unsigned long lo = 0, hi = 0;
            while (*p == ' ') p++;
            if (*p && parse_hex(p, &lo)) {
                while (*p && *p != ' ') p++;
                while (*p == ' ') p++;
                parse_hex(p, &hi);
            }
            g_svec_x = v[0]; g_svec_y = v[1]; g_svec_z = v[2];
            g_svec_lo = lo; g_svec_hi = hi; g_req_scanvec_valid = 1;
            snprintf(resp, sizeof(resp), "scanvec (%ld,%ld,%ld) 入队", v[0], v[1], v[2]);
        } else snprintf(resp, sizeof(resp), "scanvec: 'scanvec <x> <y> <z> [lo_hex hi_hex]'");
    } else if (!strncmp(args, "scanptr ", 8)) {
        const char *p = args + 8; unsigned long v = 0, lo = 0, hi = 0;
        while (*p == ' ') p++;
        if (parse_hex(p, &v) && v) {
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
            if (*p && parse_hex(p, &lo)) {
                while (*p && *p != ' ') p++;
                while (*p == ' ') p++;
                parse_hex(p, &hi);
            }
            g_sptr_val = v; g_sptr_lo = lo; g_sptr_hi = hi; g_req_scanptr_valid = 1;
            snprintf(resp, sizeof(resp), "scanptr 0x%lx 入队", v);
        } else snprintf(resp, sizeof(resp), "scanptr: 'scanptr <hex> [lo_hex hi_hex]'");
    } else if (!strncmp(args, "scanrec ", 8)) {
        const char *p = args + 8; unsigned long v[3]; int k = 0;
        while (*p == ' ') p++;
        if (parse_hex(p, &v[0])) {
            k = 1;
            while (k < 6) {
                while (*p && *p != ' ') p++;
                while (*p == ' ') p++;
                if (!*p || !parse_hex(p, &v[k])) break;
                k++;
            }
        }
        g_sr_stride = (k > 0) ? v[0] : 0x348;
        g_sr_t1 = (k > 1) ? (unsigned int)v[1] : 0x74;
        g_sr_t2 = (k > 2) ? (unsigned int)v[2] : 0x99;
        g_sr_bm   = (k > 3) ? (int)v[3] : 1;
        g_sr_pm   = (k > 4) ? (int)v[4] : 0;
        g_sr_nrun = (k > 5) ? (int)v[5] : 6;
        if (g_sr_nrun < 2) g_sr_nrun = 2;
        if (g_sr_nrun > 16) g_sr_nrun = 16;
        if (g_sr_stride < 0x10 || g_sr_stride > 0x10000) {
            snprintf(resp, sizeof(resp), "scanrec: 'scanrec <stride_hex> [t1] [t2]'");
        } else {
            g_req_scanrec_valid = 1;
            snprintf(resp, sizeof(resp), "scanrec stride=0x%lx t=%u/%u bm=%d pos=%d 入队", g_sr_stride, g_sr_t1, g_sr_t2, g_sr_bm, g_sr_pm);
        }
    } else if (!strncmp(args, "scanlive ", 9)) {
        const char *p = args + 9; unsigned long v[6]; int k;
        for (k = 0; k < 6; k++) {
            while (*p == ' ') p++;
            if (!parse_hex(p, &v[k])) break;
            while (*p && *p != ' ') p++;
        }
        if (k == 6) {
            g_sl_mode = (int)v[0];
            g_sl_xlo = (unsigned int)v[1]; g_sl_xhi = (unsigned int)v[2];
            g_sl_zlo = (unsigned int)v[3]; g_sl_zhi = (unsigned int)v[4];
            g_sl_wait = (long)v[5];
            g_req_scanlive_valid = 1;
            snprintf(resp, sizeof(resp), "scanlive 入队 mode=%d x[%08x,%08x] z[%08x,%08x] wait=%ld",
                     g_sl_mode, g_sl_xlo, g_sl_xhi, g_sl_zlo, g_sl_zhi, g_sl_wait);
        } else snprintf(resp, sizeof(resp), "scanlive: 'scanlive <mode 0=float 1=int> <xlo> <xhi> <zlo> <zhi> <waitms>' (hex)");
    } else if (!strncmp(args, "findpid ", 8)) {
        const char *p = args + 8; int l = 0;
        while (*p == ' ') p++;
        while (p[l] && l < (int)sizeof(g_req_fp_name) - 1) { g_req_fp_name[l] = p[l]; l++; }
        g_req_fp_name[l] = 0;
        g_req_findpid = 1;
        snprintf(resp, sizeof(resp), "findpid '%s' 入队", g_req_fp_name);
    } else if (!strncmp(args, "setcomm ", 8)) {
        const char *p = args + 8; int l = 0;
        char nm[64];
        while (*p == ' ') p++;
        while (p[l] && l < (int)sizeof(nm) - 1) { nm[l] = p[l]; l++; }
        nm[l] = 0;
        if (strcmp(nm, g_target_comm) != 0) {
            /* 名字变化才重置, 重复 setcomm 是幂等的 (守护可周期重发) */
            memcpy(g_target_comm, nm, sizeof(g_target_comm));
            g_req_pid = 0; g_req_pid_valid = 1;
        }
        snprintf(resp, sizeof(resp), "setcomm '%s' (内核态定位)", g_target_comm);
    } else if (!strncmp(args, "name ", 5)) {
        const char *p = args + 5; unsigned long a = 0;
        if (parse_hex(p, &a) && a) {
            g_req_name_addr = a; g_req_name_valid = 1;
            snprintf(resp, sizeof(resp), "name 0x%lx 入队", a);
        } else snprintf(resp, sizeof(resp), "name: 'name <hex>'");
    } else if (!strncmp(args, "dump ", 5)) {
        const char *p = args + 5; unsigned long a = 0; long n = 0;
        if (parse_hex(p, &a) && a) {
            while (*p && *p != ' ') p++; parse_dec(p, &n);
            g_req_dump_addr = a; g_req_dump_words = (int)n; g_req_dump_valid = 1;
            snprintf(resp, sizeof(resp), "dump 0x%lx 入队", a);
        } else snprintf(resp, sizeof(resp), "dump: 'dump <hex> [words]'");
    } else if (!strncmp(args, "gcwatch ", 8)) {
        const char *p = args + 8; unsigned long sf = 0; long ms = 0, sec = 0;
        if (parse_hex(p, &sf) && sf) {
            while (*p && *p != ' ') p++; while (*p == ' ') p++; parse_dec(p, &ms);
            while (*p && *p != ' ') p++; while (*p == ' ') p++; parse_dec(p, &sec);
            g_req_gcw_sf = sf; g_req_gcw_ms = (int)ms; g_req_gcw_sec = sec; g_req_gcw_valid = 1;
            snprintf(resp, sizeof(resp), "gcwatch 0x%lx ms=%ld sec=%ld 入队", sf, ms, sec);
        } else snprintf(resp, sizeof(resp), "gcwatch: 'gcwatch <sf_hex> <period_ms> <secs>'");
    } else if (!strncmp(args, "verbose", 7)) {
        const char *p = args + 7; long v = 0;
        if (parse_dec(p, &v)) g_verbose = (int)v; else g_verbose = !g_verbose;
        snprintf(resp, sizeof(resp), "verbose=%d", g_verbose);
    } else if (!strncmp(args, "wide", 4)) {
        const char *p = args + 4; long v = 0;
        if (parse_dec(p, &v)) g_scan_wide = (int)v; else g_scan_wide = !g_scan_wide;
        snprintf(resp, sizeof(resp), "scan wide=%d (%s)", g_scan_wide, g_scan_wide ? "全区域" : "默认");
    } else if (!strcmp(args, "reset")) {
        g_req_reset = 1; snprintf(resp, sizeof(resp), "reset 入队");
    } else {
        snprintf(resp, sizeof(resp), "未知: %s", args);
    }

    if (g_verbose) pr_info("[hero-reader] ctl0 [%s] => %s\n", args, resp);
    kick();
    if (out_msg && outlen > 0) {
        int len = (int)strlen(resp);
        if (len > outlen - 1) len = outlen - 1;
        if (len > 0) compat_copy_to_user(out_msg, resp, len + 1);
    }
    return 0;
}

KPM_INIT(hero_init);
KPM_CTL0(hero_ctl0);
KPM_EXIT(hero_exit);
