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
#include "heromap.h"   /* 英雄ID -> 英雄名 静态表 (只需查表, 不联网/不查询) */

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

/* libGameCore.so 指针链 */
#define GC_MANAGER_BSS_OFF       0x53ddb90UL
#define GC_OBJ_UNIT_LABEL_FINDER 0x220UL
#define GC_ULF_ARRAY_BEGIN       0xC8UL
#define GC_ULF_ARRAY_END         0xD0UL
#define UNIT_LABEL_SIZE          0xB8
#define LABEL_CAMP_ID            0x0C
#define LABEL_POS_X              0x14
#define LABEL_POS_Z              0x1C
#define LABEL_HP                 0x2C
#define MAX_ACTORS               100

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
/* 性能统计 (每 50 个周期打印一次) */
static long long (*p_ktime_get_ns)(void);   /* 指向 ktime_get (返回 ns) */
static unsigned int   g_pf_cycles = 0, g_pf_scans = 0;
static int            g_in_match = 0;
static int            g_nat_gate = 0;   /* 1=可见时用 C# 校验原生坐标; 0=完全信任原生 */          /* 局内/局外状态, 用于降频与日志限流 */
static unsigned long long g_pf_total_us = 0, g_pf_max_us = 0;
static unsigned int   g_pf_slow = 0;
static unsigned int   g_bin_no_native = 0, g_bin_mm_fallback = 0, g_bin_bad_native = 0;                       /* >3ms 的轮数 */
static unsigned long long g_bw_total_us = 0, g_bw_max_us = 0;
static unsigned int   g_bw_n = 0;
static unsigned long  g_pgd        = 0;
static unsigned long  g_base       = 0;
static unsigned long  g_gc_base    = 0;
static int            g_verbose    = 0;
static int            g_allow_scan = 0;   /* 默认禁用重扫 (dumpall/findobj); 需 'unsafe on' */
static int            g_diag       = 0;   /* 默认禁用诊断命令; 需 'diag on' */
static int            g_scan_wide  = 0;
static int            g_camcal     = 0;
static unsigned char  g_cam_last[64] = {0};   /* 1=扫描不限区域大小/地址 (需 'wide on') */

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
/* 稳定化缓存: 类表 / ActorManager 类与实例 (稳态下 heroes 为纯指针读, 零扫描) */
static unsigned long  g_tbl = 0, g_tbl_n = 0;
static unsigned long  g_am_class = 0, g_am_inst = 0;
static unsigned long  g_tbl_slot = 0;    /* .bss 里存放类表指针的槽地址 (可 base 相对固定) */
static unsigned long  g_am_holder_idx = 0, g_am_holder_off = 0;

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
static volatile int           g_req_heroes     = 0;
static volatile int           g_req_binflush   = 0;
static volatile int           g_req_natfind    = 0;
static volatile int           g_req_natchain   = 0;
static volatile int           g_req_nat3      = 0;
static volatile int           g_req_natx2     = 0;
static volatile unsigned int  g_nf_hero = 0;
static volatile int           g_nf_x = 0, g_nf_z = 0;
static char                   g_hero_path[160];     /* 非空 = 写 JSON 文件供其他程序消费 */

/* heroes.json 头部字段说明 (_doc) */
static const char *g_hero_doc =
    "{\"seq\":\"输出序号,每次+1\",\"n\":\"英雄/角色总数\",\"heroes\":\"角色数组\","
    "\"i\":\"数组下标(0..n-1)\",\"a\":\"actor内存地址(十进制)\",\"camp\":\"阵营 1=左/蓝 2=右/红\","
    "\"objid\":\"对象ID\",\"hero\":\"英雄ID(官方)\",\"name\":\"英雄名(官方表;未知为?(0xID))\","
    "\"hp\":\"当前血量\",\"hpmax\":\"最大血量\",\"exp\":\"经验\",\"expmax\":\"升级所需经验\","
    "\"lvl\":\"等级(英雄=英雄等级; 技能内=该技能等级)\",\"gold\":\"金币\",\"incgold\":\"每秒被动金币\","
    "\"charge\":\"蓄力/能量值\",\"chargemax\":\"蓄力/能量上限\",\"shield\":\"护盾值\",\"shieldmax\":\"护盾上限\","
    "\"x\":\"坐标X (值/100=米)\",\"y\":\"坐标Y(高度)\",\"z\":\"坐标Z\",\"fx\":\"朝向向量X(值/100)\",\"fz\":\"朝向向量Z(值/100)\","
    "\"move\":\"移动速度(值/100)\",\"groundy\":\"地面高度(值/100)\","
    "\"ad\":\"物理攻击(当前值=基础+等级成长)\",\"def\":\"物理防御(当前值)\",\"res\":\"法术防御(当前值)\","    "\"equipcnt\":\"(保留,恒0;请用eqn)\",\"cfgid\":\"角色配置ID\","
    "\"dead\":\"1=死亡\",\"dying\":\"1=濒死\",\"revive\":\"复活剩余(秒)\",\"grass\":\"1=在草丛\",\"freeze\":\"1=被控/冰冻\",\"battle\":\"1=战斗中\","
    "\"nomove\":\"1=禁止移动\",\"inroom\":\"1=在房间内\",\"fantasy\":\"1=梦境/幻想态\",\"autoai\":\"1=AI托管\","
    "\"atktarget\":\"普攻锁定目标的objid(0=无)\","
    "\"cam\":\"1=在本机相机视野内\",\"lvis\":\"1=逻辑可见(暴露视野)\","
    "\"eqn\":\"已购装备数\",\"eq\":\"已购装备数组 [[装备ID,数量],...]\","
    "\"skills\":\"技能槽数组(见下)\","
    "\"s\":\"技能槽位 0..5\",\"lvl\":\"技能等级\",\"cd\":\"当前冷却(毫秒)\",\"cdmax\":\"冷却上限(毫秒)\","
    "\"ready\":\"1=可用\",\"bean\":\"法术/充能层数\",\"power\":\"能量\",\"powermax\":\"能量上限\","
    "\"tgt\":\"技能目标ID\",\"hit\":\"命中计数\",\"lvlup\":\"1=可升级\"}";

/* ===== 方案2: 定长二进制 + seqlock (供用户态 mmap 高频读取) ===== */
#define HB_MAGIC   0x48523031u   /* "HR01" */
#define HB_VERSION 1u
#define HB_MAXREC  16
struct __attribute__((packed)) hb_eq { unsigned short id, cnt; };
struct __attribute__((packed)) hb_sk {
    unsigned char lvl, ready, lvlup, bean;
    int cd, cdmax, power, powermax, tgt, hit;
};
struct __attribute__((packed)) hb_rec {
    unsigned int heroid, camp, objid;
    int hp, hpmax, exp, expmax, lvl, gold, incgold;
    int charge, chargemax, shield, shieldmax;
    int x, y, z, fx, fz, move, groundy;
    int mx, mz;                 /* 小地图组件里的位置(雾里也更新, 用作"真实坐标") */
    int ad, def, res;
    unsigned int atktarget;
    unsigned char dead, dying, grass, freeze, battle, nomove, inroom, fantasy, autoai, lvis, cam, me;
    unsigned int eqn;
    struct hb_eq eq[8];
    struct hb_sk sk[6];
};
struct __attribute__((packed)) hb_hdr {
    unsigned int magic, version, seq, rec_size, max_rec, n;
    unsigned long long ts_ms;
    unsigned int flags, rsv[7];
};
static char                   g_bin_path[160];      /* 非空 = 写定长二进制 */
static int                    g_bin_interval = 0;   /* ms, >0 周期 */
static unsigned int           g_bin_seq = 0;
static int                    g_bin_created = 0;
static unsigned int           g_bin_ts = 0;
static void                  *g_bin_filp = NULL;   /* 常驻打开, 避免每轮 filp_open */
static struct hb_rec          g_bin_rec[HB_MAXREC];
static unsigned int           g_bin_n = 0;

/* hbin_write() 定义见下方 do_heroes 之前 (需 g_iobuf) */
static volatile int           g_hero_interval  = 0; /* ms, >0 = 周期刷新 */
static unsigned long          g_hero_seq       = 0;
static volatile int           g_req_native     = 0;
static volatile int           g_req_hwbp_valid = 0;
static volatile int           g_hwbp_off       = 0;
static volatile int           g_req_hwbpslot_valid = 0;
static volatile int           g_req_fullchain   = 0;
static volatile int           g_req_ns_valid   = 0;
static volatile int           g_req_corr_valid = 0;
static volatile int           g_req_cscan_valid = 0;
static volatile int           g_req_pair_valid  = 0;
static volatile int           g_req_cad2_valid = 0;
static volatile int           g_req_cams_valid = 0;
static volatile int           g_req_hwbpslot4_valid = 0;
static volatile int           g_req_hwbpxva_valid = 0;
static unsigned long          g_hwbp_va = 0;
static volatile int           g_hwbp_slot      = 0;
static volatile int           g_hwbp_tid       = 0;
static unsigned long          g_hwbp_addr      = 0;
static unsigned long          g_hwbp_base      = 0;

static volatile int           g_req_walk       = 0;
static volatile int           g_req_chain      = 0;
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

/* libGameCore.so base: ELF magic + manager 验证 */
#define GC_MANAGER_OBJ_ULF 0x220UL
static int gc_base_cb(void *udata, unsigned long start, unsigned long vend, unsigned long flags)
{
    unsigned long *out = udata;
    unsigned char magic[4] = {0};
    unsigned long mgr = 0;
    (void)vend;
    if (!(flags & VM_READ) || (flags & VM_EXEC)) return 0;
    rm(magic, start, 4);
    if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') return 0;
    rm(&mgr, start + GC_MANAGER_BSS_OFF, 8);
    mgr = untag(mgr);
    if (mgr && mgr < 0x100000000UL) return 0;
    if (mgr) {
        unsigned long ulf = 0;
        rm(&ulf, mgr + GC_OBJ_UNIT_LABEL_FINDER, 8);
        ulf = untag(ulf);
        if (!ulf || ulf < 0x100000000UL) return 0;
    }
    *out = start;
    return 1;
}

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

/* ============================================================ 对局英雄数据 (ctl0 heroes)
 * 链: ActorManager 实例(+0x18 HeroActors: TinyValueList<PoolObjHandle<ActorLinker>>)
 *     -> .items(+0x8 数组) / .count(+0x10)
 *     -> 元素(数组对象 +0x20, 步长 0x10, obj@+0)
 *     -> ActorLinker: name@0x4B0, ObjID@0x4AC, ValueComponent@0x3B8(actorHp@+0x38),
 *        position@0x4C4(float x,y,z)
 * 阵营: ActorManager.CampsActors(+0x78 数组, 按 camp 分桶的 TinyValueList)
 * 全程页表物理读, 不阻塞目标。 */
#define OFF_AM_HEROACTORS   0x18UL
#define OFF_AM_CAMPSACTORS  0x78UL
#define OFF_TVL_ITEMS       0x08UL
#define OFF_TVL_COUNT       0x10UL
#define ARR_ELEMS           0x20UL
#define ELEM_STRIDE         0x10UL
#define AL_NAME             0x4B0UL
#define AL_OBJID            0x4ACUL
#define AL_VALUECOMP        0x3B8UL
#define VC_HP               0x38UL
#define VC_HPMAX            0x3CUL
#define AL_POS              0x4C4UL
#define AL_RESCFG           0x38UL     /* ActorLinker.resHeroCfgInfo (低32=英雄ID) */
#define AL_EQUIP            0x30UL     /* ActorLinker.EquipComponent -> EquipLinkerComponent */
#define EQ_BUYCOUNT         0x2CUL     /* EquipLinkerComponent.buyEquipCount */
#define AL_ACTORCTRL        0x3C0UL    /* ActorLinker.ActorControl -> ObjLinkerWrapper */
#define AL_FORWARD          0x4B8UL    /* ActorLinker.forward (float xyz) */
#define AL_MOVESPEED        0x764UL    /* ActorLinker.moveSpeed */
#define VC_EXP              0x28UL     /* ValueLinkerComponent */
#define VC_EXPMAX           0x2CUL
#define VC_GOLD             0x30UL
#define VC_INCGOLD          0x34UL
#define VC_SHIELDMAX        0x40UL
#define VC_SHIELD           0x44UL
#define VC_CHARGEMAX        0x48UL     /* actorChargeValueMax */
#define VC_CHARGE           0x4CUL     /* actorChargeValue (蓄力/能量) */
#define VC_LEVEL            0x58UL
#define OC_ISDEAD           0x39UL     /* ObjLinkerWrapper (ActorControl) */
#define OC_ISDYING          0x3AUL
#define OC_REVIVE           0x4CUL
#define OC_GRASS            0x5AUL
#define OC_FREEZE           0x5BUL
#define OC_BATTLE           0x34UL
#define OC_CONFIGID         0x28UL
#define OC_NOMOVE           0x58UL
#define OC_INROOM           0x5CUL
#define OC_FANTASY          0x5EUL
#define OC_AUTOAI           0x36UL
#define OC_ATKTARGET        0x88UL     /* commonAttackEnemyHeroTargetID */
#define AL_GROUNDY          0x480UL
#define AL_MINIMAP          0x3F0UL     /* ActorLinker.miniMap -> MinimapComponentNew */
#define MM_ACTORPOS         0x58UL      /* MinimapComponentNew.m_actorPos (Vector3, 雾里也更新) */
#define AL_LOGICVIS         0x505UL     /* ActorLinker._logicVisible */
#define AL_MESHVIS          0x506UL     /* ActorLinker._meshVisible  */
#define AL_INCAM            0x507UL     /* ActorLinker._inCamera (游戏自己算的"在相机内") */
#define SSL_BEAN            0x44UL     /* SkillSlotLinker */
#define SSL_POWER           0x68UL
#define SSL_POWERMAX        0x70UL
#define SSL_TARGET          0x80UL
#define SSL_HIT             0x78UL
#define SSL_CANLEVEL        0x95UL
#define AL_SKILLCOMP        0x28UL     /* ActorLinker.SkillControl -> SkillLinkerComponent */
#define SLC_SLOTARR         0x28UL     /* SkillLinkerComponent.skillSlotLinkerArray */
#define SSL_CD              0x5CUL     /* SkillSlotLinker.CurSkillCD */
#define SSL_CDMAX           0x60UL     /* SkillSlotLinker.CurSkillCDMax */
#define AL_BUFF             0x410UL    /* ActorLinker -> BuffLinkerComponent */
#define EQ_C_COMMON         0x40UL     /* EquipLinkerComponent.m_commonContainer (CEquipContainer*) */
#define EQ_C_HORIZON        0x48UL
#define EQ_C_LVLX           0x50UL
#define CEC_GRID            0x08UL     /* CEquipContainer.m_gridEquips (array ptr) */
#define CEC_MAX             0x10UL     /* CEquipContainer.m_maxGridCount */
#define BUF_SPAWNED         0x28UL     /* BuffLinkerComponent.SpawnedBuffList */
#define GRE_STRIDE          0x28UL     /* 装备格数组: 元素 stGridEquipInfo */
#define GRE_AMOUNT          0x28UL     /* 相对数组起点的 m_amount */
#define GRE_EQUIPID         0x30UL     /* 相对数组起点的 m_equipID (ushort, 低16位) */
/* ActorLinker.TheStaticData (ActorStaticData 内联) .TheBaseAttribute (.BaseAttribute 内联) */
#define AL_STATICDATA       0x580UL
#define ASD_BASEATTR        0x08UL
#define BA_HP               0x18UL     /* BaseHp */
#define BA_AD               0x44UL     /* BaseAd */
#define BA_AP               0x4CUL     /* BaseAp */
#define BA_DEF              0x54UL     /* BaseDef */
#define BA_RES              0x5CUL     /* BaseRes */
#define BA_MOVESPD          0x0CUL     /* MoveSpeed */
/* 运行时英雄基础属性结构 (BaseAttribute), 实测 a+0x578 起 (真机校验: 小乔 163/0/150/75) */
#define AB_BASE             0x578UL
#define ABI_HP              0x18UL     /* BaseHp */
#define ABI_AD              0x44UL     /* BaseAd  (物攻 基础) */
#define ABI_PAD             0x48UL     /* PerLvAd (成长 ×10000) */
#define ABI_AP              0x4CUL     /* BaseAp  (法强 基础) */
#define ABI_PAP             0x50UL     /* PerLvAp */
#define ABI_DEF             0x54UL     /* BaseDef (物抗 基础) */
#define ABI_PDF             0x58UL     /* PerLvDef */
#define ABI_RES             0x5CUL     /* BaseRes (法抗 基础) */
#define ABI_PRS             0x60UL     /* PerLvRes */
#define ABI_ASP             0x10UL     /* BaseAtkSpeed (攻速) */
#define ABI_PASP            0x14UL     /* PerLvAtkSpeed */
#define ABI_HPR             0x20UL     /* BaseHpRecover (回血/5s) */
#define ABI_PHPR            0x24UL
#define ABI_EP              0x2CUL     /* BaseEp (法力) */
#define ABI_EPG             0x30UL     /* EpGrowth */
#define ABI_EPR             0x34UL     /* BaseEpRecover (回蓝/5s) */
#define ABI_PEPR            0x38UL
#define ABI_ATKI            0x64UL     /* AttackIntensity (攻击强度) */
#define ABI_PATKI           0x68UL
#define ABI_CRIT            0x6CUL     /* CriticalChance (暴击率) */
#define ABI_CRITD           0x70UL     /* CriticalDamage (暴击伤害) */

static int rf32x100(unsigned long a)
{
    float f = 0.0f;
    rm(&f, a, 4);
    return (int)(f * 100.0f);
}
static int rb(unsigned long a) { unsigned char c = 0; rm(&c, a, 1); return c; }


/* 用 CampsActors 分桶判断某 actor 的阵营(返回 0 基索引, -1 未知) */
static int camp_of(unsigned long inst, unsigned long a)
{
    unsigned long ca = rptr(inst + OFF_AM_CAMPSACTORS);
    unsigned int cmax = 0, c;
    unsigned long elems;
    if (!ca) return -1;
    rm(&cmax, ca + 0x18, 4);
    if (cmax > 8) cmax = 8;
    elems = ca + ARR_ELEMS;
    for (c = 0; c < cmax; c++) {
        unsigned long list = rptr(elems + (unsigned long)c * 8);
        unsigned long items;
        unsigned int cnt = 0, j;
        if (!list) continue;
        items = rptr(list + OFF_TVL_ITEMS);
        rm(&cnt, list + OFF_TVL_COUNT, 4);
        if (cnt > 64) continue;
        for (j = 0; j < cnt; j++)
            if (rptr(items + ARR_ELEMS + (unsigned long)j * ELEM_STRIDE) == a)
                return (int)c;
    }
    return -1;
}

struct hscan { unsigned long amc; unsigned long inst; int found; };
static int hscan_cb(void *udata, unsigned long start, unsigned long end, unsigned long flags)
{
    struct hscan *h = udata;
    unsigned long off = 0, total = end - start;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && !h->found) {
        unsigned long want = total - off;
        int n, k;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        n = (int)want;
        for (k = 0; k + 8 <= n; k += 8) {
            unsigned long w, c;
            char nm[48];
            __builtin_memcpy(&w, g_iobuf + k, 8);
            if (untag(w) != h->amc) continue;
            c = start + off + (unsigned long)k;      /* 候选实例 */
            {
                unsigned long cont = rptr(c + OFF_AM_HEROACTORS);
                unsigned long cls = rptr(cont);
                if (cls && rstr(rptr(cls + CLASS_NAME_O), nm, sizeof(nm)) > 0 && strstr(nm, "TinyValueList")) {
                    h->inst = c; h->found = 1; return 1;
                }
            }
        }
        off += (unsigned long)n;
    }
    return 0;
}

/* 校验 ActorManager 实例是否仍有效 (klass == ActorManager 且 HeroActors 容器是 TinyValueList) */
/* 只校验"实例还活着": klass 对 + HeroActors 是 TinyValueList。
 * 注意: 不能把 cnt==0 当成失效 —— 局外/结算时 cnt 就是 0,
 * 那样会每轮触发一次全堆扫描 (实测空闲 CPU 被吃掉 60%)。 */
static int am_alive(unsigned long inst, unsigned long amc)
{
    unsigned long cont, cls;
    char nm[48];
    if (!inst || untag(rptr(inst)) != amc)
        return 0;
    cont = rptr(inst + OFF_AM_HEROACTORS);
    if (!cont)
        return 0;
    cls = rptr(cont);
    if (!cls)
        return 0;
    if (rstr(rptr(cls + CLASS_NAME_O), nm, sizeof(nm)) <= 0)
        return 1;                       /* 名字页未驻留: 不据此判失效, 避免触发扫描 */
    return strstr(nm, "TinyValueList") != NULL;
}

static int am_valid(unsigned long inst, unsigned long amc)
{
    unsigned long cont;
    unsigned int cnt = 0;
    if (!am_alive(inst, amc))
        return 0;
    cont = rptr(inst + OFF_AM_HEROACTORS);
    rm(&cnt, cont + OFF_TVL_COUNT, 4);
    return cnt > 0 && cnt <= 64;
}

/* 把 g_bin_rec/g_bin_n 作为定长 seqlock 文件写出 (首次建到定长, 之后原地覆盖) */
static void hbin_write(void)
{
    void *f = NULL, *old_cred = NULL;
    unsigned long long t0 = p_ktime_get_ns ? p_ktime_get_ns() : 0;
    struct hb_hdr *H = (struct hb_hdr *)g_iobuf;
    unsigned long hdr_sz = sizeof(struct hb_hdr), rec_sz = sizeof(struct hb_rec);
    unsigned long total = hdr_sz + HB_MAXREC * rec_sz;
    long long p;
    int first = !g_bin_created;
    if (!g_bin_path[0] || total > sizeof(g_iobuf)) return;
    if (!p_filp_open || !p_kernel_write || !p_filp_close) return;

    memset(g_iobuf, 0, total);
    H->magic = HB_MAGIC; H->version = HB_VERSION;
    H->rec_size = (unsigned int)rec_sz; H->max_rec = HB_MAXREC;
    H->n = g_bin_n; H->ts_ms = g_bin_ts++; H->flags = 0;
    H->rsv[0] = (unsigned int)g_target_pid;          /* 供用户态 status 显示 (内核定位结果) */
    H->rsv[1] = g_target_mm ? 1u : 0u;               /* mm 是否已锁定 */
    H->seq = g_bin_seq;                              /* 偶数=稳定 */
    if (g_bin_n) memcpy(g_iobuf + hdr_sz, g_bin_rec, g_bin_n * rec_sz);

    /* SELinux 在 write 时也会做 file_permission 检查, 所以 creds 覆盖必须包住 open+write,
     * 不能只在 open 时覆盖 (否则内核线程上下文写入被拒, O_TRUNC 后留下 0 字节文件)。 */
    if (g_io_cred && p_override_creds) old_cred = p_override_creds(g_io_cred);

    if (!g_bin_filp) {
        g_bin_filp = p_filp_open(g_bin_path,
                        KPM_O_WRONLY | KPM_O_CREAT | (first ? KPM_O_TRUNC : 0), 0644);
        if (!g_bin_filp || (unsigned long)g_bin_filp >= (unsigned long)-4095UL) {
            g_bin_filp = NULL;
            if (old_cred && p_revert_creds) p_revert_creds(old_cred);
            return;
        }
    }
    f = g_bin_filp;
    g_bin_created = 1;

    {
        int ok = 1;
        if (first) {
            p = 0;
            ok = (p_kernel_write(f, g_iobuf, total, &p) == (long)total);
        } else {
            unsigned int odd = g_bin_seq + 1, even = g_bin_seq + 2;
            p = 8;  p_kernel_write(f, &odd, 4, &p);       /* seq = 奇 (写入中) */
            p = 0;  p_kernel_write(f, g_iobuf, 8, &p);    /* magic/version 每次都补上 */
            p = 12; p_kernel_write(f, g_iobuf + 12, total - 12, &p);
            g_bin_seq = even;
            p = 8;  p_kernel_write(f, &even, 4, &p);      /* seq = 偶 (稳定) */
        }
        if (!ok) {
            pr_warn("[hero-reader] hbin: 首次写入失败, 重建文件\n");
            if (g_bin_filp && p_filp_close) p_filp_close(g_bin_filp, NULL);
            g_bin_filp = NULL; g_bin_created = 0;
        }
    }
    if (old_cred && p_revert_creds) p_revert_creds(old_cred);
    if (t0 && p_ktime_get_ns) {
        unsigned long long dt = (p_ktime_get_ns() - t0) / 1000ULL;
        g_bw_n++; g_bw_total_us += dt;
        if (dt > g_bw_max_us) g_bw_max_us = dt;
    }
}


/* ===================== 原生 (libGameCore) actor 链 =====================
 * 来源: Devil 采样材料核实 (同版本 libGameCore).
 *   .bss + 0x182810 -> p ; p + 0x250 -> roster
 *   roster[i] (stride 0x18) -> actor
 *   actor + 0x28 = hero cfg id, +0x34 = camp(1/2)
 *   actor + 0xA8 -> node ; node + 0x10 -> link ; link + 0x2C = (x,0,z) int32 x1000
 *   备路: actor - 0x758 -> 指针 -> (x,0,z)
 * 全部纯指针读, 零扫描 (roster 定位只做一次, 用 .bss 大小+链路校验).
 */
#define GC_BSS_ROSTER_OFF   0x182810UL
#define GC_BSS_VA_OFF       0x526F000UL   /* ELF: .bss 相对 image base 的 VA */
#define GC_ROOT_VA          0x53F1810UL   /* ELF: root 槽 = .bss + 0x182810 */
#define GC_ROSTER_PTR_OFF   0x250UL
#define GC_ROSTER_STRIDE    0x18UL
#define NA_ID               0x28UL
#define NA_CAMP             0x34UL
#define NA_NODE             0xA8UL
#define NODE_LINK           0x10UL
#define LINK_XYZ            0x2CUL
#define NA_XYZPTR_DELTA     0x758UL
#define NAT_MAX             16

struct nat_rec { unsigned int hero, camp; int x, z; int hp, hpmax; };
static unsigned long g_nat_roster = 0;
static unsigned long g_gc_bss = 0;      /* libGameCore .bss 运行期起始 */

static int nat_plausible(unsigned long q) { return q > 0x10000UL && q < 0x800000000000UL; }

struct nat_cand { unsigned long roster; };
static int nat_scan_cb(void *ud, unsigned long start, unsigned long end, unsigned long flags)
{
    struct nat_cand *c = ud;
    unsigned long sz = end - start, p, r, a;
    unsigned int hero = 0, camp = 0;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (sz < 0x1d0000UL || sz > 0x210000UL) return 0;      /* libGameCore .bss = 0x1df000 */
    p = rptr(start + GC_BSS_ROSTER_OFF);
    if (!nat_plausible(p)) return 0;
    r = rptr(p + GC_ROSTER_PTR_OFF);
    if (!nat_plausible(r)) return 0;
    a = untag(rptr(r));
    if (!nat_plausible(a)) return 0;
    if (!rm(&hero, a + NA_ID, 4) || hero == 0 || hero > 4000) return 0;
    if (!rm(&camp, a + NA_CAMP, 4) || (camp != 1 && camp != 2)) return 0;
    c->roster = r;
    g_gc_bss = start;
    return 1;
}

struct gcb { unsigned long base; int found; };
static int gcb_cb(void *ud, unsigned long start, unsigned long end, unsigned long flags)
{
    struct gcb *g = ud;
    unsigned int magic = 0, hero = 0;
    unsigned long p, r, a;
    if (!(flags & VM_READ) || (flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (end - start < GC_ROOT_VA + 8) return 0;
    if (!rm(&magic, start, 4) || magic != 0x464C457FU) return 0;   /* ELF magic */
    p = rptr(start + GC_ROOT_VA);
    if (!nat_plausible(p)) return 0;
    r = rptr(p + GC_ROSTER_PTR_OFF);
    if (!nat_plausible(r)) return 0;
    a = untag(rptr(r));
    if (!nat_plausible(a)) return 0;
    if (!rm(&hero, a + NA_ID, 4) || hero == 0 || hero > 4000) return 0;
    g->base = start; g->found = 1;
    return 1;
}

/* 纯静态常量定位: image base -> root = base + GC_ROOT_VA -> 全指针 */
static unsigned long gc_base(void)
{
    struct gcb g;
    if (g_gc_base && g_gc_bss) return g_gc_base;
    g.base = 0; g.found = 0;
    vma_walk(gcb_cb, &g);
    if (!g.found) return 0;
    g_gc_base = g.base;
    g_gc_bss  = g.base + GC_BSS_VA_OFF;
    return g_gc_base;
}

static int nat_xyz(unsigned long actor, int *ox, int *oz);

/* 快速校验 roster: 前 16 个槽里至少要有 5 个合法 actor (hero/camp/坐标) */
static int nat_roster_ok(unsigned long r)
{
    int i, ok = 0;
    if (!nat_plausible(r)) return 0;
    for (i = 0; i < NAT_MAX; i++) {
        unsigned long a = untag(rptr(r + (unsigned long)i * GC_ROSTER_STRIDE));
        unsigned int hero = 0, camp = 0;
        int x = 0, z = 0;
        if (!nat_plausible(a)) continue;
        if (!rm(&hero, a + NA_ID, 4) || hero == 0 || hero > 4000) continue;
        if (!rm(&camp, a + NA_CAMP, 4) || (camp != 1 && camp != 2)) continue;
        if (!nat_xyz(a, &x, &z)) continue;
        ok++;
    }
    return ok >= 5;
}

static unsigned long nat_roster(void)
{
    struct nat_cand c;
    /* 先走静态链 (3 次读): 换局/换进程后 root 会变, 不能先信缓存 */
    {
        unsigned long b = gc_base();
        if (b) {
            unsigned long p = rptr(b + GC_ROOT_VA);
            unsigned long r = nat_plausible(p) ? rptr(p + GC_ROSTER_PTR_OFF) : 0;
            if (nat_roster_ok(r)) { g_nat_roster = r; return r; }
        }
    }
    if (g_nat_roster && nat_roster_ok(g_nat_roster)) return g_nat_roster;
    g_nat_roster = 0;
    c.roster = 0;
    vma_walk(nat_scan_cb, &c);
    if (c.roster) g_nat_roster = c.roster;
    return c.roster;
}

static int nat_xyz_ok(int xx, int y, int zz)
{
    return y == 0 && xx != 0 && zz != 0 &&
           xx > -300000 && xx < 300000 && zz > -300000 && zz < 300000;
}

static int nat_xyz(unsigned long actor, int *ox, int *oz)
{
    unsigned long node, link, xp, c1, c2, tr;
    int xx = 0, y = 0, zz = 0;
    /* 主链 (2026-10-17 实测, 匹配/训练营都稳定):
     *   actor+0xA8 -> node+0x10 -> link
     *   link[0] = transform ; *(transform+0x60) = p2
     *   p2 = (x, 0, z) int32 ×1000      ← 世界坐标 (雾里也更新)
     * link+0x2C 是另一份 (训练营里与 p2 同址, 匹配里是局部/未更新值), 仅作备选。 */
    node = untag(rptr(actor + NA_NODE));
    if (nat_plausible(node)) {
        link = untag(rptr(node + NODE_LINK));
        if (nat_plausible(link)) {
            tr = untag(rptr(link));
            if (nat_plausible(tr)) {
                unsigned long p2 = untag(rptr(tr + 0x60UL));
                if (nat_plausible(p2)) {
                    xx = y = zz = 0;
                    rm(&xx, p2, 4); rm(&y, p2 + 4, 4); rm(&zz, p2 + 8, 4);
                    if (nat_xyz_ok(xx, y, zz)) { *ox = xx; *oz = zz; return 1; }
                }
            }
            /* 备选: link+0x2C (训练营等场景) */
            xx = y = zz = 0;
            rm(&xx, link + LINK_XYZ, 4); rm(&y, link + LINK_XYZ + 4, 4); rm(&zz, link + LINK_XYZ + 8, 4);
            if (nat_xyz_ok(xx, y, zz)) { *ox = xx; *oz = zz; return 1; }
        }
    }
    /* 备链: actor+0x248 -> +0x128 -> +0x2C */
    c1 = untag(rptr(actor + 0x248UL));
    if (nat_plausible(c1)) {
        c2 = untag(rptr(c1 + 0x128UL));
        if (nat_plausible(c2)) {
            xx = y = zz = 0;
            rm(&xx, c2 + LINK_XYZ, 4); rm(&y, c2 + LINK_XYZ + 4, 4); rm(&zz, c2 + LINK_XYZ + 8, 4);
            if (nat_xyz_ok(xx, y, zz)) { *ox = xx; *oz = zz; return 1; }
        }
    }
    xp = untag(rptr(actor - NA_XYZPTR_DELTA));
    if (nat_plausible(xp)) {
        xx = y = zz = 0;
        rm(&xx, xp, 4); rm(&y, xp + 4, 4); rm(&zz, xp + 8, 4);
        if (nat_xyz_ok(xx, y, zz)) { *ox = xx; *oz = zz; return 1; }
    }
    return 0;
}

static int nat_collect(struct nat_rec *out, int max)
{
    unsigned long r = nat_roster(), i;
    int n = 0;
    if (!r) return 0;
    for (i = 0; i < NAT_MAX && n < max; i++) {
        unsigned long a = untag(rptr(r + i * GC_ROSTER_STRIDE));
        unsigned int hero = 0, camp = 0;
        int x = 0, z = 0;
        if (!nat_plausible(a)) continue;
        if (!rm(&hero, a + NA_ID, 4) || hero == 0 || hero > 4000) continue;
        if (!rm(&camp, a + NA_CAMP, 4) || (camp != 1 && camp != 2)) continue;
        if (!nat_xyz(a, &x, &z)) continue;
        out[n].hero = hero; out[n].camp = camp; out[n].x = x; out[n].z = z;
        out[n].hp = 0; out[n].hpmax = 0;
        {   /* 属性组件: actor+0x1D0 -> +0xC0 hp, +0xC8 hpmax */
            unsigned long comp = untag(rptr(a + 0x1D0UL));
            if (nat_plausible(comp)) {
                rm(&out[n].hp, comp + 0xC0UL, 4);
                rm(&out[n].hpmax, comp + 0xC8UL, 4);
            }
        }
        n++;
    }
    return n;
}

static void do_native(void)
{
    struct nat_rec nr[NAT_MAX];
    int n = nat_collect(nr, NAT_MAX), i;
    pr_info("[hero-reader] native: roster=0x%lx n=%d\n", g_nat_roster, n);
    for (i = 0; i < n; i++)
        pr_info("[hero-reader] nat[%d] hero=%u camp=%u xyz=(%d,0,%d)\n",
                i, nr[i].hero, nr[i].camp, nr[i].x, nr[i].z);
}


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


/* ==================== 硬件写断点 (perf hw_breakpoint) ====================
 * 用途: 在 xyz 地址上挂写断点, 命中时记录 user PC / x0..x7 / LR
 *       -> 直接定位"谁写了坐标", 不必再猜指令形态.
 * 命令: hwbp <addr_hex> <tid_dec> [libgamecore_base_hex]   挂一个线程
 *       hwbp off                                         全部卸载
 */
#define HR_PERF_TYPE_BREAKPOINT 5
#define HR_HW_BREAKPOINT_W      2
#define HR_HW_BREAKPOINT_LEN_4  4

struct hr_perf_attr {
    unsigned int       type;
    unsigned int       size;
    unsigned long long config;
    unsigned long long sample_period;
    unsigned long long sample_type;
    unsigned long long read_format;
    unsigned long long flags;          /* bit5=exclude_kernel, bit6=exclude_hv */
    unsigned int       wakeup_events;
    unsigned int       bp_type;
    unsigned long long bp_addr;
    unsigned long long bp_len;
    unsigned long long branch_sample_type;
    unsigned long long sample_regs_user;
    unsigned int       sample_stack_user;
    int                clockid;
    unsigned long long sample_regs_intr;
    unsigned int       aux_watermark;
    unsigned short     sample_max_stack;
    unsigned short     r2;
    unsigned int       aux_sample_size;
    unsigned int       r3;
    unsigned long long sig_data;          /* 6.6: sizeof(perf_event_attr)=128 */
};

struct hr_pt_regs { unsigned long regs[31]; unsigned long sp; unsigned long pc; unsigned long pstate; };

struct hr_bp_hit { unsigned long pc, lr, far, x[8]; };
#define HR_BP_RING 16
static struct hr_bp_hit      g_bp_ring[HR_BP_RING];
static volatile unsigned int g_bp_head, g_bp_tail;
static void                 *g_bp_events[64];
static int                   g_bp_nev = 0;
static unsigned long         g_bp_gcbase = 0;
static unsigned int           g_bp_type_x = HR_HW_BREAKPOINT_W;
static unsigned int           g_bp_len_x  = HR_HW_BREAKPOINT_LEN_4;

static void *(*p_register_user_hw_breakpoint)(void *, void *, void *, void *);
static void *(*p_find_get_task_by_vpid)(int);
static void *(*p_find_get_pid)(int);
static void *(*p_get_pid_task)(void *, int);
static void  (*p_put_pid)(void *);
static void  (*p_put_task_struct)(void *);
static void  (*p_unregister_hw_breakpoint)(void *);
static void  (*p_perf_event_enable)(void *);

/* 命中后立刻关掉当前 CPU 上匹配该地址的 watchpoint (DBGWCRn.E=0)
 * 参考 rwProcMem33 的 toggle_bp_registers_directly(): 不做这一步会形成中断风暴 */
static void hr_bp_kill_current(unsigned long addr)
{
    unsigned long want = addr & ~7UL, v = 0, c = 0;
    int n, hit = -1;

    for (n = 0; n < 4; n++) {
        switch (n) {
        case 0: __asm__ __volatile__("mrs %0, dbgwvr0_el1" : "=r"(v)); break;
        case 1: __asm__ __volatile__("mrs %0, dbgwvr1_el1" : "=r"(v)); break;
        case 2: __asm__ __volatile__("mrs %0, dbgwvr2_el1" : "=r"(v)); break;
        case 3: __asm__ __volatile__("mrs %0, dbgwvr3_el1" : "=r"(v)); break;
        }
        if ((v & ~7UL) == want) { hit = n; break; }
    }
    if (hit < 0) return;
    switch (hit) {
    case 0: __asm__ __volatile__("mrs %0, dbgwcr0_el1" : "=r"(c)); break;
    case 1: __asm__ __volatile__("mrs %0, dbgwcr1_el1" : "=r"(c)); break;
    case 2: __asm__ __volatile__("mrs %0, dbgwcr2_el1" : "=r"(c)); break;
    case 3: __asm__ __volatile__("mrs %0, dbgwcr3_el1" : "=r"(c)); break;
    }
    c &= ~1UL;                                  /* clear E */
    switch (hit) {
    case 0: __asm__ __volatile__("msr dbgwcr0_el1, %0" :: "r"(c)); break;
    case 1: __asm__ __volatile__("msr dbgwcr1_el1, %0" :: "r"(c)); break;
    case 2: __asm__ __volatile__("msr dbgwcr2_el1, %0" :: "r"(c)); break;
    case 3: __asm__ __volatile__("msr dbgwcr3_el1, %0" :: "r"(c)); break;
    }
    /* 执行断点用的是 BCR/BVR, 也必须一起清 */
    v = 0; hit = -1;
    {
        unsigned long want2 = addr & ~3UL;
        for (n = 0; n < 4; n++) {
            switch (n) {
            case 0: __asm__ __volatile__("mrs %0, dbgbvr0_el1" : "=r"(v)); break;
            case 1: __asm__ __volatile__("mrs %0, dbgbvr1_el1" : "=r"(v)); break;
            case 2: __asm__ __volatile__("mrs %0, dbgbvr2_el1" : "=r"(v)); break;
            case 3: __asm__ __volatile__("mrs %0, dbgbvr3_el1" : "=r"(v)); break;
            }
            if ((v & ~3UL) == want2) { hit = n; break; }
        }
        if (hit >= 0) {
            c = 0;
            switch (hit) {
            case 0: __asm__ __volatile__("mrs %0, dbgbcr0_el1" : "=r"(c)); break;
            case 1: __asm__ __volatile__("mrs %0, dbgbcr1_el1" : "=r"(c)); break;
            case 2: __asm__ __volatile__("mrs %0, dbgbcr2_el1" : "=r"(c)); break;
            case 3: __asm__ __volatile__("mrs %0, dbgbcr3_el1" : "=r"(c)); break;
            }
            c &= ~1UL;
            switch (hit) {
            case 0: __asm__ __volatile__("msr dbgbcr0_el1, %0" :: "r"(c)); break;
            case 1: __asm__ __volatile__("msr dbgbcr1_el1, %0" :: "r"(c)); break;
            case 2: __asm__ __volatile__("msr dbgbcr2_el1, %0" :: "r"(c)); break;
            case 3: __asm__ __volatile__("msr dbgbcr3_el1, %0" :: "r"(c)); break;
            }
        }
    }
    __asm__ __volatile__("isb");
}

static volatile int g_bp_fired = 0;

static void hr_bp_handler(void *bp, void *data, struct hr_pt_regs *regs)
{
    unsigned int i = g_bp_head;   /* 单写者场景; 不用 __atomic (会引入 __aarch64_ldadd4_relax, KPM 无法解析) */
    g_bp_head = i + 1;
    struct hr_bp_hit *h = &g_bp_ring[i & (HR_BP_RING - 1)];
    int k;
    (void)bp; (void)data;
    if (g_bp_fired) return;            /* 已命中过: 立即返回, 避免风暴 */
    g_bp_fired = 1;
    __asm__ __volatile__("isb");
    if (!regs) return;
    h->pc = regs->pc;
    h->lr = regs->regs[30];
    {   /* FAR_EL1: 触发异常的访问地址 (验证断点是否真的编到目标地址) */
        unsigned long f = 0;
        __asm__ __volatile__("mrs %0, far_el1" : "=r"(f));
        h->far = f;
    }
    for (k = 0; k < 8; k++) h->x[k] = regs->regs[k];
    hr_bp_kill_current(g_hwbp_addr);   /* ★ 单次采样: 立刻关掉, 防止中断风暴 */
}

static void hr_bp_drain(void)
{
    int n = 0;
    while (g_bp_tail != g_bp_head && n < 20) {
        struct hr_bp_hit *h = &g_bp_ring[g_bp_tail & (HR_BP_RING - 1)];
        pr_info("[hero-reader] hwbp: pc=0x%lx far=0x%lx gc=%s0x%lx lr=0x%lx x0=%lx x1=%lx x2=%lx x3=%lx x4=%lx x5=%lx x6=%lx x7=%lx\n",
                h->pc, h->far,
                (g_bp_gcbase && h->pc >= g_bp_gcbase) ? "" : "?",
                (g_bp_gcbase && h->pc >= g_bp_gcbase) ? (h->pc - g_bp_gcbase) : h->pc,
                h->lr, h->x[0], h->x[1], h->x[2], h->x[3], h->x[4], h->x[5], h->x[6], h->x[7]);
        g_bp_tail++;
        n++;
    }
}

static void hr_bp_clear(void)
{
    int i, n = g_bp_nev;
    if (!n) return;
    if (!p_unregister_hw_breakpoint)
        pr_warn("[hero-reader] hwbp: 缺 unregister_hw_breakpoint, 无法注销!\n");
    for (i = 0; i < n; i++) {
        if (g_bp_events[i] && p_unregister_hw_breakpoint) p_unregister_hw_breakpoint(g_bp_events[i]);
        g_bp_events[i] = NULL;
    }
    g_bp_nev = 0;
    pr_info("[hero-reader] hwbp: 已注销 %d 个事件\n", n);
}

static void do_hwbp(void);   /* fwd */

/* 内核内从 roster 解析第 slot 个 actor 的 xyz 地址 (不依赖用户态算地址) */
static int nat_xyz_addr(int slot, unsigned long *out)
{
    unsigned long r = nat_roster(), i;
    int idx = 0;
    if (!r) return 0;
    for (i = 0; i < NAT_MAX; i++) {
        unsigned long a = untag(rptr(r + i * GC_ROSTER_STRIDE));
        unsigned char hero = 0;
        unsigned int h32 = 0, camp = 0;
        unsigned long node, link;
        int x = 0, z = 0;
        (void)hero;
        if (!nat_plausible(a)) break;
        if (!rm(&h32, a + NA_ID, 4) || h32 == 0 || h32 > 4000) continue;
        if (!rm(&camp, a + NA_CAMP, 4) || (camp != 1 && camp != 2)) continue;
        if (!nat_xyz(a, &x, &z)) continue;
        if (idx == slot) {
            node = untag(rptr(a + NA_NODE));
            if (!nat_plausible(node)) return 0;
            link = untag(rptr(node + NODE_LINK));
            if (!nat_plausible(link)) return 0;
            *out = link + LINK_XYZ;
            return 1;
        }
        idx++;
    }
    return 0;
}

static void do_hwbpxva(void)
{
    unsigned long img, addr;
    if (!g_gc_bss) { (void)nat_roster(); }
    if (!g_gc_bss) { pr_warn("[hero-reader] hwbpxva: 找不到 libGameCore .bss\n"); return; }
    img = g_gc_bss - GC_BSS_VA_OFF;
    addr = img + g_hwbp_va;
    pr_info("[hero-reader] hwbpxva: va=0x%lx -> addr=0x%lx tid=%d\n", g_hwbp_va, addr, g_hwbp_tid);
    g_hwbp_addr = addr;
    g_hwbp_off = 0;
    g_bp_type_x = 4;                       /* HW_BREAKPOINT_X */
    g_bp_len_x  = 4;
    do_hwbp();
}

static void do_hwbpslot4(void)
{
    unsigned long xyz = 0;
    static const unsigned int ty[4] = { 2, 2, 3, 3 };   /* W, W, RW, RW */
    static const unsigned int ln[4] = { 4, 8, 4, 8 };
    int i;
    if (!nat_xyz_addr(g_hwbp_slot, &xyz)) {
        pr_warn("[hero-reader] hwbpslot4: 取不到 slot=%d\n", g_hwbp_slot);
        return;
    }
    pr_info("[hero-reader] hwbpslot4: slot=%d xyz=0x%lx tid=%d\n", g_hwbp_slot, xyz, g_hwbp_tid);
    for (i = 0; i < 4; i++) {
        g_hwbp_addr = xyz; g_hwbp_off = 0;
        g_bp_type_x = ty[i]; g_bp_len_x = ln[i];
        pr_info("[hero-reader] hwbpslot4: 试 type=%u len=%u\n", ty[i], ln[i]);
        do_hwbp();
    }
}


/* ==================== 全指针链自检 ====================
 * 从 .bss 基址出发, 每一跳都是 "基址+偏移" 或 "指针解引用", 不扫描堆.
 * 双路径校验: link+0x2C 与 *(transform+0x60) 必须指向同一地址.
 */

/* ==================== nativescan: 原生字段批量映射 ====================
 * nativescan <v1> <v2> ... <v8>   (十进制, C# 已知值)
 * 对每个 actor: 读本体 0..0xC00, 遍历其中带 0xb4 标签的指针字段,
 * 读目标 0..0x400, 在全 4 字节字上匹配 int(含多种缩放) 与 float。
 */
static int           g_ns_n = 0;
static int           g_ns_v[8];
static volatile int  g_req_nativescan_valid = 0;

static int ns_match(unsigned int w, int v)
{
    static const int scales[] = { 1, 2, 4, 8, 10, 16, 32, 64, 100, 128, 256, 512, 1000, 1024, 2048, 4096, 8192, 16384, 0 };
    int iw, k;
    float fw;
    __builtin_memcpy(&iw, &w, 4);
    __builtin_memcpy(&fw, &w, 4);
    for (k = 0; scales[k]; k++) {
        long long t = (long long)v * scales[k];
        if (t > 2147483647LL || t < -2147483647LL) continue;
        if (iw == (int)t) return scales[k];
        if (iw == -(int)t) return -scales[k];
    }
    if (v > 3 && fw > (float)v - 0.51f && fw < (float)v + 0.51f) return -1;
    return 0;
}

static void ns_scan(unsigned long t, unsigned long from_off, unsigned int hero,
                    unsigned int camp, int depth)
{
    unsigned char *b;
    unsigned long n, off;

    if (depth > 3) return;
    b = g_iobuf + (depth == 1 ? 0x1000UL : (depth == 2 ? 0x3000UL : 0x5000UL));
    if (!rm(b, t, 0x400)) return;

    for (n = 0; n < 0x400; n += 4) {
        unsigned int w;
        int k;
        __builtin_memcpy(&w, b + n, 4);
        for (k = 0; k < g_ns_n; k++) {
            int sc = ns_match(w, g_ns_v[k]);
            if (sc)
                pr_info("[hero-reader] ns d%d hero=%u camp=%u via+0x%lx obj=0x%lx field+0x%x probe#%d=%d %s\n",
                        depth, hero, camp, from_off, t, n, k, g_ns_v[k],
                        sc < 0 ? "float" : "int");
        }
    }
    if (depth < 2) {
        for (off = 0; off + 8 <= 0x400; off += 8) {
            unsigned long v, u;
            __builtin_memcpy(&v, b + off, 8);
            if ((v >> 56) != 0xb4UL) continue;
            u = v & PTR_MASK;
            if (!nat_plausible(u) || u == t) continue;
            ns_scan(u, off, hero, camp, depth + 1);
        }
    }
}


/* ==================== nscorr: 跨英雄一致性定位 ====================
 * nscorr <v1> ... <v10>  按 fullchain slot 顺序传入 10 个英雄的同一字段值
 * 只有 (组件偏移, 字段偏移, 缩放) 在 10 个 actor 上同时成立才算命中。
 */
static int           g_corr_n = 0;
static int           g_corr_v[10];

static void do_nscorr(void)
{
    unsigned long r = nat_roster(), i, off, fo;
    unsigned long act[10];
    unsigned char *bodies = g_iobuf;             /* 10 x 0xC00 */
    unsigned char *comps  = g_iobuf + 0x8000;    /* 10 x 0x400 */
    int na = 0, k;

    if (!r || g_corr_n != 10) { pr_warn("[hero-reader] nscorr: 需要 10 个值\n"); return; }
    for (i = 0; i < NAT_MAX && na < 10; i++) {
        unsigned long a = untag(rptr(r + i * GC_ROSTER_STRIDE));
        unsigned int h = 0, c = 0;
        if (!nat_plausible(a)) break;
        if (!rm(&h, a + NA_ID, 4) || h == 0 || h > 4000) continue;
        if (!rm(&c, a + NA_CAMP, 4) || (c != 1 && c != 2)) continue;
        act[na++] = a;
    }
    if (na != 10) { pr_warn("[hero-reader] nscorr: 只找到 %d 个 actor\n", na); return; }
    for (k = 0; k < 10; k++)
        if (!rm(bodies + (unsigned long)k * 0xC00UL, act[k], 0xC00)) { pr_warn("nscorr: body 读失败\n"); return; }
    pr_info("[hero-reader] nscorr: 开始\n");

    for (off = 0; off + 8 <= 0xC00; off += 8) {
        int ok = 1;
        for (k = 0; k < 10; k++) {
            unsigned long v, t;
            __builtin_memcpy(&v, bodies + (unsigned long)k * 0xC00UL + off, 8);
            if ((v >> 56) != 0xb4UL) { ok = 0; break; }
            t = v & PTR_MASK;
            if (!nat_plausible(t)) { ok = 0; break; }
            if (!rm(comps + (unsigned long)k * 0x400UL, t, 0x400)) { ok = 0; break; }
        }
        if (!ok) continue;
        for (fo = 0; fo + 4 <= 0x400; fo += 4) {
            int sc = 0, all = 1;
            for (k = 0; k < 10; k++) {
                unsigned int w;
                __builtin_memcpy(&w, comps + (unsigned long)k * 0x400UL + fo, 4);
                if (k == 0) {
                    sc = ns_match(w, g_corr_v[0]);
                    if (!sc || sc < 0) { all = 0; break; }
                } else if (ns_match(w, g_corr_v[k]) != sc) { all = 0; break; }
            }
            if (all)
                pr_info("[hero-reader] nscorr: 命中 comp+0x%lx field+0x%x scale=%d (10/10)\n",
                        off, fo, sc);
        }
    }
    pr_info("[hero-reader] nscorr: 结束\n");
}

static void do_nativescan(void)
{
    unsigned long r = nat_roster(), i, off;
    if (!r) { pr_warn("[hero-reader] nativescan: roster 未就绪\n"); return; }
    if (!g_ns_n) { pr_warn("[hero-reader] nativescan: 无探针值\n"); return; }
    pr_info("[hero-reader] nativescan: 探针 %d 个, 深度 2\n", g_ns_n);
    for (i = 0; i < NAT_MAX; i++) {
        unsigned long a = untag(rptr(r + i * GC_ROSTER_STRIDE));
        unsigned int hero = 0, camp = 0;
        if (!nat_plausible(a)) break;
        if (!rm(&hero, a + NA_ID, 4) || hero == 0 || hero > 4000) continue;
        if (!rm(&camp, a + NA_CAMP, 4) || (camp != 1 && camp != 2)) continue;
        pr_info("[hero-reader] nativescan: === actor=0x%lx hero=%u camp=%u ===\n", a, hero, camp);
        if (!rm(g_iobuf, a, 0xC00)) continue;
        /* 本体直接命中 */
        for (off = 0; off + 4 <= 0xC00; off += 4) {
            unsigned int w;
            int k;
            __builtin_memcpy(&w, g_iobuf + off, 4);
            for (k = 0; k < g_ns_n; k++) {
                int sc = ns_match(w, g_ns_v[k]);
                if (sc)
                    pr_info("[hero-reader] ns d0 hero=%u camp=%u actor+0x%lx probe#%d=%d %s\n",
                            hero, camp, off, k, g_ns_v[k], sc < 0 ? "float" : "int");
            }
        }
        for (off = 0; off + 8 <= 0xC00; off += 8) {
            unsigned long v, u;
            __builtin_memcpy(&v, g_iobuf + off, 8);
            if ((v >> 56) != 0xb4UL) continue;
            u = v & PTR_MASK;
            if (!nat_plausible(u) || u == a) continue;
            ns_scan(u, off, hero, camp, 1);
        }
    }
    pr_info("[hero-reader] nativescan: 结束\n");
}


/* natfind <hero> <x_cm> <z_cm>: 用 C# 坐标作参照, 在同一次读里扫描 native actor
 * (本体 + 一级指针), 找出坐标真实所在偏移。仅诊断用。 */
static void do_natfind(unsigned int hero, int px, int pz)
{
    unsigned long r = nat_roster(), i, off, k2, k3;
    int tx = px * 10, tz = pz * 10, tol = 800;          /* 整数: ×1000 */
    float fx = px / 100.0f, fz = pz / 100.0f;            /* 浮点: 米 */
    char *buf2 = g_iobuf + 0x40000;
    char *buf3 = g_iobuf + 0x80000;
    if (!r) { pr_warn("[hero-reader] natfind: roster 未就绪\n"); return; }
    pr_info("[hero-reader] natfind: hero=%u target int=(%d,%d) float=(%d,%d)cm\n",
            hero, tx, tz, px, pz);
#define NF_CHK(base, off, tag) do { \
        int _vx = 0, _vy = 0, _vz = 0; float _fx, _fz; \
        __builtin_memcpy(&_vx, (base) + (off), 4); \
        __builtin_memcpy(&_vy, (base) + (off) + 4, 4); \
        __builtin_memcpy(&_vz, (base) + (off) + 8, 4); \
        __builtin_memcpy(&_fx, (base) + (off), 4); \
        __builtin_memcpy(&_fz, (base) + (off) + 8, 4); \
        if (_vy == 0 && _vx > tx - tol && _vx < tx + tol && _vz > tz - tol && _vz < tz + tol) \
            pr_info("[hero-reader] natfind: %s int (%d,0,%d)\n", tag, _vx, _vz); \
        else if (_fx > fx - 1.0f && _fx < fx + 1.0f && _fz > fz - 1.0f && _fz < fz + 1.0f) \
            pr_info("[hero-reader] natfind: %s float (%.2f,%.2f)\n", tag, (double)_fx, (double)_fz); \
    } while (0)
    for (i = 0; i < NAT_MAX; i++) {
        unsigned long a = untag(rptr(r + i * GC_ROSTER_STRIDE));
        unsigned int h = 0, c = 0;
        if (!nat_plausible(a)) continue;
        if (!rm(&h, a + NA_ID, 4) || h != hero) continue;
        rm(&c, a + NA_CAMP, 4);
        pr_info("[hero-reader] natfind: actor=0x%lx camp=%u slot=%lu\n", a, c, i);
        if (!rm(g_iobuf, a, 0x1000)) continue;
        for (off = 0; off + 12 <= 0x1000; off += 4) NF_CHK(g_iobuf, off, "d0b");
        for (off = 0; off + 8 <= 0x1000; off += 8) {
            unsigned long v, u;
            __builtin_memcpy(&v, g_iobuf + off, 8);
            u = v & PTR_MASK;
            if (!nat_plausible(u) || u == a) continue;
            if ((v >> 56) != 0 && (v >> 56) != 0xb4UL) continue;
            if (!rm(buf2, u, 0x800)) continue;
            for (k2 = 0; k2 + 12 <= 0x800; k2 += 4) NF_CHK(buf2, k2, "d1");
            for (k2 = 0; k2 + 8 <= 0x800; k2 += 8) {
                unsigned long v2, u2;
                __builtin_memcpy(&v2, buf2 + k2, 8);
                u2 = v2 & PTR_MASK;
                if (!nat_plausible(u2) || u2 == u || u2 == a) continue;
                if ((v2 >> 56) != 0 && (v2 >> 56) != 0xb4UL) continue;
                if (!rm(buf3, u2, 0x400)) continue;
                for (k3 = 0; k3 + 12 <= 0x400; k3 += 4) {
                    int vx = 0, vy = 0, vz = 0;
                    __builtin_memcpy(&vx, buf3 + k3, 4);
                    __builtin_memcpy(&vy, buf3 + k3 + 4, 4);
                    __builtin_memcpy(&vz, buf3 + k3 + 8, 4);
                    if (vy == 0 && vx > tx - tol && vx < tx + tol && vz > tz - tol && vz < tz + tol)
                        pr_info("[hero-reader] natfind: d2 a+0x%lx -> 0x%lx +0x%lx -> 0x%lx +0x%lx = (%d,0,%d)\n",
                                off, u, k2, u2, k3, vx, vz);
                }
            }
        }
    }
#undef NF_CHK
    pr_info("[hero-reader] natfind: 结束\n");
}


/* ============================================================ natchain
 * 用"同一时刻 10 个英雄的 C# 坐标"做交叉约束, 暴力枚举 offset 链:
 *   d0: actor + o
 *   d1: *(actor + o1) + o2
 * 只保留对 >=6 个英雄同时成立的 (o1,o2)。用来找稳定的坐标链。 */
struct nc_t { unsigned int hero, camp; int tx, tz; unsigned long a; };
static struct nc_t g_nc_h[16];
static int          g_nc_nh = 0;
static unsigned int g_nc_c1[2048], g_nc_c2[2048];
static int          g_nc_nc = 0;

static int nc_match3(char *b, unsigned long lim, unsigned long off, int tx, int tz, int tol)
{
    int vx = 0, vy = 0, vz = 0;
    float fx, fy, fz;
    if (off + 12 > lim) return 0;
    __builtin_memcpy(&vx, b + off, 4);
    __builtin_memcpy(&vy, b + off + 4, 4);
    __builtin_memcpy(&vz, b + off + 8, 4);
    if (vx > tx - tol && vx < tx + tol && vz > tz - tol && vz < tz + tol) return 1;   /* 不再要求 y==0 */
    /* 也匹配 float 版本 (米), 容差 4m */
    __builtin_memcpy(&fx, b + off, 4);
    __builtin_memcpy(&fy, b + off + 4, 4);
    __builtin_memcpy(&fz, b + off + 8, 4);
    {
        float mx = tx / 1000.0f, mz = tz / 1000.0f;
        if (fx > mx - 4.0f && fx < mx + 4.0f && fz > mz - 4.0f && fz < mz + 4.0f) return 1;
    }
    return 0;
}

/* 给第 hi 个英雄枚举 d1 候选, 结果写到 out (o1<<16|o2) */
static int nc_enum_d1(int hi, unsigned int *out, int max)
{
    unsigned long a = g_nc_h[hi].a;
    int tx = g_nc_h[hi].tx, tz = g_nc_h[hi].tz, tol = 400;
    char *body = g_iobuf;
    char *buf  = g_iobuf + 0x40000;
    unsigned long o1, o2;
    int n = 0;
    if (!rm(body, a, 0x1000)) return 0;
    for (o1 = 0; o1 + 8 <= 0x1000; o1 += 8) {
        unsigned long v, u;
        __builtin_memcpy(&v, body + o1, 8);
        u = v & PTR_MASK;
        if (!nat_plausible(u) || u == a) continue;
        if ((v >> 56) != 0 && (v >> 56) != 0xb4UL) continue;
        if (!rm(buf, u, 0x800)) continue;
        for (o2 = 0; o2 + 12 <= 0x800; o2 += 4) {
            if (!nc_match3(buf, 0x800, o2, tx, tz, tol)) continue;
            if (n < max) out[n] = ((unsigned int)(o1 & 0xFFFF) << 16) | (unsigned int)(o2 & 0xFFFF);
            n++;
        }
    }
    return n;
}

static void do_natchain(void)
{
    unsigned long r = nat_roster();
    int i, k, nh = 0, nc, ci, hi;
    static unsigned int cand[2048];
    char *body = g_iobuf;
    int d0_hit[0x1000 / 4];
    int d0_n = 0;

    memset(d0_hit, 0, sizeof(d0_hit));
    if (!r) { pr_warn("[hero-reader] natchain: roster 未就绪\n"); return; }
    /* 1. 目标集合: 用 do_heroes 刚写的 g_bin_rec (C# x/z, ×100) */
    for (k = 0; k < (int)g_bin_n && k < 16; k++) {
        unsigned int hero = g_bin_rec[k].heroid, camp = g_bin_rec[k].camp;
        int tx, tz;
        unsigned long a = 0;
        if (!hero || !g_bin_rec[k].x || !g_bin_rec[k].z) continue;
        tx = g_bin_rec[k].x * 10; tz = g_bin_rec[k].z * 10;
        for (i = 0; i < NAT_MAX; i++) {
            unsigned long aa = untag(rptr(r + (unsigned long)i * GC_ROSTER_STRIDE));
            unsigned int hh = 0, cc = 0;
            if (!nat_plausible(aa)) continue;
            if (!rm(&hh, aa + NA_ID, 4) || !rm(&cc, aa + NA_CAMP, 4)) continue;
            if (hh == hero && cc == camp) { a = aa; break; }
        }
        if (!a) continue;
        g_nc_h[nh].hero = hero; g_nc_h[nh].camp = camp;
        g_nc_h[nh].tx = tx; g_nc_h[nh].tz = tz; g_nc_h[nh].a = a;
        nh++;
    }
    g_nc_nh = nh;
    pr_info("[hero-reader] natchain: 目标=%d\n", nh);
    if (nh < 6) { pr_warn("[hero-reader] natchain: 目标不足\n"); return; }

    /* 2. 深度 0: actor+off 直接命中 (所有英雄同一 off) */
    for (i = 0; i < nh; i++) {
        if (!rm(body, g_nc_h[i].a, 0x1000)) return;
        for (k = 0; k + 12 <= 0x1000; k += 4)
            if (nc_match3(body, 0x1000, (unsigned long)k, g_nc_h[i].tx, g_nc_h[i].tz, 400))
                d0_hit[k / 4]++;
    }
    for (k = 0; k + 12 <= 0x1000; k += 4)
        if (d0_hit[k / 4] >= nh) { pr_info("[hero-reader] natchain: d0 actor+0x%x 命中 %d/%d\n", k, d0_hit[k/4], nh); d0_n++; }
    if (!d0_n) pr_info("[hero-reader] natchain: d0 无稳定偏移\n");

    /* 3. 深度 1: 用第 0 个英雄枚举, 再让其余英雄过滤 */
    nc = nc_enum_d1(0, cand, 2048);
    pr_info("[hero-reader] natchain: d1 初始候选=%d\n", nc);
    if (nc > 2048) nc = 2048;
    for (hi = 1; hi < nh && nc > 0; hi++) {
        int keep = 0;
        for (ci = 0; ci < nc; ci++) {
            unsigned long o1 = (cand[ci] >> 16) & 0xFFFF;
            unsigned long o2 = cand[ci] & 0xFFFF;
            unsigned long v, u;
            char *buf = g_iobuf + 0x40000;
            int ok = 0;
            if (!rm(body, g_nc_h[hi].a, 0x1000)) continue;
            __builtin_memcpy(&v, body + o1, 8);
            u = v & PTR_MASK;
            if (nat_plausible(u) && u != g_nc_h[hi].a && rm(buf, u, 0x800))
                ok = nc_match3(buf, 0x800, o2, g_nc_h[hi].tx, g_nc_h[hi].tz, 400);
            if (ok) cand[keep++] = cand[ci];
        }
        nc = keep;
        pr_info("[hero-reader] natchain: 过滤到英雄 %d 后候选=%d\n", hi, nc);
    }
    for (ci = 0; ci < nc && ci < 20; ci++)
        pr_info("[hero-reader] natchain: d1 actor+0x%lx -> +0x%lx  (稳定)\n",
                (cand[ci] >> 16) & 0xFFFF, cand[ci] & 0xFFFF);

    /* 4. 深度 2: 只对英雄0枚举, 其余英雄验证 */
    if (nc == 0) {
        char *b1 = g_iobuf + 0x40000;
        char *b2 = g_iobuf + 0x80000;
        unsigned long o1, o2, o3;
        int hits = 0;
        if (rm(body, g_nc_h[0].a, 0x1000)) {
            for (o1 = 0; o1 + 8 <= 0x400; o1 += 8) {
                unsigned long v1, p1;
                __builtin_memcpy(&v1, body + o1, 8);
                p1 = v1 & PTR_MASK;
                if (!nat_plausible(p1) || p1 == g_nc_h[0].a) continue;
                if ((v1 >> 56) != 0 && (v1 >> 56) != 0xb4UL) continue;
                if (!rm(b1, p1, 0x800)) continue;
                for (o2 = 0; o2 + 8 <= 0x400; o2 += 8) {
                    unsigned long v2, p2;
                    __builtin_memcpy(&v2, b1 + o2, 8);
                    p2 = v2 & PTR_MASK;
                    if (!nat_plausible(p2) || p2 == p1 || p2 == g_nc_h[0].a) continue;
                    if ((v2 >> 56) != 0 && (v2 >> 56) != 0xb4UL) continue;
                    if (!rm(b2, p2, 0x400)) continue;
                    for (o3 = 0; o3 + 12 <= 0x400; o3 += 4) {
                        int hi2, good = 1;
                        if (!nc_match3(b2, 0x400, o3, g_nc_h[0].tx, g_nc_h[0].tz, 400)) continue;
                        for (hi2 = 1; hi2 < nh && good; hi2++) {
                            unsigned long w1, q1, w2, q2, t1 = 0, t2 = 0, t3 = 0;
                            char *c1 = g_iobuf + 0x40000, *c2 = g_iobuf + 0x80000;
                            if (!rm(body, g_nc_h[hi2].a, 0x1000)) { good = 0; break; }
                            __builtin_memcpy(&w1, body + o1, 8); q1 = w1 & PTR_MASK;
                            if (!nat_plausible(q1) || !rm(c1, q1, 0x800)) { good = 0; break; }
                            __builtin_memcpy(&w2, c1 + o2, 8); q2 = w2 & PTR_MASK;
                            if (!nat_plausible(q2) || !rm(c2, q2, 0x400)) { good = 0; break; }
                            good = nc_match3(c2, 0x400, o3, g_nc_h[hi2].tx, g_nc_h[hi2].tz, 400);
                        }
                        if (good) {
                            pr_info("[hero-reader] natchain: d2 actor+0x%lx -> +0x%lx -> +0x%lx (稳定 %d/%d)\n",
                                    o1, o2, o3, nh, nh);
                            if (++hits > 10) goto d2done;
                        }
                    }
                }
            }
        }
d2done:
        pr_info("[hero-reader] natchain: d2 稳定链=%d\n", hits);
    }
    pr_info("[hero-reader] natchain: 结束 稳定链=%d\n", nc);
}


/* 打印三条已确认稳定的候选坐标链 (用于判断哪条是雾中真值) */
static void do_nat3(void)
{
    unsigned long r = nat_roster();
    int i, k;
    static const unsigned long A[3] = {0x110, 0x128, 0x170};
    static const unsigned long B[3] = {0x420, 0x560, 0x3c8};
    if (!r) { pr_warn("[hero-reader] nat3: roster 未就绪\n"); return; }
    pr_info("[hero-reader] nat3: 开始\n");
    for (i = 0; i < NAT_MAX; i++) {
        unsigned long a = untag(rptr(r + (unsigned long)i * GC_ROSTER_STRIDE));
        unsigned int hero = 0, camp = 0;
        int cx = 0, cz = 0;
        int v[3][2];
        int lv = -1;
        if (!nat_plausible(a)) continue;
        if (!rm(&hero, a + NA_ID, 4) || hero == 0 || hero > 4000) continue;
        if (!rm(&camp, a + NA_CAMP, 4) || (camp != 1 && camp != 2)) continue;
        for (k = 0; k < (int)g_bin_n && k < 16; k++) {
            if (g_bin_rec[k].heroid == hero && g_bin_rec[k].camp == camp) {
                cx = g_bin_rec[k].x; cz = g_bin_rec[k].z; lv = g_bin_rec[k].lvis; break;
            }
        }
        for (k = 0; k < 3; k++) {
            unsigned long p1 = untag(rptr(a + A[k])), p2 = 0;
            v[k][0] = 0; v[k][1] = 0;
            if (!nat_plausible(p1)) continue;
            p2 = untag(rptr(p1 + B[k]));
            if (!nat_plausible(p2)) continue;
            rm(&v[k][0], p2 + LINK_XYZ, 4);
            rm(&v[k][1], p2 + LINK_XYZ + 8, 4);
        }
        pr_info("[hero-reader] nat3 hero=%u camp=%u lvis=%d C#=(%d,%d) | A=(%d,%d) B=(%d,%d) C=(%d,%d)\n",
                hero, camp, lv, cx, cz, v[0][0], v[0][1], v[1][0], v[1][1], v[2][0], v[2][1]);
    }
    pr_info("[hero-reader] nat3: 结束\n");
}


/* natx2: 对比 link+0x2C 与 *(transform+0x60) 的值 (后者可能是世界坐标) */
static void do_natx2(void)
{
    unsigned long r = nat_roster(), i;
    if (!r) { pr_warn("[hero-reader] natx2: roster 未就绪\n"); return; }
    pr_info("[hero-reader] natx2: 开始\n");
    for (i = 0; i < NAT_MAX; i++) {
        unsigned long a = untag(rptr(r + (unsigned long)i * GC_ROSTER_STRIDE));
        unsigned long node, link, tr, p2;
        unsigned int hero = 0, camp = 0;
        int x1 = 0, z1 = 0, x2 = 0, y2 = 0, z2 = 0;
        int cx = 0, cz = 0, lv = -1, k;
        float fx2 = 0, fy2 = 0, fz2 = 0;
        if (!nat_plausible(a)) continue;
        if (!rm(&hero, a + NA_ID, 4) || hero == 0 || hero > 4000) continue;
        if (!rm(&camp, a + NA_CAMP, 4) || (camp != 1 && camp != 2)) continue;
        for (k = 0; k < (int)g_bin_n && k < 16; k++)
            if (g_bin_rec[k].heroid == hero && g_bin_rec[k].camp == camp) {
                cx = g_bin_rec[k].x; cz = g_bin_rec[k].z; lv = g_bin_rec[k].lvis; break;
            }
        node = untag(rptr(a + NA_NODE));
        link = nat_plausible(node) ? untag(rptr(node + NODE_LINK)) : 0;
        if (!nat_plausible(link)) continue;
        rm(&x1, link + LINK_XYZ, 4); rm(&z1, link + LINK_XYZ + 8, 4);
        tr = untag(rptr(link));
        p2 = nat_plausible(tr) ? untag(rptr(tr + 0x60)) : 0;
        if (nat_plausible(p2)) {
            rm(&x2, p2, 4); rm(&y2, p2 + 4, 4); rm(&z2, p2 + 8, 4);
            __builtin_memcpy(&fx2, &x2, 4);
            __builtin_memcpy(&fy2, &y2, 4);
            __builtin_memcpy(&fz2, &z2, 4);
        }
        pr_info("[hero-reader] natx2 hero=%u camp=%u lvis=%d C#=(%d,%d) | link=(%d,%d) | p2addr=0x%lx p2=(%d,%d,%d)\n",
                hero, camp, lv, cx, cz, x1, z1, p2, x2, y2, z2);
    }
    pr_info("[hero-reader] natx2: 结束\n");
}

/* cscan <value>: 在 10 个 C# ActorLinker 对象里找该值 (int/float/缩放) */
static int          g_cs_val = 0;

static void cs_scan(unsigned long t, unsigned long from_off, unsigned int objid, int depth)
{
    unsigned char *b;
    unsigned long n, off;
    if (depth > 2) return;
    b = g_iobuf + (depth == 1 ? 0x1000UL : 0x3000UL);
    if (!rm(b, t, 0x400)) return;
    for (n = 0; n < 0x400; n += 4) {
        unsigned int w;
        int k;
        __builtin_memcpy(&w, b + n, 4);
        k = ns_match(w, g_cs_val);
        if (!k && n + 8 <= 0x400) {          /* double */
            double dv;
            __builtin_memcpy(&dv, b + n, 8);
            if (dv > (double)g_cs_val - 0.001 && dv < (double)g_cs_val + 0.001) k = 99000;
        }
        if (k)
            pr_info("[hero-reader] ccscan: d%d objid=%u via+0x%lx obj=0x%lx +0x%x = %d %s\n",
                    depth, objid, from_off, t, n, g_cs_val, k < 0 ? "float" : "int");
    }
    if (depth < 3) {
        for (off = 0; off + 8 <= 0x400; off += 8) {
            unsigned long v, u;
            __builtin_memcpy(&v, b + off, 8);
            if ((v >> 56) == 0xb4UL) u = v & PTR_MASK;
            else if (v >= 0x7000000000UL && v < 0x8000000000UL) u = v;
            else continue;
            if (!nat_plausible(u) || u == t) continue;
            cs_scan(u, off, objid, depth + 1);
        }
    }
}


/* cad: 打印每个 C# actor 的 (actor+0x170)+0x3E0..0x400 浮点区 (定位最终攻击力) */
static volatile int g_req_cad_valid = 0;

/* cams: 打印每个 C# actor 的 0x505..0x509 五个布尔 (可见/在相机/渲染/真实检查) */
static void do_cams(void)
{
    unsigned long inst = g_am_inst, cont, arr;
    unsigned int cnt = 0, i;
    if (!inst) { pr_warn("[hero-reader] cams: ActorManager 未就绪\n"); return; }
    cont = rptr(inst + OFF_AM_HEROACTORS);
    arr  = rptr(cont + OFF_TVL_ITEMS);
    rm(&cnt, cont + OFF_TVL_COUNT, 4);
    for (i = 0; i < cnt && i < 32; i++) {
        unsigned long a = rptr(arr + ARR_ELEMS + (unsigned long)i * ELEM_STRIDE);
        unsigned int objid = 0, hero = 0;
        int x = 0, z = 0;
        if (!a) continue;
        rm(&objid, a + AL_OBJID, 4);
        rm(&hero, a + AL_RESCFG, 4);
        x = rf32x100(a + AL_POS); z = rf32x100(a + AL_POS + 8);
        pr_info("[hero-reader] cams: objid=%u hero=%u x=%d z=%d 505=%d 507=%d 508=%d 509=%d\n",
                objid, hero, x, z,
                rb(a + 0x505UL), rb(a + 0x507UL), rb(a + 0x508UL), rb(a + 0x509UL));
    }
}
static void do_cad(void)
{
    unsigned long inst = g_am_inst, cont, arr;
    unsigned int cnt = 0, i;
    if (!inst) { pr_warn("[hero-reader] cad: ActorManager 未就绪\n"); return; }
    cont = rptr(inst + OFF_AM_HEROACTORS);
    arr  = rptr(cont + OFF_TVL_ITEMS);
    rm(&cnt, cont + OFF_TVL_COUNT, 4);
    for (i = 0; i < cnt && i < 32; i++) {
        unsigned long a = rptr(arr + ARR_ELEMS + (unsigned long)i * ELEM_STRIDE);
        unsigned long p2;
        unsigned int objid = 0, hero = 0;
        int off;
        if (!a) continue;
        rm(&objid, a + AL_OBJID, 4);
        rm(&hero,  a + AL_RESCFG, 4);
        p2 = untag(rptr(a + 0x170UL));
        if (!nat_plausible(p2)) continue;
        if (!rm(g_iobuf, p2 + 0x3E0UL, 0x20)) continue;
        pr_info("[hero-reader] cad: objid=%u hero=%u obj=0x%lx :", objid, hero, p2);
        for (off = 0; off < 0x20; off += 4) {
            float f;
            __builtin_memcpy(&f, g_iobuf + off, 4);
            pr_info(" 0x%x=%.1f", 0x3E0 + off, f);
        }
        pr_info("\n");
    }
}

/* ==================== pairscan: 成对值定位 ====================
 * pairscan <v1> <v2>  全内存找 v1, 并在其 ±0x80 内找 v2 (int/多种缩放/float/double)
 */
static int           g_pair_a = 0, g_pair_b = 0;
static int           g_pair_hits = 0;

static int pair_near(unsigned long base, int n, int p)
{
    int q;
    int lo = (p - 0x80 < 0) ? 0 : p - 0x80;
    int hi = (p + 0x80 > n - 4) ? n - 4 : p + 0x80;
    for (q = lo; q <= hi; q += 4) {
        unsigned int w;
        __builtin_memcpy(&w, g_iobuf + q, 4);
        if (ns_match(w, g_pair_b)) return q - p;
    }
    return 0x7fffffff;
}

static int pair_cb(void *ud, unsigned long start, unsigned long end, unsigned long flags)
{
    unsigned long off = 0, total = end - start;
    (void)ud;
    if (!(flags & VM_READ) || (flags & VM_WRITE) || (flags & VM_EXEC)) return 0;
    if (start < (g_scan_wide ? 0x10000UL : 0x100000000UL)) return 0;
    if (total > (g_scan_wide ? (8UL << 30) : (2UL << 30))) total = g_scan_wide ? (8UL << 30) : (2UL << 30);
    while (off < total && g_pair_hits < 40) {
        unsigned long want = total - off;
        int n, p;
        if (p_kthread_should_stop && p_kthread_should_stop()) return 1;
        if (want > IO_CHUNK) want = IO_CHUNK;
        if (!rm(g_iobuf, start + off, (int)want)) break;
        n = (int)want;
        for (p = 0; p + 4 <= n; p += 4) {
            unsigned int w;
            int d;
            __builtin_memcpy(&w, g_iobuf + p, 4);
            if (!ns_match(w, g_pair_a)) continue;
            d = pair_near(start + off, n, p);
            if (d == 0x7fffffff) continue;
            pr_info("[hero-reader] pairscan: v1@0x%lx v2@0x%lx (delta %+d)\n",
                    start + off + (unsigned long)p, start + off + (unsigned long)p + (long)d, d);
            if (++g_pair_hits >= 40) return 1;
        }
        off += (want > 0x100UL ? want - 0x100UL : want);
    }
    return 0;
}

static void do_pairscan(void)
{
    if (!g_target_mm) { pr_warn("[hero-reader] pairscan: mm 未锁定\n"); return; }
    g_pair_hits = 0;
    pr_info("[hero-reader] pairscan: v1=%d v2=%d 开始\n", g_pair_a, g_pair_b);
    vma_walk(pair_cb, NULL);
    pr_info("[hero-reader] pairscan: 结束, 命中 %d\n", g_pair_hits);
}

static void do_cscan(void)
{
    unsigned long inst = g_am_inst, cont, arr;
    unsigned int cnt = 0, i;
    if (!inst) { pr_warn("[hero-reader] cscan: ActorManager 未就绪\n"); return; }
    cont = rptr(inst + OFF_AM_HEROACTORS);
    arr  = rptr(cont + OFF_TVL_ITEMS);
    rm(&cnt, cont + OFF_TVL_COUNT, 4);
    pr_info("[hero-reader] cscan: 值=%d actors=%u\n", g_cs_val, cnt);
    for (i = 0; i < cnt && i < 32; i++) {
        unsigned long a = rptr(arr + ARR_ELEMS + (unsigned long)i * ELEM_STRIDE);
        unsigned int objid = 0;
        int off;
        if (!a) continue;
        rm(&objid, a + AL_OBJID, 4);
        if (!rm(g_iobuf, a, 0x800)) continue;
        for (off = 0; off + 4 <= 0x800; off += 4) {
            unsigned int w;
            int k;
            __builtin_memcpy(&w, g_iobuf + off, 4);
            k = ns_match(w, g_cs_val);
            if (k)
                pr_info("[hero-reader] cscan: objid=%u actor=0x%lx +0x%x val=%d %s\n",
                        objid, a, off, g_cs_val, k < 0 ? "float" : "int");
        }
        {   /* 递归到子组件 */
            unsigned long po;
            for (po = 0; po + 8 <= 0x800; po += 8) {
                unsigned long v, u;
                __builtin_memcpy(&v, g_iobuf + po, 8);
                if ((v >> 56) != 0xb4UL) continue;
                u = v & PTR_MASK;
                if (!nat_plausible(u) || u == a) continue;
                cs_scan(u, po, objid, 1);
            }
        }
    }
    pr_info("[hero-reader] cscan: 结束\n");
}
static void do_fullchain(void)
{
    unsigned long r = nat_roster(), i;
    if (!r) { pr_warn("[hero-reader] fullchain: roster 未就绪 (不在对局?)\n"); return; }
    pr_info("[hero-reader] fullchain: bss=0x%lx base=0x%lx root_slot=0x%lx roster=0x%lx\n",
            g_gc_bss,
            g_gc_bss ? (g_gc_bss - GC_BSS_VA_OFF) : 0,
            g_gc_bss ? (g_gc_bss + GC_BSS_ROSTER_OFF) : 0,
            r);
    for (i = 0; i < NAT_MAX; i++) {
        unsigned long a = untag(rptr(r + i * GC_ROSTER_STRIDE));
        unsigned int hero = 0, camp = 0;
        unsigned long node = 0, link = 0, tr = 0, xyz2 = 0;
        int x = 0, z = 0;
        if (!nat_plausible(a)) break;
        if (!rm(&hero, a + NA_ID, 4) || hero == 0 || hero > 4000) continue;
        if (!rm(&camp, a + NA_CAMP, 4) || (camp != 1 && camp != 2)) continue;
        node = untag(rptr(a + NA_NODE));
        if (nat_plausible(node)) link = untag(rptr(node + NODE_LINK));
        if (!nat_plausible(link)) continue;
        rm(&x, link + LINK_XYZ, 4);
        rm(&z, link + LINK_XYZ + 8, 4);
        tr = untag(rptr(link));
        {
            int wx = 0, wy = 0, wz = 0;
            if (nat_plausible(tr)) xyz2 = untag(rptr(tr + 0x60));
            if (nat_plausible(xyz2)) { rm(&wx, xyz2, 4); rm(&wy, xyz2 + 4, 4); rm(&wz, xyz2 + 8, 4); }
            pr_info("[hero-reader] fullchain[%lu] roster+0x%lx actor=0x%lx hero=%u camp=%u "
                    "node=0x%lx link=0x%lx local=(%d,0,%d) transform=0x%lx world@0x%lx=(%d,%d,%d) %s\n",
                    i, i * GC_ROSTER_STRIDE, a, hero, camp,
                    node, link, x, z, tr, xyz2, wx, wy, wz,
                    (wy == 0 && nat_xyz_ok(wx, wy, wz)) ? "WORLD-OK" : "NO-WORLD");
        }
        {   /* 附: 原生 hp/hpmax */
            unsigned long comp = untag(rptr(a + 0x1D0UL));
            int nhp = 0, nhm = 0;
            if (nat_plausible(comp)) { rm(&nhp, comp + 0xC0UL, 4); rm(&nhm, comp + 0xC8UL, 4); }
            pr_info("[hero-reader] fullchain[%lu] native hp=%d/%d (comp=0x%lx)\n",
                    i, nhp, nhm, comp);
        }
    }
}

static void do_hwbpslot(void)
{
    unsigned long xyz = 0;
    if (!nat_xyz_addr(g_hwbp_slot, &xyz)) {
        pr_warn("[hero-reader] hwbpslot: 取不到 slot=%d 的 xyz (未在对局?)\n", g_hwbp_slot);
        return;
    }
    {
        int vx = 0, vy = 0, vz = 0;
        rm(&vx, xyz, 4); rm(&vy, xyz + 4, 4); rm(&vz, xyz + 8, 4);
        pr_info("[hero-reader] hwbpslot: slot=%d xyz=0x%lx tid=%d 当前值=(%d,%d,%d)\n",
                g_hwbp_slot, xyz, g_hwbp_tid, vx, vy, vz);
    }
    g_hwbp_addr = xyz;
    g_hwbp_off = 0;
    g_bp_type_x = HR_HW_BREAKPOINT_W;     /* 复位: hwbpslot4 会改这两个值 */
    g_bp_len_x  = HR_HW_BREAKPOINT_LEN_4;
    do_hwbp();
}

static void do_hwbp(void)
{
    struct hr_perf_attr attr;
    void *tsk = NULL, *ev = NULL;
    static const unsigned int sizes[3] = { 128, 120, 104 };
    int si;

    if (g_hwbp_off) { g_bp_fired = 0; hr_bp_clear(); pr_info("[hero-reader] hwbp: 已全部卸载\n"); return; }
    if (g_bp_fired) {                    /* 已命中过: 拒绝再注册, 防风暴 */
        pr_warn("[hero-reader] hwbp: 已命中过, 请先 'hwbp off' 再挂\n");
        return;
    }
    hr_bp_clear();                       /* 防累积: 新注册前清掉旧事件 */
    if (!p_register_user_hw_breakpoint) {
        pr_warn("[hero-reader] hwbp: 缺 register_user_hw_breakpoint\n");
        return;
    }
    if (g_bp_nev >= (int)(sizeof(g_bp_events)/sizeof(g_bp_events[0]))) {
        pr_warn("[hero-reader] hwbp: 槽位满 %d\n", g_bp_nev);
        return;
    }

    /* 取 task: 优先 find_get_task_by_vpid(自带引用); 否则 find_get_pid+get_pid_task */
    if (p_find_get_task_by_vpid) tsk = p_find_get_task_by_vpid(g_hwbp_tid);
    if (!tsk && p_find_get_pid && p_get_pid_task) {
        void *pidp = p_find_get_pid(g_hwbp_tid);
        if (pidp) {
            tsk = p_get_pid_task(pidp, 0 /*PIDTYPE_PID*/);
            if (p_put_pid) p_put_pid(pidp);
        }
    }
    pr_info("[hero-reader] hwbp: tid=%d tsk=0x%lx\n", g_hwbp_tid, (unsigned long)tsk);
    if (!tsk) { pr_warn("[hero-reader] hwbp: 找不到 task\n"); return; }

    for (si = 0; si < 3; si++) {
        memset(&attr, 0, sizeof(attr));
        attr.type          = HR_PERF_TYPE_BREAKPOINT;
        attr.size          = sizes[si];
        attr.sample_period = 1;                      /* ptrace_breakpoint_init 的做法 */
        attr.flags         = (1ULL << 5) | (1ULL << 6); /* exclude_kernel|exclude_hv */
        attr.bp_type       = g_bp_type_x;
        attr.bp_addr       = g_hwbp_addr;
        attr.bp_len        = g_bp_len_x;
        ev = p_register_user_hw_breakpoint(&attr, (void *)hr_bp_handler, NULL, tsk);
        if (ev && (unsigned long)ev < (unsigned long)-4095UL) break;
        pr_warn("[hero-reader] hwbp: size=%u 失败 ev=0x%lx\n", sizes[si], (unsigned long)ev);
        ev = NULL;
    }
    if (p_put_task_struct) p_put_task_struct(tsk);

    if (!ev) { pr_warn("[hero-reader] hwbp: 注册失败 (所有 size 都试过)\n"); return; }
    g_bp_events[g_bp_nev++] = ev;
    if (p_perf_event_enable) p_perf_event_enable(ev);   /* 内核计数器创建后必须显式使能 */
    if (g_hwbp_base) g_bp_gcbase = g_hwbp_base;
    pr_info("[hero-reader] hwbp: tid=%d addr=0x%lx 已挂 (%d 个)\n", g_hwbp_tid, g_hwbp_addr, g_bp_nev);
}

static void do_heroes(void)
{
    unsigned long table, total = 0, i, amc = 0;
    unsigned int hostPid = 0;
    unsigned long md = g_meta_addr ? g_meta_addr : md_locate();
    struct hscan hs;
    unsigned long inst, cont, arr;
    unsigned int cnt = 0;

    if (!g_target_mm) { pr_warn("[hero-reader] heroes: mm 未锁定\n"); return; }
    if (!g_base) find_base();
    if (!md) { pr_warn("[hero-reader] heroes: metadata 未就绪\n"); return; }
    g_meta_addr = md;
    table = find_typeinfo_table(&total);
    if (!table) { pr_warn("[hero-reader] heroes: 未找到类表\n"); return; }
    /* ActorManager 类: 缓存, 只解析一次 */
    if (g_am_class && cname_ok(g_am_class)) {
        amc = g_am_class;
    } else {
        for (i = 0; i < 70000; i++) {
            unsigned long c = rptr(table + i * 8);
            char nm[96];
            if (!c) continue;
            if (rstr(rptr(c + CLASS_NAME_O), nm, sizeof(nm)) > 0 && strcmp(nm, "ActorManager") == 0) { amc = c; break; }
        }
        if (amc) g_am_class = amc;
    }
    if (!amc) { pr_warn("[hero-reader] heroes: 未找到 ActorManager\n"); return; }

    /* 零扫描链: instance = table[HOLDER].static_fields[0] */
    {
        /* instance = *( *(table[HOLDER_IDX] + 0xB8) + HOLDER_OFF )  —— 纯静态链, 零扫描 */
        unsigned long cls = rptr(table + 39479UL * 8);
        unsigned long cand = rptr(rptr(cls + CLASS_STATIC_FIELDS) + 0x80UL);
        if (g_verbose) pr_info("[hero-reader] 静态链 cls=0x%lx inst=0x%lx valid=%d\n",
                               cls, cand, am_valid(cand, amc));
        if (am_alive(cand, amc)) { g_am_inst = cand; inst = cand; goto have_inst; }
    }
    /* 缓存 + 每次校验; 无效才扫一次 (开新对局时)
     * 注意: 全堆扫描实测一次 ~650ms, 会造成明显卡顿。
     * 静态链 (table[idx].static_fields) 已能覆盖换局, 所以扫描默认禁用,
     * 只有诊断时 'unsafe on' 才允许。 */
    if (am_alive(g_am_inst, amc)) {
        inst = g_am_inst;
    } else if (!g_allow_scan) {
        if (g_verbose) pr_info("[hero-reader] heroes: 实例未就绪, 等下一轮 (扫描已禁用)\n");
        return;
    } else {
        hs.amc = amc; hs.inst = 0; hs.found = 0;
        g_pf_scans++;
        vma_walk(hscan_cb, &hs);
        if (!hs.found) { if (g_verbose) pr_warn("[hero-reader] heroes: 未找到 ActorManager 实例\n"); return; }
        inst = hs.inst;
        g_am_inst = inst;
        /* 找持有该实例的类 (static_fields[0] == instance) → 得到纯静态链 */
        {
            unsigned long j;
            for (j = 0; j < 70000; j++) {
                unsigned long c = rptr(table + j * 8);
                unsigned long sf;
                unsigned long o;
                if (!c) continue;
                sf = rptr(c + CLASS_STATIC_FIELDS);
                if (!sf) continue;
                for (o = 0; o < 0x100; o += 8) {
                    if (rptr(sf + o) == inst) { g_am_holder_idx = j; g_am_holder_off = o; break; }
                }
                if (g_am_holder_off || g_am_holder_idx) break;
            }
        }
        if (g_verbose)
            pr_info("[hero-reader] holder: idx=%lu off=0x%lx\n",
                    g_am_holder_idx, g_am_holder_off);
    }
have_inst:
    cont = rptr(inst + OFF_AM_HEROACTORS);
    arr  = rptr(cont + OFF_TVL_ITEMS);
    rm(&cnt, cont + OFF_TVL_COUNT, 4);
    if (!arr || !cnt || cnt > 64) {
        if (g_in_match) { g_in_match = 0; pr_info("[hero-reader] 对局结束/未在对局\n"); }
        return;
    }

    /* 本机玩家: GamePlayerCenter.hostPlayerID (= SceneMgr holder +0xE0 的对象 +0x40) */
    {
        unsigned long cls = rptr(table + 39479UL * 8);
        unsigned long holder = rptr(cls + CLASS_STATIC_FIELDS);
        unsigned long gpc = rptr(holder + 0xE0UL);
        if (gpc) rm(&hostPid, gpc + 0x40UL, 4);
        if (g_verbose) pr_info("[hero-reader] holder=0x%lx gpc=0x%lx hostPlayerID=%u\n",
                               holder, gpc, hostPid);
    }
    /* 输出: g_hero_path 非空 -> 写 JSON 文件; 否则 dmesg */
    {
        void *f = NULL, *old_cred = NULL;
        long long pos = 0;
        char line[2048];
        int k2;
        struct nat_rec nrt[NAT_MAX];
        int nrn = 0;
        int selfX = 0, selfZ = 0;

        if (g_hero_path[0] && p_filp_open && p_kernel_write && p_filp_close) {
            if (g_io_cred && p_override_creds) old_cred = p_override_creds(g_io_cred);
            f = p_filp_open(g_hero_path, KPM_O_WRONLY | KPM_O_CREAT | KPM_O_TRUNC, 0644);
            if (!f || (unsigned long)f >= (unsigned long)-4095UL) f = NULL;
        }
        if (f) {
            int n = snprintf(line, sizeof(line), "{\"_doc\":%s,\"seq\":%lu,\"n\":%lu,\"heroes\":[\n", g_hero_doc, g_hero_seq++, cnt);
            p_kernel_write(f, line, (unsigned long)n, &pos);
        } else if (g_verbose) {
            if (!g_in_match) { g_in_match = 1; pr_info("[hero-reader] 对局开始 heroes=%u\n", cnt); }
        }

        { int nn = nat_collect(nrt, NAT_MAX); if (g_verbose) pr_info("[hero-reader] native 表: roster=0x%lx n=%d\n", g_nat_roster, nn); nrn = nn; }
        {   /* 标定用: 先找本机 actor 的位置 */
            int zz;
            for (zz = 0; zz < (int)cnt && zz < 32; zz++) {
                unsigned long aa = rptr(arr + ARR_ELEMS + (unsigned long)zz * ELEM_STRIDE);
                unsigned int pid = 0;
                if (!aa) continue;
                rm(&pid, aa + 0x558UL, 4);
                if (hostPid && pid == hostPid) {
                    selfX = rf32x100(aa + AL_POS);
                    selfZ = rf32x100(aa + AL_POS + 8);
                    break;
                }
            }
        }
        for (k2 = 0; k2 < (int)cnt && k2 < 32; k2++) {
            unsigned long a = rptr(arr + ARR_ELEMS + (unsigned long)k2 * ELEM_STRIDE);
            unsigned long vc, oc;
            int hp = 0, hpmax = 0, camp, exp = 0, expmax = 0, lvl = 0, gold = 0, incgold = 0;
            int charge = 0, chargemax = 0, shield = 0, shieldmax = 0;
            unsigned int objid = 0, herocfg = 0, cfgid = 0, revive = 0, equipcnt = 0, atktarget = 0;
            int dead = 0, dying = 0, grass = 0, freeze = 0, battle = 0;
            int nomove = 0, inroom = 0, fantasy = 0, autoai = 0, move = 0, groundy = 0;
            int ad = 0, ap = 0, df = 0, rs = 0;
            int asp = 0, hpr = 0, epr = 0, epv = 0, atki = 0, crit = 0, critd = 0;
            int lvis = 0, incam = 0;
            const char *hn;
            char skills[1024];
            char eqbuf[360];
            int sp = 0, s, eqn = 0, epos = 0;

            if (!a) continue;
            if (g_verbose && k2 == 0) {   /* 诊断: 列出该 actor 的组件类名 */
                int o;
                for (o = 0x20; o < 0x470; o += 8) {
                    unsigned long cv = rptr(a + (unsigned long)o);
                    unsigned long cp, np;
                    char cn[48];
                    if (!cv) continue;
                    cp = rptr(cv);
                    if (!cp) continue;
                    np = rptr(cp + CLASS_NAME_O);
                    if (rstr(np, cn, sizeof(cn)) <= 0) continue;
                    pr_info("[hero-reader]   comp +0x%03x %s obj=0x%lx\n", o, cn, cv);
                }
            }
            vc = rptr(a + AL_VALUECOMP);
            if (vc) {
                rm(&hp, vc + VC_HP, 4); rm(&hpmax, vc + VC_HPMAX, 4);
                rm(&exp, vc + VC_EXP, 4); rm(&expmax, vc + VC_EXPMAX, 4);
                rm(&gold, vc + VC_GOLD, 4); rm(&incgold, vc + VC_INCGOLD, 4);
                rm(&shield, vc + VC_SHIELD, 4); rm(&shieldmax, vc + VC_SHIELDMAX, 4);
                rm(&charge, vc + VC_CHARGE, 4); rm(&chargemax, vc + VC_CHARGEMAX, 4); rm(&lvl, vc + VC_LEVEL, 4);
            }
            oc = rptr(a + AL_ACTORCTRL);
            if (oc) {
                rm(&cfgid, oc + OC_CONFIGID, 4);
                rm(&revive, oc + OC_REVIVE, 4);
                dead = rb(oc + OC_ISDEAD); dying = rb(oc + OC_ISDYING);
                grass = rb(oc + OC_GRASS); freeze = rb(oc + OC_FREEZE); battle = rb(oc + OC_BATTLE);
                nomove = rb(oc + OC_NOMOVE); inroom = rb(oc + OC_INROOM);
                fantasy = rb(oc + OC_FANTASY); autoai = rb(oc + OC_AUTOAI);
                rm(&atktarget, oc + OC_ATKTARGET, 4);
            }
            move = rf32x100(a + AL_MOVESPEED);
            groundy = rf32x100(a + AL_GROUNDY);
            { unsigned long ab = a + AB_BASE;
              int bad = 0, pad = 0, bap = 0, pap = 0, bdf = 0, pdf = 0, brs = 0, prs = 0;
              int L = lvl > 0 ? lvl - 1 : 0;
              rm(&bad, ab + ABI_AD, 4);  rm(&pad, ab + ABI_PAD, 4);
              rm(&bap, ab + ABI_AP, 4);  rm(&pap, ab + ABI_PAP, 4);
              rm(&bdf, ab + ABI_DEF, 4); rm(&pdf, ab + ABI_PDF, 4);
              rm(&brs, ab + ABI_RES, 4); rm(&prs, ab + ABI_PRS, 4);
              ad = bad + pad * L / 10000;      /* 当前 = 基础 + 成长×(lvl-1) */
              ap = bap + pap * L / 10000;
              df = bdf + pdf * L / 10000;
              rs = brs + prs * L / 10000;
              { int x1=0,x2=0;
                rm(&x1, ab + ABI_ASP, 4);  rm(&x2, ab + ABI_PASP, 4); asp  = x1 + x2 * L / 10000;
                rm(&x1, ab + ABI_HPR, 4);  rm(&x2, ab + ABI_PHPR, 4); hpr  = x1 + x2 * L / 10000;
                rm(&x1, ab + ABI_EP, 4);   rm(&x2, ab + ABI_EPG, 4);  epv  = x1 + x2 * L / 10000;
                rm(&x1, ab + ABI_EPR, 4);  rm(&x2, ab + ABI_PEPR, 4); epr  = x1 + x2 * L / 10000;
                rm(&x1, ab + ABI_ATKI, 4); rm(&x2, ab + ABI_PATKI, 4);atki = x1 + x2 * L / 10000;
              }
              rm(&crit, ab + ABI_CRIT, 4);
              rm(&critd, ab + ABI_CRITD, 4);
              lvis = rb(a + AL_LOGICVIS); incam = rb(a + AL_INCAM);
              if (g_verbose) pr_info("[hero-reader] calc h[%d] lvl=%d ad=%d ap=%d def=%d res=%d asp=%d crit=%d critd=%d atki=%d hpr=%d epr=%d ep=%d\n",
                                     k2, lvl, ad, ap, df, rs, asp, crit, critd, atki, hpr, epr, epv); }
            /* g_bin_rec 填充见下方 camp 计算之后 */
            rm(&objid, a + AL_OBJID, 4);
            rm(&herocfg, a + AL_RESCFG, 4);
            {
                unsigned long ec = rptr(a + AL_EQUIP);
                eqbuf[0] = 0;
                if (ec) {
                    const unsigned long eoff[3] = { EQ_C_COMMON, EQ_C_HORIZON, EQ_C_LVLX };
                    int ci;
                    rm(&equipcnt, ec + EQ_BUYCOUNT, 4);
                    for (ci = 0; ci < 3; ci++) {
                        unsigned long c = rptr(ec + eoff[ci]);
                        unsigned long g = c ? rptr(c + CEC_GRID) : 0;
                        unsigned long mx = c ? rptr(c + CEC_MAX) : 0, i;
                        if (!g || !mx || mx > 64) continue;
                        for (i = 0; i < mx; i++) {
                            unsigned int id = 0, amt = 0;
                            rm(&id, g + GRE_EQUIPID + i * GRE_STRIDE, 4);
                            rm(&amt, g + GRE_AMOUNT + i * GRE_STRIDE, 4);
                            if (g_verbose)
                                pr_info("[hero-reader] h[%d] eqc%d s%lu g=0x%lx id=0x%x amt=%u\n",
                                        k2, ci, i, g, id, amt);
                            id &= 0xffffu;
                            if (!id || amt == 0 || amt > 99) continue;   /* 过滤数组尾部越界读到的垃圾 */
                            if (epos <= (int)sizeof(eqbuf) - 24) {
                                int w = snprintf(eqbuf + epos, sizeof(eqbuf) - (size_t)epos,
                                                 "%s[%u,%u]", eqn ? "," : "", id, amt);
                                if (w > 0) epos += w;
                            }
                            if (g_bin_path[0] && k2 < HB_MAXREC && eqn < 8) {
                                g_bin_rec[k2].eq[eqn].id = (unsigned short)id;
                                g_bin_rec[k2].eq[eqn].cnt = (unsigned short)amt;
                            }
                            eqn++;
                        }
                    }
                }
            }
            hn = hero_name(herocfg);
            camp = camp_of(inst, a);
            if (g_bin_path[0] && k2 < HB_MAXREC) {
                struct hb_rec *rb = &g_bin_rec[k2];
                memset(rb, 0, sizeof(*rb));
                rb->heroid = herocfg; rb->camp = camp >= 0 ? camp + 1 : 0; rb->objid = objid;
                rb->hp = hp; rb->hpmax = hpmax; rb->exp = exp; rb->expmax = expmax;
                rb->lvl = lvl; rb->gold = gold; rb->incgold = incgold;
                rb->charge = charge; rb->chargemax = chargemax; rb->shield = shield; rb->shieldmax = shieldmax;
                rb->x = rf32x100(a + AL_POS); rb->y = rf32x100(a + AL_POS + 4); rb->z = rf32x100(a + AL_POS + 8);
                { unsigned int qy = 0, qw = 0;   /* rotation 四元数 -> fx/fz (原始位, 供上层算 yaw) */
                  rm(&qy, a + 0x4D4UL, 4); rm(&qw, a + 0x4DCUL, 4);
                  rb->fx = (int)qy; rb->fz = (int)qw; }
                rb->move = move; rb->groundy = groundy;
                {   /* 坐标只走原生链 (libGameCore actor); 不再回退小地图组件 */
                    int kk, got = 0;
                    rb->mx = 0; rb->mz = 0;
                    for (kk = 0; kk < nrn; kk++) {
                        if (nrt[kk].hero == herocfg && nrt[kk].camp == (unsigned int)(camp + 1)) {
                            int nx = nrt[kk].x / 10, nz = nrt[kk].z / 10;   /* x1000 -> x100 */
                            if (nx && nz) { rb->mx = nx; rb->mz = nz; }
                            if (nrt[kk].hp > 0) { hp = nrt[kk].hp; }        /* 原生优先 */
                            if (nrt[kk].hpmax > 0) { hpmax = nrt[kk].hpmax; }
                            got = 1; break;
                        }
                    }
                    if (!got) g_bin_no_native++;
                    /* 可见时用 C# 位置交叉校验原生值: 偏差>5m 说明这次原生读坏了,
                     * 丢弃并让桥接回退 C# (宁可暂时没有真值, 也不喂错坐标)。 */
                    if (g_nat_gate && lvis && (rb->mx || rb->mz)) {
                        int cx = rf32x100(a + AL_POS), cz = rf32x100(a + AL_POS + 8);
                        if (cx && cz) {
                            int ddx = rb->mx - cx, ddz = rb->mz - cz;
                            if (ddx > 500 || ddx < -500 || ddz > 500 || ddz < -500) {
                                rb->mx = 0; rb->mz = 0; g_bin_bad_native++;
                            }
                        }
                    }
                    (void)got;
                }
                rb->ad = ad; rb->def = df; rb->res = rs;
                rb->atktarget = atktarget;
                rb->dead = dead; rb->dying = dying; rb->grass = grass; rb->freeze = freeze;
                rb->battle = battle; rb->nomove = nomove; rb->inroom = inroom; rb->fantasy = fantasy;
                rb->autoai = autoai; rb->lvis = lvis; rb->cam = incam;
                if (g_camcal && k2 < 64 && (unsigned char)incam != g_cam_last[k2]) {
                    g_cam_last[k2] = (unsigned char)incam;
                    pr_info("[hero-reader] camcal: objid=%u camp=%d cam=%d x=%d z=%d sx=%d sz=%d\n",
                            objid, camp >= 0 ? camp + 1 : 0, incam,
                            rf32x100(a + AL_POS), rf32x100(a + AL_POS + 8), selfX, selfZ);
                }
                if (hostPid) { unsigned int pid = 0; rm(&pid, a + 0x558UL, 4); if (pid == hostPid) rb->me = 1; }
            }

            if (g_verbose) {
                unsigned long eq = rptr(a + AL_EQUIP), bc = rptr(a + AL_BUFF);
                unsigned long c0 = eq ? rptr(eq + EQ_C_COMMON) : 0;
                unsigned long c1 = eq ? rptr(eq + EQ_C_HORIZON) : 0;
                unsigned long c2 = eq ? rptr(eq + EQ_C_LVLX) : 0;
                pr_info("[hero-reader] h[%d] eq=0x%lx c0=0x%lx/%lu g0=0x%lx c1=0x%lx/%lu g1=0x%lx c2=0x%lx/%lu g2=0x%lx buff=0x%lx spawn=0x%lx\n",
                        k2, eq,
                        c0, c0 ? rptr(c0 + CEC_MAX) : 0, c0 ? rptr(c0 + CEC_GRID) : 0,
                        c1, c1 ? rptr(c1 + CEC_MAX) : 0, c1 ? rptr(c1 + CEC_GRID) : 0,
                        c2, c2 ? rptr(c2 + CEC_MAX) : 0, c2 ? rptr(c2 + CEC_GRID) : 0,
                        bc, bc ? rptr(bc + BUF_SPAWNED) : 0);
                {
                    unsigned long ba = a + AL_STATICDATA + ASD_BASEATTR;
                    int bhp = 0, bad = 0, bap = 0, bdef = 0, bres = 0, bms = 0;
                    rm(&bhp, ba + BA_HP, 4); rm(&bad, ba + BA_AD, 4); rm(&bap, ba + BA_AP, 4);
                    rm(&bdef, ba + BA_DEF, 4); rm(&bres, ba + BA_RES, 4); rm(&bms, ba + BA_MOVESPD, 4);
                    pr_info("[hero-reader] h[%d] BaseAttr hp=%d ad=%d ap=%d def=%d res=%d ms=%d\n",
                            k2, bhp, bad, bap, bdef, bres, bms);
                }
            }

            if (g_bin_path[0] && k2 < HB_MAXREC) g_bin_rec[k2].eqn = (unsigned int)eqn;
            skills[0] = 0;
            {
                unsigned long sc = rptr(a + AL_SKILLCOMP), sa = sc ? rptr(sc + SLC_SLOTARR) : 0;
                for (s = 0; sa && s < 6; s++) {
                    unsigned long slot = rptr(sa + ARR_ELEMS + (unsigned long)s * 8);
                    int cd = 0, cdm = 0, sl = 0, bean = 0, power = 0, pmax = 0, tgt = 0, hit = 0;
                    if (!slot) continue;
                    rm(&cd, slot + SSL_CD, 4); rm(&cdm, slot + SSL_CDMAX, 4);
                    rm(&sl, slot + 0x38, 4); rm(&bean, slot + SSL_BEAN, 4);
                    rm(&power, slot + SSL_POWER, 4); rm(&pmax, slot + SSL_POWERMAX, 4);
                    rm(&tgt, slot + SSL_TARGET, 4); rm(&hit, slot + SSL_HIT, 4);
                    if (g_bin_path[0] && k2 < HB_MAXREC) {
                        struct hb_sk *K = &g_bin_rec[k2].sk[s];
                        K->lvl = (unsigned char)sl; K->ready = (unsigned char)rb(slot + 0x74);
                        K->lvlup = (unsigned char)rb(slot + SSL_CANLEVEL); K->bean = (unsigned char)bean;
                        K->cd = cd; K->cdmax = cdm; K->power = power; K->powermax = pmax;
                        K->tgt = tgt; K->hit = hit;
                    }
                    if (sp < (int)sizeof(skills) - 1) {
                        int w = snprintf(skills + sp, sizeof(skills) - (size_t)sp,
                                       "%s{\"s\":%d,\"lvl\":%d,\"cd\":%d,\"cdmax\":%d,\"ready\":%d,"
                                       "\"bean\":%d,\"power\":%d,\"powermax\":%d,\"tgt\":%d,\"hit\":%d,\"lvlup\":%d}",
                                       s ? "," : "", s, sl, cd, cdm, rb(slot + 0x74),
                                       bean, power, pmax, tgt, hit, rb(slot + SSL_CANLEVEL));
                        if (w > 0) { sp += w; if (sp > (int)sizeof(skills) - 1) sp = (int)sizeof(skills) - 1; }
                    }
                }
            }

            if (f) {
                int n = snprintf(line, sizeof(line),
                    "%s{\"i\":%d,\"a\":%lu,\"camp\":%d,\"objid\":%u,\"hero\":%u,\"name\":\"%s\","
                    "\"hp\":%d,\"hpmax\":%d,\"exp\":%d,\"expmax\":%d,\"lvl\":%d,\"gold\":%d,\"incgold\":%d,"
                    "\"charge\":%d,\"chargemax\":%d,\"shield\":%d,\"shieldmax\":%d,"
                    "\"x\":%d,\"y\":%d,\"z\":%d,\"fx\":%d,\"fz\":%d,\"move\":%d,\"groundy\":%d,"
                    "\"ad\":%d,\"def\":%d,\"res\":%d,"
                    "\"equipcnt\":%u,\"cfgid\":%u,\"dead\":%d,\"dying\":%d,\"revive\":%d,"
                    "\"grass\":%d,\"freeze\":%d,\"battle\":%d,\"nomove\":%d,\"inroom\":%d,\"fantasy\":%d,\"autoai\":%d,\"atktarget\":%u,"
                    "\"cam\":%d,\"lvis\":%d,"
                    "\"eqn\":%d,\"eq\":[%s],"
                    "\"skills\":[%s]}",
                    k2 ? ",\n" : "", k2, a, camp >= 0 ? camp + 1 : 0, objid, herocfg, hn ? hn : "?",
                    hp, hpmax, exp, expmax, lvl, gold, incgold, charge, chargemax, shield, shieldmax,
                    rf32x100(a + AL_POS), rf32x100(a + AL_POS + 4), rf32x100(a + AL_POS + 8),
                    rf32x100(a + AL_FORWARD), rf32x100(a + AL_FORWARD + 8), move, groundy,
                    ad, df, rs,
                    equipcnt, cfgid, dead, dying, revive,
                    grass, freeze, battle, nomove, inroom, fantasy, autoai, atktarget,
                    incam, lvis,
                    eqn, eqbuf, skills);
                p_kernel_write(f, line, (unsigned long)n, &pos);
            } else if (g_verbose) {
                pr_info("[hero-reader] hero[%d] camp=%d objid=%u hero=%s(0x%x) hp=%d/%d lvl=%d gold=%d pos=(%d,%d,%d) dead=%d grass=%d battle=%d\n",
                        k2, camp >= 0 ? camp + 1 : 0, objid, hn ? hn : "?", herocfg, hp, hpmax, lvl, gold,
                        rf32x100(a + AL_POS), rf32x100(a + AL_POS + 4), rf32x100(a + AL_POS + 8),
                        dead, grass, battle);
            }
        }

        g_bin_n = (cnt < HB_MAXREC) ? cnt : HB_MAXREC;
        if (g_bin_path[0]) hbin_write();
        if (f) {
            p_kernel_write(f, "]}\n", 3, &pos);
            p_filp_close(f, NULL);
            if (old_cred && p_revert_creds) p_revert_creds(old_cred);
            if (g_verbose) pr_info("[hero-reader] heroes json -> %s\n", g_hero_path);
        }
    }
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

static void read_chain(void)
{
    unsigned long manager = 0, ulf = 0, begin = 0, end = 0;
    int i, count = 0;
    if (!g_target_mm) { pr_warn("[hero-reader] chain: mm 未锁定\n"); return; }
    if (!g_gc_base) {
        unsigned long found = 0;
        vma_walk(gc_base_cb, &found);   /* 一次有界 VMA 遍历 */
        if (found) g_gc_base = found;
    }
    if (!g_gc_base) { pr_warn("[hero-reader] chain: libGameCore 未就绪\n"); return; }
    rm(&manager, g_gc_base + GC_MANAGER_BSS_OFF, 8); manager = untag(manager);
    if (!manager || manager < 0x100000000UL) { pr_warn("[hero-reader] chain: manager 无效\n"); return; }
    rm(&ulf, manager + GC_OBJ_UNIT_LABEL_FINDER, 8); ulf = untag(ulf);
    if (!ulf || ulf < 0x100000000UL) { pr_warn("[hero-reader] chain: ULF 无效\n"); return; }
    rm(&begin, ulf + GC_ULF_ARRAY_BEGIN, 8);
    rm(&end, ulf + GC_ULF_ARRAY_END, 8);
    begin = untag(begin); end = untag(end);
    if (!begin || begin >= end || (end - begin) % UNIT_LABEL_SIZE != 0) {
        pr_warn("[hero-reader] chain: 数组区间无效\n"); return;
    }
    count = (int)((end - begin) / UNIT_LABEL_SIZE);
    pr_info("[hero-reader] chain: arr=0x%lx-0x%lx (%d)\n", begin, end, count);
    for (i = 0; i < count && i < MAX_ACTORS; i++) {
        unsigned long p = begin + (unsigned long)i * UNIT_LABEL_SIZE;
        unsigned int camp = 0, x = 0, z = 0, hp = 0;
        r32(p + LABEL_CAMP_ID, &camp); r32(p + LABEL_HP, &hp);
        if (hp < 1) continue;
        r32(p + LABEL_POS_X, &x); r32(p + LABEL_POS_Z, &z);
        pr_info("[hero-reader]   [%d] camp=%u x=%u z=%u hp=%u\n", i, camp, x, z, hp);
    }
}

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
    g_tbl = 0; g_tbl_n = 0; g_am_class = 0; g_am_inst = 0;
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
                if (!g_base) find_base();
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
        if (g_req_native)  { g_req_native = 0; do_native(); }
        if (g_req_hwbpxva_valid) { g_req_hwbpxva_valid = 0; do_hwbpxva(); }
        if (g_req_fullchain) { g_req_fullchain = 0; do_fullchain(); }
        if (g_req_ns_valid)  { g_req_ns_valid = 0; do_nativescan(); }
        if (g_req_corr_valid) { g_req_corr_valid = 0; do_nscorr(); }
        if (g_req_cscan_valid) { g_req_cscan_valid = 0; do_cscan(); }
        if (g_req_pair_valid)  { g_req_pair_valid = 0; do_pairscan(); }
        if (g_req_cad2_valid) { g_req_cad2_valid = 0; do_cad(); }
        if (g_req_cams_valid) { g_req_cams_valid = 0; do_cams(); }
        if (g_req_hwbpslot4_valid) { g_req_hwbpslot4_valid = 0; do_hwbpslot4(); }
        if (g_req_hwbpslot_valid) { g_req_hwbpslot_valid = 0; do_hwbpslot(); }
        if (g_req_hwbp_valid) { g_req_hwbp_valid = 0; do_hwbp(); }
        if (g_bp_head != g_bp_tail) hr_bp_drain();
        if (g_bp_fired && g_bp_nev) { hr_bp_clear();
            pr_info("[hero-reader] hwbp: 已单次命中, 事件已自动注销\n"); }
        if (g_req_scanvec_valid) { g_req_scanvec_valid = 0; do_scanvec(); }
        if (g_req_scanptr_valid) { g_req_scanptr_valid = 0; do_scanptr(); }
        if (g_req_heroes || g_hero_interval > 0 || g_bin_interval > 0) {
            unsigned long long t0 = p_ktime_get_ns ? p_ktime_get_ns() : 0;
            g_req_heroes = 0;
            do_heroes();
            if (t0) {
                unsigned long long dt = (p_ktime_get_ns() - t0) / 1000ULL;
                g_pf_cycles++; g_pf_total_us += dt;
                if (dt > g_pf_max_us) g_pf_max_us = dt;
                if (dt > 3000ULL) g_pf_slow++;
                if ((g_pf_cycles % 50) == 0)
                    pr_info("[hero-reader] perf: n=%u avg=%lluus max=%lluus slow=%u scans=%u bin_avg=%lluus bin_max=%lluus nonat=%u mmfb=%u\n",
                            g_pf_cycles, g_pf_total_us / g_pf_cycles, g_pf_max_us, g_pf_slow, g_pf_scans,
                            g_bw_n ? g_bw_total_us / g_bw_n : 0ULL, g_bw_max_us,
                            g_bin_no_native, g_bin_mm_fallback + g_bin_bad_native);
            }
        }
        if (g_req_natfind) { g_req_natfind = 0; do_natfind(g_nf_hero, g_nf_x, g_nf_z); }
        if (g_req_natchain) { g_req_natchain = 0; do_natchain(); }
        if (g_req_nat3) { g_req_nat3 = 0; do_nat3(); }
        if (g_req_natx2) { g_req_natx2 = 0; do_natx2(); }
        if (g_req_binflush) { g_req_binflush = 0; hbin_write(); pr_info("[hero-reader] hbin: flush n=%u path=%s\n", g_bin_n, g_bin_path); }
        if (g_req_walk)   { g_req_walk = 0; do_walk(40); }
        if (g_req_chain)  { g_req_chain = 0; read_chain(); }
        if (g_req_peek_valid) { g_req_peek_valid = 0; do_peek(g_req_peek_addr, g_req_peek_count); }
        if (g_req_name_valid) { g_req_name_valid = 0; do_name(g_req_name_addr); }
        if (g_req_dump_valid) { g_req_dump_valid = 0; do_dump(g_req_dump_addr, g_req_dump_words); }
        if (g_req_gcw_valid)  { g_req_gcw_valid = 0; do_gcwatch(g_req_gcw_sf, g_req_gcw_ms, g_req_gcw_sec); }

        { int iv = g_hero_interval > 0 ? g_hero_interval : 0;
          if (g_bin_interval > 0 && (iv == 0 || g_bin_interval < iv)) iv = g_bin_interval;
          if (!g_in_match && iv < 1000) iv = 1000;      /* 局外降频, 减少空转与日志 */
          p_msleep(iv > 0 ? (iv < 50 ? 50 : iv) : 1000); }
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
    KSYM_OPT(void *(*)(void *, void *, void *, void *), register_user_hw_breakpoint, "register_user_hw_breakpoint");
    KSYM_OPT(void (*)(void *), unregister_hw_breakpoint, "unregister_hw_breakpoint");
    KSYM_OPT(void *(*)(int), find_get_task_by_vpid, "find_get_task_by_vpid");
    KSYM_OPT(long long (*)(void), ktime_get_ns, "ktime_get");
    KSYM_OPT(void *(*)(int), find_get_pid, "find_get_pid");
    KSYM_OPT(void *(*)(void *, int), get_pid_task, "get_pid_task");
    KSYM_OPT(void (*)(void *), put_pid, "put_pid");
    KSYM_OPT(void (*)(void *), put_task_struct, "put_task_struct");
    KSYM_OPT(void (*)(void *), perf_event_enable, "perf_event_enable");
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
    /* 卸载前必须注销所有硬件断点: 否则事件回调指针指向已释放的模块内存 */
    hr_bp_clear();
    if (g_bin_filp && p_filp_close) { p_filp_close(g_bin_filp, NULL); g_bin_filp = NULL; }
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
    } else if (!strcmp(args, "natx2")) {
        g_req_natx2 = 1;
        snprintf(resp, sizeof(resp), "natx2 入队");
    } else if (!strcmp(args, "nat3")) {
        g_req_nat3 = 1;
        snprintf(resp, sizeof(resp), "nat3 入队");
    } else if (!strcmp(args, "natchain")) {
        g_req_natchain = 1;
        snprintf(resp, sizeof(resp), "natchain 入队");
    } else if (!strncmp(args, "natfind ", 8)) {
        const char *p = args + 8; long hv = 0, xv = 0, zv = 0;
        g_req_natfind = 0;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { hv = hv * 10 + (*p - '0'); p++; }
        while (*p == ' ') p++;
        { int neg = 0; if (*p == '-') { neg = 1; p++; }
          while (*p >= '0' && *p <= '9') { xv = xv * 10 + (*p - '0'); p++; }
          if (neg) xv = -xv; }
        while (*p == ' ') p++;
        { int neg = 0; if (*p == '-') { neg = 1; p++; }
          while (*p >= '0' && *p <= '9') { zv = zv * 10 + (*p - '0'); p++; }
          if (neg) zv = -zv; }
        if (hv > 0) {
            g_nf_hero = (unsigned int)hv; g_nf_x = (int)xv; g_nf_z = (int)zv;
            g_req_natfind = 1;
            snprintf(resp, sizeof(resp), "natfind hero=%ld (%ld,%ld) 入队", hv, xv, zv);
        } else snprintf(resp, sizeof(resp), "natfind 用法: natfind <hero> <x_cm> <z_cm>");
    } else if (!strncmp(args, "natgate", 7)) {
        const char *p = args + 7;
        while (*p == ' ') p++;
        if (strstr(p, "off") || *p == '0') g_nat_gate = 0;
        else if (strstr(p, "on") || *p == '1') g_nat_gate = 1;
        else g_nat_gate = !g_nat_gate;
        snprintf(resp, sizeof(resp), "native 校验门=%d (%s)", g_nat_gate,
                 g_nat_gate ? "可见时用C#校验" : "完全信任原生");
    } else if (!strcmp(args, "binflush")) {
        g_req_binflush = 1;
        snprintf(resp, sizeof(resp), "binflush 入队 (n=%u)", g_bin_n);
    } else if (!strncmp(args, "herobin", 7)) {
        const char *p = args + 7;
        while (*p == ' ') p++;
        if (!strncmp(p, "stop", 4)) {
            g_bin_interval = 0; g_bin_path[0] = 0;
            if (g_bin_filp && p_filp_close) { p_filp_close(g_bin_filp, NULL); g_bin_filp = NULL; }
            snprintf(resp, sizeof(resp), "herobin 周期输出已停止");
        } else {
            int l = 0;
            /* 换路径时先释放旧句柄, 否则会一直写旧 inode */
            if (g_bin_filp && p_filp_close) { p_filp_close(g_bin_filp, NULL); g_bin_filp = NULL; }
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
                snprintf(resp, sizeof(resp), "herobin -> %s (%s)", g_bin_path,
                         g_bin_interval > 0 ? "周期" : "一次性");
        }
    } else if (!strncmp(args, "heroes", 6)) {
        const char *p = args + 6;
        while (*p == ' ') p++;
        if (!strncmp(p, "stop", 4)) {
            g_hero_interval = 0; g_hero_path[0] = 0;
            snprintf(resp, sizeof(resp), "heroes 周期输出已停止");
        } else {
            int l = 0;
            g_hero_path[0] = 0; g_hero_interval = 0;
            if (*p) {
                while (*p && *p != ' ' && l < (int)sizeof(g_hero_path) - 1) g_hero_path[l++] = *p++;
                g_hero_path[l] = 0;
                while (*p == ' ') p++;
                { long iv = 0; if (parse_dec(p, &iv) && iv > 0) g_hero_interval = (int)iv; }
            }
            if (g_hero_path[0] && !g_io_cred && p_get_task_cred) g_io_cred = p_get_task_cred(current);
            g_req_heroes = 1;
            snprintf(resp, sizeof(resp), "heroes -> %s%s%dms",
                     g_hero_path[0] ? g_hero_path : "dmesg",
                     g_hero_interval ? " 每 " : " (一次性) ",
                     g_hero_interval);
        }
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
    } else if (!strcmp(args, "chain")) {
        g_req_chain = 1; snprintf(resp, sizeof(resp), "chain 入队");
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
    } else if (!strncmp(args, "hwbpxva ", 8)) {
        const char *p = args + 8; unsigned long va = 0; long tid = 0;
        if (!g_allow_scan) { snprintf(resp, sizeof(resp), "需 ctl0 'unsafe on'"); return 0; }
        while (*p == ' ') p++;
        if (parse_hex(p, &va) && va) {
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
            if (parse_dec(p, &tid) && tid > 0) {
                g_hwbp_va = va; g_hwbp_tid = (int)tid; g_req_hwbpxva_valid = 1;
                snprintf(resp, sizeof(resp), "hwbpxva 0x%lx tid=%ld 入队", va, tid);
            } else snprintf(resp, sizeof(resp), "hwbpxva: 'hwbpxva <va_hex> <tid>'");
        } else snprintf(resp, sizeof(resp), "hwbpxva: 'hwbpxva <va_hex> <tid>'");
    } else if (!strncmp(args, "hwbpslot4 ", 10)) {
        const char *p = args + 10; long slot = 0, tid = 0;
        if (!g_allow_scan) { snprintf(resp, sizeof(resp), "需 ctl0 'unsafe on'"); return 0; }
        while (*p == ' ') p++;
        if (parse_dec(p, &slot)) {
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
            if (parse_dec(p, &tid) && tid > 0 && slot >= 0 && slot < NAT_MAX) {
                g_hwbp_slot = (int)slot; g_hwbp_tid = (int)tid;
                g_req_hwbpslot4_valid = 1;
                snprintf(resp, sizeof(resp), "hwbpslot4 %ld tid=%ld 入队", slot, tid);
            } else snprintf(resp, sizeof(resp), "hwbpslot4: 'hwbpslot4 <slot> <tid>'");
        } else snprintf(resp, sizeof(resp), "hwbpslot4: 'hwbpslot4 <slot> <tid>'");
    } else if (!strncmp(args, "pairscan ", 9)) {
        const char *p = args + 9; long a = -1, b = -1;
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9') { a = 0; while (*p >= '0' && *p <= '9') { a = a * 10 + (*p - '0'); p++; } }
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9') { b = 0; while (*p >= '0' && *p <= '9') { b = b * 10 + (*p - '0'); p++; } }
        if (a >= 0 && b >= 0) {
            g_pair_a = (int)a; g_pair_b = (int)b; g_req_pair_valid = 1;
            snprintf(resp, sizeof(resp), "pairscan %ld,%ld 入队", a, b);
        } else snprintf(resp, sizeof(resp), "pairscan: 'pairscan <v1> <v2>'");
    } else if (!strncmp(args, "camcal", 6)) {
        const char *p = args + 6;
        while (*p == ' ') p++;
        g_camcal = (*p == '0' || strstr(p, "off")) ? 0 : 1;
        snprintf(resp, sizeof(resp), "camcal=%d", g_camcal);
    } else if (!strcmp(args, "cams")) {
        g_req_cams_valid = 1;
        snprintf(resp, sizeof(resp), "cams 入队");
    } else if (!strcmp(args, "cad")) {
        g_req_cad2_valid = 1;
        snprintf(resp, sizeof(resp), "cad 入队");
    } else if (!strncmp(args, "cscan ", 6)) {
        const char *p = args + 6; long v = 0;
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9') {
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            g_cs_val = (int)v; g_req_cscan_valid = 1;
            snprintf(resp, sizeof(resp), "cscan %ld 入队", v);
        } else snprintf(resp, sizeof(resp), "cscan: 'cscan <value>'");
    } else if (!strncmp(args, "nscorr", 6)) {
        const char *p = args + 6; int k = 0; long v = 0;
        g_corr_n = 0;
        while (k < 10) {
            while (*p == ' ') p++;
            if (*p < '0' || *p > '9') break;
            v = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            g_corr_v[g_corr_n++] = (int)v; k++;
        }
        if (g_corr_n == 10) { g_req_corr_valid = 1; snprintf(resp, sizeof(resp), "nscorr 10 值 入队"); }
        else snprintf(resp, sizeof(resp), "nscorr: 需要 10 个十进制值");
    } else if (!strncmp(args, "nativescan", 10)) {
        const char *p = args + 10; int k = 0; long v = 0;
        g_ns_n = 0;
        while (k < 8) {
            while (*p == ' ') p++;
            if (*p < '0' || *p > '9') break;
            v = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            g_ns_v[g_ns_n++] = (int)v; k++;
        }
        if (g_ns_n) { g_req_ns_valid = 1; snprintf(resp, sizeof(resp), "nativescan %d 个探针 入队", g_ns_n); }
        else snprintf(resp, sizeof(resp), "nativescan: 'nativescan <v1> .. <v8>'");
    } else if (!strcmp(args, "fullchain")) {
        g_req_fullchain = 1;
        snprintf(resp, sizeof(resp), "fullchain 入队");
    } else if (!strncmp(args, "hwbpslot ", 9)) {
        const char *p = args + 9; long slot = 0, tid = 0;
        if (!g_allow_scan) { snprintf(resp, sizeof(resp), "hwbpslot 已禁用 (需 ctl0 'unsafe on')"); return 0; }
        while (*p == ' ') p++;
        if (parse_dec(p, &slot)) {
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
            if (parse_dec(p, &tid) && tid > 0 && slot >= 0 && slot < NAT_MAX) {
                g_hwbp_slot = (int)slot; g_hwbp_tid = (int)tid;
                g_req_hwbpslot_valid = 1;
                snprintf(resp, sizeof(resp), "hwbpslot %ld tid=%ld 入队 (内核内解析地址)", slot, tid);
            } else snprintf(resp, sizeof(resp), "hwbpslot: 'hwbpslot <slot> <tid>'");
        } else snprintf(resp, sizeof(resp), "hwbpslot: 'hwbpslot <slot> <tid>'");
    } else if (!strncmp(args, "hwbp ", 5)) {
        const char *p = args + 5;
        if (!strncmp(p, "off", 3)) {
            /* 清理路径永不设门禁: 必须保证任何时候都能注销事件 */
            g_hwbp_off = 1; g_req_hwbp_valid = 1;
            snprintf(resp, sizeof(resp), "hwbp off 入队");
        } else if (!g_allow_scan) {
            snprintf(resp, sizeof(resp), "hwbp 已禁用 (需 ctl0 'unsafe on')");
        } else {
            unsigned long a = 0, base = 0; long tid = 0;
            while (*p == ' ') p++;
            if (parse_hex(p, &a) && a) {
                while (*p && *p != ' ') p++;
                while (*p == ' ') p++;
                if (parse_dec(p, &tid) && tid > 0) {
                    while (*p && *p != ' ') p++;
                    while (*p == ' ') p++;
                    parse_hex(p, &base);
                    g_hwbp_addr = a; g_hwbp_tid = (int)tid; g_hwbp_base = base;
                    g_hwbp_off = 0; g_req_hwbp_valid = 1;
                    snprintf(resp, sizeof(resp), "hwbp 0x%lx tid=%ld 入队", a, tid);
                } else snprintf(resp, sizeof(resp), "hwbp: 'hwbp <addr_hex> <tid> [gcbase_hex]'");
            } else snprintf(resp, sizeof(resp), "hwbp: 'hwbp <addr_hex> <tid> [gcbase_hex] | hwbp off'");
        }
    } else if (!strcmp(args, "native")) {
        snprintf(resp, sizeof(resp), "native 入队");
        g_req_native = 1;
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
