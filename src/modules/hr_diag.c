/* hr_diag.c — 诊断命令 — do_walk/do_peek/do_name/do_dump/do_gcwatch */
#include "hr_internal.h"

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
