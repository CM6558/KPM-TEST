/* hr_lifecycle.c — 生命周期 — find_pid_by_comm/pin_mm/reset_state/reader_thread/hero_init/hero_exit/hero_ctl0 */
#include "hr_internal.h"

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
