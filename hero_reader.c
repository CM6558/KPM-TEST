/*
 * hero_reader.kpm — 王者荣耀英雄坐标内核级读取 v4.0.0
 *
 * 本版本按 KPM 开发工具包 (kpm-dev-kit) 的实测规则重写关键路径:
 *
 *  1. 未定义符号只有两扇门: KP 导出表 + SukiSU compact 兜底。
 *     - 直接引用的只能是 KP 导出符号 (printk / kallsyms_lookup_name / hook_wrap /
 *       hook_unwrap_remove / compat_copy_to_user / task_struct_offset) 和
 *       kf_* kfunc 桩 (linux/string.h、linux/kernel.h: memcpy/strcmp/strncmp/strlen/
 *       strstr/snprintf)。
 *     - 其余内核函数一律在 init 里 kallsyms_lookup_name 解析成指针再调用, 且全部判空。
 *  2. 绝不解析宏/inline 名。6.6 上 kthread_run / kthread_create 是宏,
 *     rcu_read_lock / get_task_struct / put_task_struct 是 static inline ——
 *     它们都不是符号, kallsyms_lookup_name 返回 0。改用真实符号:
 *     kthread_create_on_node + wake_up_process、__rcu_read_lock/__rcu_read_unlock、
 *     find_task_by_vpid、get_task_mm、mmput。
 *  3. 任务引用策略: task_struct 的引用计数无法安全增减 (put_task_struct 非符号),
 *     因此不持有 task_struct —— 只在 RCU 临界区内用它取一次 mm 引用 (get_task_mm),
 *     之后所有跨进程内存读走 access_remote_vm(mm, ...); 释放走 mmput()。
 *  4. 结构体偏移: 任务字段用 KP 导出的 task_struct_offset (核心启动时实测填充);
 *     不再碰 vm_area_struct/file/dentry 这些未导出、且随内核版本变化的偏移。
 *     基址定位改为读 /proc/<pid>/maps (标准机制), 失败时用 ctl0 手动提供。
 *  5. SukiSU 上 ctl0 没有字符串回传通道 (ksud 只回 int, 负数按 errno 打印):
 *     结果一律 pr_info 进 dmesg; compat_copy_to_user 只在 out_msg 非空时调用
 *     (兼容 APatch 原生路径)。
 *  6. hook 纪律: hook_wrap5 装 before 回调, 回调只做最轻的候选登记 (一个计数 + 一次
 *     比较), 不做任何可能阻塞的活; exit 先停线程再摘 hook。
 *
 * 结果查看: dmesg | grep hero-reader
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <common.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>

KPM_NAME("hero-reader");
KPM_VERSION("4.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("analyst");
KPM_DESCRIPTION("Kernel-side IL2CPP actor reader (kpm-dev-kit compliant)");

/* ============================================================
 * 游戏侧偏移 (IDA 反编译确认; 与内核版本无关, 属于游戏数据布局)
 * ============================================================ */

#define S_DOMAIN_ADDR            0xE340030UL
#define ACTOR_SIZE                 1008
#define ACTOR_CAMP_ID             0x08
#define ACTOR_POS_X               0x20
#define ACTOR_POS_Z               0x24
#define ACTOR_POS_Y               0x28
#define MAX_HEROES                 10
#define MAX_ACTORS                100

/* ---- 内核态 Actor 自动发现 (堆特征扫描) ----
 * 特征: 连续若干块, 每块 ACTOR_SIZE=1008 字节, 偏移 0x08 处是 camp_id ∈ {1,2}。
 * 只扫描匿名可读写区 (堆), 内核读 /proc/<pid>/maps 收集候选区间后逐页扫描。 */
#define SCAN_CHUNK         (1u << 20)          /* 每次 access_remote_vm 读 1MB */
#define SCAN_BLOCK_MIN     8                   /* 连续命中块数下限 (5v5 至少 10 个 actor) */
#define SCAN_BLOCK_MAX     512                 /* 连续命中块数上限 */
#define SCAN_MIN_HITS      6                   /* 整个区至少这么多命中块才算 */
#define SCAN_MAX_REGION    (512u << 20)        /* 单区扫描上限 512MB */
#define SCAN_MAX_PASSES    4000                /* 单次自动发现最多扫多少个候选区 (勿设小: 会漏区) */
#define SCAN_BUF_SIZE      (SCAN_CHUNK + ACTOR_SIZE)   /* 跨块保留 ACTOR_SIZE 尾部 */
#define SCAN_OVERLAP       ACTOR_SIZE          /* 块按 1008 步进跨分块边界 */
#define SCAN_LOW_ADDR_MIN  0x100000000UL       /* 低于 4GB 的区视为 Java/JIT 空间, 跳过 */

/* ============================================================
 * 运行时解析的内核符号 (全部 kallsyms_lookup_name, 全部判空)
 * 注意: 这里出现的名字必须都是"真实函数符号", 不能是宏或 static inline。
 * ============================================================ */

static void *(*p_find_task_by_vpid)(pid_t nr);
static void  (*p_rcu_read_lock)(void);
static void  (*p_rcu_read_unlock)(void);
static void *(*p_get_task_mm)(void *tsk);
static void  (*p_mmput)(void *mm);
static pid_t  (*p_task_pid_nr_ns)(void *task, int type, void *ns);   /* __task_pid_nr_ns */
static int   (*p_access_remote_vm)(void *mm, unsigned long addr, void *buf,
                                   int len, unsigned int gup_flags);
static int   (*p_access_process_vm)(void *tsk, unsigned long addr, void *buf,
                                    int len, unsigned int gup_flags);
static void *(*p_find_vma)(void *mm, unsigned long addr);   /* 纯内核态 VMA 遍历 */

static void *(*p_kthread_create_on_node)(int (*fn)(void *), void *data,
                                         int node, const char *namefmt, ...);
static int   (*p_wake_up_process)(void *tsk);
static int   (*p_kthread_should_stop)(void);
static int   (*p_kthread_stop)(void *k);
static void  (*p_msleep)(unsigned int msecs);

/* /proc/<pid>/maps 自动定位基址 (可选能力) */
static void *(*p_filp_open)(const char *path, int flags, int mode);
static long  (*p_kernel_read)(void *file, void *buf, unsigned long count, long long *pos);
static int   (*p_filp_close)(void *file, void *id);

/* cred 切换 — 以目标进程身份读它自己的 /proc/<pid>/maps
 * 根因 (真机实测): kthread 的 SELinux 域是 u:r:ksu:s0, 读 app 的 maps 会触发
 * hidepid/ptrace_may_access 检查并被故意返回 -ENOENT ("假装目录不存在")。
 * 解法: override_creds() 临时换成目标进程的 cred (get_task_cred), 使检查变成
 * "app 读自己的 /proc" → 全部放行; 读完 revert_creds() 恢复。全程内核态, 不碰用户态。 */
static void *(*p_override_creds)(void *new_cred);
static void  (*p_revert_creds)(void *old_cred);
static void *(*p_get_task_cred)(void *tsk);
static void  (*p_put_cred)(void *cred);

/* ============================================================
 * 全局状态
 * 单消费者模型: 状态迁移 (pid/base/actors 生效、mm 取放) 全部在 reader 线程里做;
 * hook 回调与 ctl0 只写"请求槽", 不直接改状态、不碰 mm。
 * ============================================================ */

static pid_t          g_target_pid   = 0;      /* 当前目标进程 */
static void          *g_target_mm    = NULL;   /* 目标 mm (持有一个 mm_users 引用) */
static pid_t          g_mm_pid       = 0;      /* g_target_mm 属于哪个 pid */
static unsigned long  g_base         = 0;      /* libil2cpp.so 基址 */
static unsigned long  g_sdomain      = 0;      /* 最近一次读到的 s_domain 指针 */
static unsigned long  g_actor_begin  = 0;      /* Actor 数组范围 (手动或扫描) */
static unsigned long  g_actor_end    = 0;
static int            g_hook_calls   = 0;      /* hook 触发计数 (诊断: 是否从不触发) */
static int            g_hook_installed = 0;
static void          *g_kthread      = NULL;

/* 请求槽 (写者: hook 回调 / ctl0; 消费者: reader 线程, 固定顺序消费) */
static volatile int           g_req_reset       = 0;
static volatile pid_t         g_req_pid         = 0;
static volatile int           g_req_pid_valid   = 0;
static volatile unsigned long g_req_base        = 0;
static volatile int           g_req_base_valid  = 0;
static volatile unsigned long g_req_actor_begin = 0;
static volatile unsigned long g_req_actor_end   = 0;
static volatile int           g_req_actors_valid = 0;
static volatile unsigned long g_req_peek_addr   = 0;
static volatile int           g_req_peek_count  = 0;
static volatile int           g_req_peek_valid  = 0;
static volatile int           g_req_read        = 0;   /* 手动触发一次读取 */
static volatile int           g_req_scan        = 0;   /* 手动触发一次 Actor 自动发现 */
static volatile unsigned long g_req_vma_addr    = 0;   /* 手动触发一次 VMA 探测 */
static volatile int           g_req_vma_valid   = 0;
static volatile int           g_req_find        = 0;   /* 手动触发放宽判据候选搜索 */
static volatile int           g_req_hunt        = 0;   /* 手动触发 domain 反查 */
static volatile int           g_req_walk        = 0;   /* 手动触发指针链遍历 */
static volatile unsigned long g_req_classes_addr = 0;
static volatile int           g_req_classes_valid = 0;
static char                   g_req_fc_name[40];
static volatile int           g_req_fc_valid   = 0;
static volatile unsigned long g_req_dump_addr   = 0;   /* 手动 dump 一个块 */
static volatile int           g_req_dump_words  = 0;
static volatile int           g_req_dump_valid  = 0;

/* Actor 自动发现状态 (仅在 reader 线程读写) */
static int            g_scan_done    = 0;   /* 本目标已扫过 (避免反复扫) */
static unsigned long  g_scan_passes  = 0;   /* 已扫描候选区计数 */
static int            g_scan_found   = 0;   /* 累计发现次数 */
static int            g_scan_verbose = 0;   /* 打印每个被扫描的区 */

struct hero_info {
    int index;
    int camp;
    int x, y, z;
};

static struct {
    int valid;
    int count;
    struct hero_info heroes[MAX_HEROES];
} g_snapshot;

/* /proc/<pid>/maps 扫描缓冲 (静态, 不进 dmesg, 不动态分配) */
#define MAPS_WINDOW    32768
#define MAPS_OVERLAP   2048
#define MAPS_MAX_TOTAL (8 * 1024 * 1024)
static char g_maps_buf[MAPS_WINDOW + MAPS_OVERLAP];
static int  g_maps_tries = 0;

/* ============================================================
 * 小工具
 * ============================================================ */

/* 解析十进制数字, 返回是否成功 */
static int parse_dec(const char *s, long *out)
{
    long v = 0;
    int any = 0;

    while (*s == ' ')
        s++;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        any = 1;
        s++;
    }
    if (!any)
        return 0;
    *out = v;
    return 1;
}

/* 跳过当前空白分隔的 token (含其后的空格) */
static void skip_token(const char **pp)
{
    const char *p = *pp;

    while (*p == ' ')
        p++;
    while (*p && *p != ' ')
        p++;
    *pp = p;
}

/* 解析十六进制数字 (0x 前缀可选), 返回是否成功 */
static int parse_hex(const char *s, unsigned long *out)
{
    unsigned long v = 0;
    int any = 0;

    while (*s == ' ')
        s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (;;) {
        char c = *s;
        int d;

        if (c >= '0' && c <= '9')       d = c - '0';
        else if (c >= 'a' && c <= 'f')  d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')  d = c - 'A' + 10;
        else break;
        v = v * 16 + (unsigned long)d;
        any = 1;
        s++;
    }
    if (!any)
        return 0;
    *out = v;
    return 1;
}

/* 读目标进程用户内存 (经持有的 mm 引用, 不依赖 task_struct) */
static int rm(void *dst, unsigned long uaddr, int len)
{
    if (!g_target_mm || !p_access_remote_vm || len <= 0)
        return 0;
    return p_access_remote_vm(g_target_mm, uaddr, dst, len, 0) == len;
}

/* task_struct 字段读取 — comm 偏移来自 KP 导出并被其启动时填充 (真机实测: 只填 comm,
 * pid 不填)。因此取 pid 不用偏移, 改走真实符号 __task_pid_nr_ns(task, PIDTYPE_PID, NULL)。 */
static pid_t tsk_pid(void *tsk)
{
    if (!p_task_pid_nr_ns)
        return 0;
    return p_task_pid_nr_ns(tsk, 0 /* PIDTYPE_PID */, NULL);
}

static void tsk_comm(void *tsk, char *out)
{
    memcpy(out, (char *)tsk + task_struct_offset.comm_offset, 16);
    out[15] = 0;
}

/* ============================================================
 * hook: 捕获 access_process_vm 的目标进程
 * 设计: 每当有进程读取 sgame 的内存 (ptrace/process_vm_readv 等) 时登记候选 pid。
 * 回调必须极轻: 一个计数、一个比较, 命中才写请求槽。
 * ============================================================ */

static void capture_access_vm(hook_fargs5_t *args, void *udata)
{
    void *tsk;
    pid_t pid;
    char comm[16];

    (void)udata;
    g_hook_calls++;
    if (g_target_pid || g_req_pid_valid)
        return;                          /* 已有目标或在排队 */

    tsk = (void *)args->arg0;            /* struct task_struct *tsk */
    if (!tsk)
        return;
    pid = tsk_pid(tsk);
    if (pid <= 0)
        return;
    tsk_comm(tsk, comm);
    if (!strstr(comm, "sgame") && !strstr(comm, "tmgp"))
        return;

    g_req_pid = pid;
    g_req_pid_valid = 1;
    pr_info("[hero-reader] hook 捕获候选: pid=%d comm=%s\n", pid, comm);
}

/* ============================================================
 * 基址定位: 内核读 /proc/<pid>/maps (标准机制, 零结构体偏移)
 * 只在自动捕获流程里兜底; 用户态控制命令 (ctl0 set) 提供的 base 优先。
 * ============================================================ */

/* 在缓冲里找以 "libil2cpp.so" 结尾的行, 解析行首的起始地址。
 * at_file_start: buf[0] 是否就是文件开头 (决定行首截断是否可接受)。
 * 返回 1 = 找到; line_off 指向该行的行首。 */
static int maps_scan(const char *buf, int total, int at_file_start,
                     unsigned long *base_out, int *line_off)
{
    static const char needle[] = "libil2cpp.so";
    const int nlen = 12;
    int i;

    if (total <= nlen + 1)
        return 0;

    for (i = 0; i + nlen + 1 <= total; i++) {
        int k, j;
        unsigned long v = 0;
        int got = 0;

        for (k = 0; k < nlen; k++) {
            if (buf[i + k] != needle[k])
                break;
        }
        if (k != nlen)
            continue;
        /* 路径结尾必须是 ".so" 前面紧跟 '/', 且后面是行尾/空格(如 " (deleted)") */
        if (i == 0 || buf[i - 1] != '/')
            continue;
        {
            /* 行尾检查: LF(10) / CR(13) / 空格(32, 容忍 " (deleted)" 后缀) */
            int tail = (unsigned char)buf[i + nlen];

            if (tail != 10 && tail != 13 && tail != 32)
                continue;
        }
        /* 回退到行首 */
        j = i;
        while (j > 0 && buf[j - 1] != '\n')
            j--;
        if (j == 0 && !at_file_start)
            continue;                    /* 行首落在上一块里 — 等重叠区再找 */
        /* 解析行首 "start-end" 的 start (十六进制直到 '-') */
        {
            int p = j;
            while (p < i && buf[p] != '-') {
                char c = buf[p];
                int d;

                if (c >= '0' && c <= '9')       d = c - '0';
                else if (c >= 'a' && c <= 'f')  d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F')  d = c - 'A' + 10;
                else break;
                v = v * 16 + (unsigned long)d;
                got = 1;
                p++;
            }
        }
        if (!got || !v)
            continue;
        *base_out = v;
        if (line_off)
            *line_off = j;
        return 1;
    }
    return 0;
}

/* 以目标进程身份打开文件 — override_creds 切到目标 cred, 使 hidepid/ptrace/
 * SELinux 检查按"app 读自己"放行 (kthread 域 u:r:ksu 直接 open 会 -ENOENT)。
 * 返回文件指针 (可 IS_ERR); ctx 记录 cred 上下文, 必须配对 filp_close_as_pid()。 */
struct pid_cred_ctx {
    void *cred;   /* get_task_cred 返回值 (需 put_cred) */
    void *old;    /* override_creds 返回值 (需 revert_creds) */
};

static void *filp_open_as_pid(const char *path, int flags, int mode,
                              pid_t pid, struct pid_cred_ctx *ctx)
{
    void *tsk = NULL, *f;

    memset(ctx, 0, sizeof(*ctx));
    if (!p_filp_open)
        return NULL;
    if (p_get_task_cred && p_override_creds && p_revert_creds &&
        p_rcu_read_lock && p_rcu_read_unlock) {
        p_rcu_read_lock();
        tsk = p_find_task_by_vpid(pid);
        if (tsk)
            ctx->cred = p_get_task_cred(tsk);
        p_rcu_read_unlock();
        pr_info("[hero-reader] cred 诊断: pid=%d tsk=%lx cred=%lx\n",
                pid, (unsigned long)tsk, (unsigned long)ctx->cred);
        if (ctx->cred)
            ctx->old = p_override_creds(ctx->cred);
    } else {
        pr_info("[hero-reader] cred 诊断: 符号缺失(override=%d revert=%d getcred=%d rcu=%d/%d), 直接 open\n",
                p_override_creds ? 1 : 0, p_revert_creds ? 1 : 0,
                p_get_task_cred ? 1 : 0,
                p_rcu_read_lock ? 1 : 0, p_rcu_read_unlock ? 1 : 0);
    }
    f = p_filp_open(path, flags, mode);
    pr_info("[hero-reader] cred 诊断: open %s → %lx (old=%lx)\n",
            path, (unsigned long)f, (unsigned long)ctx->old);
    return f;
}

/* 只恢复 cred 上下文 (文件打开失败提前退出时用; 此时 f 是 ERR 指针, 不能 filp_close) */
static void pid_cred_restore(struct pid_cred_ctx *ctx)
{
    if (ctx->old && p_revert_creds)
        p_revert_creds(ctx->old);
    if (ctx->cred && p_put_cred)
        p_put_cred(ctx->cred);
}

static void filp_close_as_pid(void *f, struct pid_cred_ctx *ctx)
{
    if (f && p_filp_close)
        p_filp_close(f, NULL);
    pid_cred_restore(ctx);
}

/* 读一次 /proc/<pid>/maps 定位 libil2cpp.so 基址; ~5s 重试一次 */
static void try_read_maps_base(void)
{
    void *f;
    char path[32];
    long long pos = 0;
    int carry = 0, found = 0;
    unsigned long buf_file_off = 0;      /* 缓冲首字节对应的文件偏移 */
    unsigned long base = 0, read_total = 0;
    int line_off = 0;
    int n;
    struct pid_cred_ctx ctx;

    if (!g_target_pid || !p_filp_open || !p_kernel_read || !p_filp_close)
        return;                          /* 符号缺失: 只能靠 ctl0 set 提供 base */
    if (g_maps_tries++ % 10 != 0)
        return;                          /* 500ms * 10 = ~5s 重试间隔 */

    snprintf(path, sizeof(path), "/proc/%d/maps", (int)g_target_pid);
    /* 以目标进程身份打开 — kthread 域 (u:r:ksu) 直接 open 会被 hidepid 判 -ENOENT */
    f = filp_open_as_pid(path, 0 /* O_RDONLY */, 0, g_target_pid, &ctx);
    if (!f || (unsigned long)f >= (unsigned long)-4095UL) {   /* IS_ERR */
        pid_cred_restore(&ctx);          /* 提前退出也要恢复 cred */
        if (g_maps_tries % 4 == 0)
            pr_warn("[hero-reader] 打开 %s 失败 (%lx); 可用 ctl0 'set <pid> <base>' 手动提供\n",
                    path, (unsigned long)f);
        return;
    }

    for (;;) {
        int total;

        n = (int)p_kernel_read(f, g_maps_buf + carry, MAPS_WINDOW, &pos);
        if (n <= 0)
            break;
        read_total += (unsigned long)n;
        total = carry + n;
        /* at_start 判据 = 缓冲首字节是否就是文件第 0 字节 (短读时缓冲仍从 0 开始) */
        if (maps_scan(g_maps_buf, total, buf_file_off == 0, &base, &line_off)) {
            found = 1;
            break;
        }
        if (read_total > MAPS_MAX_TOTAL)
            break;
        /* 保留尾部重叠, 保证跨块的行能被完整看到 */
        if (total > MAPS_OVERLAP) {
            memmove(g_maps_buf, g_maps_buf + total - MAPS_OVERLAP, MAPS_OVERLAP);
            buf_file_off += (unsigned long)(total - MAPS_OVERLAP);
            carry = MAPS_OVERLAP;
        } else {
            carry = total;
        }
    }
    filp_close_as_pid(f, &ctx);

    if (found && base) {
        g_base = base;
        pr_info("[hero-reader] libil2cpp.so base=0x%lx (maps) line=%.80s\n",
                base, g_maps_buf + line_off);
    } else if (g_maps_tries % 4 == 0) {
        pr_warn("[hero-reader] maps 未找到 libil2cpp.so (第 %d 次; 游戏未加载? 或 ctl0 'set <pid> <base>')\n",
                g_maps_tries);
    }
}

/* ============================================================
 * 内核态 Actor 自动发现 (堆特征扫描)
 *
 * 全程内核态: 内核读 /proc/<pid>/maps 收集匿名 rw 区 → 内核用
 * access_remote_vm 逐块读目标进程内存 → 块特征匹配 → 命中即写
 * g_actor_begin/end。用户态不需要提供任何地址。
 *
 * 块特征: 偏移 0x08 是 camp_id ∈ {1,2} 且偏移 0x20 是合法小坐标,
 * 连续 SCAN_BLOCK_MIN..MAX 块按 ACTOR_SIZE=1008 步进成立 → 认定数组。
 * ============================================================ */

static char g_scan_buf[SCAN_BUF_SIZE];

/* 热路径必须避免 kf_memcpy (它是间接调用, 逐字节调用会拖垮内核线程):
 * 常量长度的 __builtin_memcpy 会被 clang 直接编译成一条 ldr。 */
static int ld32(const char *p)
{
    int v;

    __builtin_memcpy(&v, p, 4);
    return v;
}

/* 坐标合理性判定 — 不假设坐标是 int 还是 float (避免内核里做浮点运算):
 *   整数: |v| < 100000
 *   浮点: 按 IEEE754 位型看指数域是否落在 |值| ≈ 1e-3..1e5 的区间
 * 这样 int 与 float 两种游戏坐标表示都能通过, 而指针/垃圾值会被挡掉。 */
static int coord_ok(int v)
{
    unsigned int uv = (unsigned int)v;
    unsigned int exp;

    if (v > -100000 && v < 100000)
        return 1;
    exp = (uv >> 23) & 0xFFu;
    return exp >= 110 && exp <= 150;
}

/* 判定缓冲内偏移 boff 处是否是一个合法 actor 块 (camp ∈ {1,2} 且三坐标合理)。
 * g_relaxed 为真时只认 camp (诊断用: 先用放宽判据找候选, 再人工核对布局)。 */
static int g_relaxed = 0;
static int scan_block_at(const char *buf, int window, unsigned long boff)
{
    const char *p;
    int camp, x, z, y;

    if ((long)(boff + ACTOR_SIZE) > window)
        return 0;
    p = buf + boff;
    camp = ld32(p + ACTOR_CAMP_ID);
    if (camp != 1 && camp != 2)
        return 0;
    if (g_relaxed)
        return camp;
    x = ld32(p + ACTOR_POS_X);
    z = ld32(p + ACTOR_POS_Z);
    y = ld32(p + ACTOR_POS_Y);
    if (!coord_ok(x) || !coord_ok(z) || !coord_ok(y))
        return 0;
    return camp;
}

/* 在一个候选区 [start,end) 里扫块特征。
 *
 * 数组起点可能落在区内任意偏移 (不一定与区起点 1008 对齐), 因此算法是:
 *   1) 逐字节找 camp 候选 (int32 ∈ {1,2}) → 候选数组起点 = camp偏移 - 0x08;
 *   2) 从候选起点按 ACTOR_SIZE 步进验证连续块, 连续 >= SCAN_BLOCK_MIN 即认定。
 *
 * 缓冲纪律 (关键): 只把"新读到的字节"追加到缓冲尾, 从不重读同一段 ——
 * 否则重复内容会在缓冲里伪造出 1008 周期的假链。因此 off 只按实际读到的
 * 字节数前进, base_off 是缓冲当前起点, 缓冲内容恒为 [base_off, base_off+carry)
 * 的连续切片; 消费时只丢弃 keep 之前的部分, 保证跨边界的链仍可完整验证。
 *
 * 返回 1 = 命中; *out_begin = 数组起点(绝对地址), *out_blocks = 已确认的连续块数。 */
static int scan_region(unsigned long start, unsigned long end,
                       unsigned long *out_begin, int *out_blocks)
{
    unsigned long total = end - start;
    unsigned long base_off = start;      /* 缓冲首字节的绝对地址 */
    unsigned long off = start;           /* 下一个待读地址 */
    unsigned long region_end = start + total;
    int carry = 0;
    const int need = SCAN_BLOCK_MIN;
    const int keep = (SCAN_BLOCK_MIN + 1) * ACTOR_SIZE;   /* 跨读取边界保留量 */

    if (total > SCAN_MAX_REGION)
        region_end = start + SCAN_MAX_REGION;
    if (total < (unsigned long)need * ACTOR_SIZE)
        return 0;

    while (off < region_end) {
        int c;

        /* 1. 追加读取: 目标是把缓冲填到 SCAN_CHUNK, 绝不重读已持有的字节 */
        if (carry < SCAN_CHUNK) {
            unsigned long want = SCAN_CHUNK - (unsigned long)carry;
            int n;

            if (want > region_end - off)
                want = region_end - off;
            if (want > 0) {
                n = p_access_remote_vm(g_target_mm, off, g_scan_buf + carry,
                                       (int)want, 0);
                if (n <= 0)
                    break;               /* 不可读区段: 放弃本区剩余部分 */
                off += (unsigned long)n;
                carry += n;
            }
        }

        /* 2. 扫描本窗口 */
        for (c = 8; c + 4 <= carry; c++) {
            int camp = ld32(g_scan_buf + c);

            if (camp != 1 && camp != 2)
                continue;
            {
                unsigned long boff = (unsigned long)(c - 8);   /* 候选起点(缓冲偏移) */
                int run = 0, full = 0, camp1 = 0, camp2 = 0;
                unsigned long a = boff;

                while (scan_block_at(g_scan_buf, carry, a)) {
                    int cp = scan_block_at(g_scan_buf, carry, a);

                    if (cp == 1)
                        camp1 = 1;
                    else
                        camp2 = 1;
                    run++;
                    a += ACTOR_SIZE;
                    if (run >= need)
                        break;
                }
                /* 认定条件: 连续 need 块 + 两个阵营都出现 (排除 Java 堆里的假阳性) */
                if (run >= need && camp1 && camp2) {
                    unsigned long b = boff;

                    while (scan_block_at(g_scan_buf, carry, b)) {
                        full++;
                        b += ACTOR_SIZE;
                    }
                    *out_begin = base_off + boff;
                    *out_blocks = full;
                    return 1;
                }
            }
        }

        /* 3. 消费: 只丢弃 keep 之前的部分 (块对齐, 链不被切断) */
        if (carry > keep) {
            int consumed = carry - keep;

            memmove(g_scan_buf, g_scan_buf + consumed, keep);
            base_off += (unsigned long)consumed;
            carry = keep;
        } else if (carry >= SCAN_CHUNK) {
            break;                       /* 兜底: 不该发生 (keep < SCAN_CHUNK) */
        }
    }

    return 0;
}

/* 解析 maps 行首地址并判断是否匿名 rw 区 (无路径 或 [heap]/[anon]); 
 * 只关心可读写的匿名区 — 数组在堆里。 */
static int maps_line_is_heap_rw(const char *buf, int line_off, int line_end,
                                unsigned long *start, unsigned long *end)
{
    int p = line_off;
    unsigned long v = 0, w = 0;
    int got = 0;
    const char *sp;

    /* start */
    while (p < line_end && buf[p] != '-') {
        char c = buf[p];
        int d;

        if (c >= '0' && c <= '9')       d = c - '0';
        else if (c >= 'a' && c <= 'f')  d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')  d = c - 'A' + 10;
        else return 0;
        v = v * 16 + (unsigned long)d;
        got = 1;
        p++;
    }
    if (!got || p >= line_end || buf[p] != '-')
        return 0;
    p++;
    /* end */
    got = 0;
    while (p < line_end && buf[p] != ' ') {
        char c = buf[p];
        int d;

        if (c >= '0' && c <= '9')       d = c - '0';
        else if (c >= 'a' && c <= 'f')  d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')  d = c - 'A' + 10;
        else return 0;
        w = w * 16 + (unsigned long)d;
        got = 1;
        p++;
    }
    if (!got || w <= v)
        return 0;
    /* perms: 形如 "rw-p" — 第 1 字节 'r', 第 2 字节 'w' */
    while (p < line_end && buf[p] == ' ')
        p++;
    if (p + 3 >= line_end)
        return 0;
    if (buf[p] != 'r' || buf[p + 1] != 'w')
        return 0;
    /* 路径: maps 行格式固定为
     *   start-end perms offset dev inode [pathname]
     * 匿名区没有 pathname —— 因此跳过 perms/offset/dev/inode 四个 token 后,
     * 若行内还有内容, 说明是文件映射 (libil2cpp.so / [anon:...] 之外的路径)。 */
    sp = buf + p;
    {
        int fields = 0;

        while (sp < buf + line_end && fields < 4) {
            while (sp < buf + line_end && *sp == ' ')
                sp++;
            while (sp < buf + line_end && *sp != ' ' && *sp != '\n')
                sp++;
            fields++;
        }
        while (sp < buf + line_end && (*sp == ' ' || *sp == '\n'))
            sp++;
        if (sp < buf + line_end)
            return 0;                   /* 有路径 → 文件映射, 不是匿名堆 */
    }
    *start = v;
    *end = w;
    return 1;
}

/* 前向声明 (VMA 遍历与扫描回调定义在后面) */
struct scan_ctx {
    unsigned long hits;
};
static int vma_walk(int (*cb)(void *, unsigned long, unsigned long, unsigned long),
                    void *udata);
static int scan_cb(void *udata, unsigned long start, unsigned long end,
                   unsigned long flags);

/* 纯内核态扫描: 遍历目标 mm 的 VMA, 对匿名 rw 区做特征扫描。 */
static int scan_actor_arrays_vma(int verbose)
{
    struct scan_ctx ctx = { 0 };
    int n;

    if (!g_target_mm || !p_find_vma || !p_access_remote_vm)
        return 0;
    g_scan_verbose = verbose;
    n = vma_walk(scan_cb, &ctx);
    g_scan_verbose = 0;
    if (verbose)
        pr_info("[hero-reader] VMA 扫描: 遍历 %d 个 VMA, 候选已扫=%lu, 命中=%lu\n",
                n, g_scan_passes, ctx.hits);
    return ctx.hits > 0;
}

/* 遍历 maps, 收集匿名 rw 候选区并逐区扫描; 命中即写 g_actor_begin/end。
 * verbose: 打印诊断 (open 结果 / 读入字节 / 行数 / 匿名 rw 数) — 手动 scan 时开。
 * 返回 1 = 本次调用找到。 */
static int scan_actor_arrays(int verbose)
{
    void *f;
    char path[32];
    long long pos = 0;
    int carry = 0;
    unsigned long read_total = 0;
    int n, found = 0;
    int lines = 0, heap_lines = 0, reads = 0;
    unsigned long fval = 0;
    struct pid_cred_ctx ctx;

    if (!g_target_mm || !p_access_remote_vm)
        return 0;
    if (!p_filp_open || !p_kernel_read || !p_filp_close)
        return 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", (int)g_target_pid);
    /* 以目标进程身份打开 — 否则 kthread 域被 hidepid 拦 (-ENOENT) */
    f = filp_open_as_pid(path, 0, 0, g_target_pid, &ctx);
    fval = (unsigned long)f;
    if (!f || fval >= (unsigned long)-4095UL) {
        /* 兜底: cred 切换失败或仍被拦时, 回退纯内核 VMA 遍历 */
        pid_cred_restore(&ctx);
        pr_info("[hero-reader] scan: 打开 %s 失败 (rc=%lx) → 回退纯内核 VMA 遍历\n",
                path, fval);
        return scan_actor_arrays_vma(verbose);
    }

    for (;;) {
        int total;

        n = (int)p_kernel_read(f, g_maps_buf + carry, MAPS_WINDOW, &pos);
        reads++;
        if (n <= 0) {
            if (verbose)
                pr_info("[hero-reader] scan: kernel_read 结束 (n=%d, 已读 %lu 字节)\n",
                        n, read_total);
            break;
        }
        read_total += (unsigned long)n;
        total = carry + n;

        /* 逐行解析本窗口 */
        {
            int i = 0;

            while (i < total) {
                int ls = i, le = i;
                unsigned long s = 0, e = 0;

                while (le < total && g_maps_buf[le] != '\n')
                    le++;
                if (le >= total)
                    break;              /* 不完整行: 留到重叠区 */
                lines++;
                if (maps_line_is_heap_rw(g_maps_buf, ls, le, &s, &e)) {
                    unsigned long ab = 0;
                    int blocks = 0;

                    heap_lines++;
                    if (g_scan_passes < SCAN_MAX_PASSES &&
                        scan_region(s, e, &ab, &blocks)) {
                        g_actor_begin = ab;
                        g_actor_end = ab + (unsigned long)blocks * ACTOR_SIZE;
                        g_scan_found++;
                        pr_info("[hero-reader] 自动发现 Actor 数组: 0x%lx-0x%lx (%d 块, 区 0x%lx-0x%lx)\n",
                                g_actor_begin, g_actor_end, blocks, s, e);
                        found = 1;
                        goto out;
                    }
                    g_scan_passes++;
                }
                i = le + 1;
            }
            /* 保留尾部重叠 */
            if (total > MAPS_OVERLAP) {
                memmove(g_maps_buf, g_maps_buf + total - MAPS_OVERLAP, MAPS_OVERLAP);
                carry = MAPS_OVERLAP;
            } else {
                carry = total;
            }
        }
        if (read_total > MAPS_MAX_TOTAL)
            break;
    }

out:
    filp_close_as_pid(f, &ctx);
    if (verbose)
        pr_info("[hero-reader] scan 诊断: 读 %lu 字节 (%d 次), 行=%d, 匿名rw=%d, 候选已扫=%lu\n",
                read_total, reads, lines, heap_lines, g_scan_passes);
    return found;
}

/* ============================================================
 * 纯内核态 VMA 遍历 (不碰 /proc — 内核线程读 app 的 /proc/<pid>/maps 会被
 * SELinux 拦下, 实测 filp_open 返回 -ENOENT)。
 *
 * 偏移来自真机探针 (Android 16 / 6.6.150, __randomize_layout):
 *   vm_area_struct: +0x00 vm_start, +0x08 vm_end, +0x10 vm_mm, +0x20 vm_flags
 * 机制: find_vma(mm, addr) 取首个 vma->vm_end > addr 的 VMA; 用上一块 vm_end
 * 作为下一次的 addr 即可顺序遍历 (mm 被我们持引用, 遍历期间不会释放)。
 * ============================================================ */

#define VMA_VM_START_OFF   0x00UL
#define VMA_VM_END_OFF     0x08UL
#define VMA_VM_FLAGS_OFF   0x20UL
#define VM_READ            0x00000001UL
#define VM_WRITE           0x00000002UL
#define VM_EXEC            0x00000004UL
#define VMA_WALK_MAX       20000        /* 安全上限 */

static void vma_read_fields(void *vma, unsigned long *start, unsigned long *end,
                            unsigned long *flags)
{
    unsigned long s = 0, e = 0, fl = 0;

    __builtin_memcpy(&s, (char *)vma + VMA_VM_START_OFF, 8);
    __builtin_memcpy(&e, (char *)vma + VMA_VM_END_OFF, 8);
    __builtin_memcpy(&fl, (char *)vma + VMA_VM_FLAGS_OFF, 8);
    if (start)
        *start = s;
    if (end)
        *end = e;
    if (flags)
        *flags = fl;
}

/* 遍历目标 mm 的 VMA 链表。每个 VMA 回调 cb(udata, start, end, flags);
 * cb 返回非 0 则提前停止遍历。返回遍历到的 VMA 数。 */
static int vma_walk(int (*cb)(void *, unsigned long, unsigned long, unsigned long),
                    void *udata)
{
    unsigned long addr = 0;
    int count = 0;

    if (!g_target_mm || !p_find_vma)
        return 0;

    while (count < VMA_WALK_MAX) {
        void *vma = p_find_vma(g_target_mm, addr);
        unsigned long vs = 0, ve = 0, fl = 0;

        if (!vma)
            break;
        vma_read_fields(vma, &vs, &ve, &fl);
        if (!vs || ve <= vs || vs < addr)
            break;                      /* 异常: 防死循环 */
        count++;
        if (cb && cb(udata, vs, ve, fl))
            break;
        addr = ve;
    }
    return count;
}

/* 回调: 对匿名 rw 区做 Actor 特征扫描 (纯内核 VMA 遍历路径) */
static int scan_cb(void *udata, unsigned long start, unsigned long end,
                   unsigned long flags)
{
    struct scan_ctx *ctx = udata;
    unsigned long ab = 0;
    int blocks = 0;

    /* 只看可读写、且不含可执行的匿名区 (堆/匿名映射) */
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC))
        return 0;
    if (start < SCAN_LOW_ADDR_MIN)
        return 0;                        /* Java/JIT 空间 (低地址), 跳过 */
    if (g_scan_passes >= SCAN_MAX_PASSES)
        return 1;                        /* 停止遍历 */
    if (g_scan_verbose)
        pr_info("[hero-reader]   扫区 0x%lx-0x%lx (%lu MB)\n",
                start, end, (end - start) >> 20);
    if (scan_region(start, end, &ab, &blocks)) {
        g_actor_begin = ab;
        g_actor_end = ab + (unsigned long)blocks * ACTOR_SIZE;
        g_scan_found++;
        ctx->hits++;
        pr_info("[hero-reader] 自动发现 Actor 数组: 0x%lx-0x%lx (%d 块, 区 0x%lx-0x%lx)\n",
                g_actor_begin, g_actor_end, blocks, start, end);
        return 1;                        /* 命中即停 */
    }
    g_scan_passes++;
    return 0;
}

/* ============================================================
 * Actor 数组读取
 * ============================================================ */

static void read_hero_positions(void)
{
    unsigned long total;
    int i, count = 0;

    if (!g_actor_begin || g_actor_end <= g_actor_begin)
        return;
    total = (g_actor_end - g_actor_begin) / ACTOR_SIZE;
    if (!total || total > MAX_ACTORS)
        return;

    for (i = 0; i < (int)total && count < MAX_HEROES; i++) {
        unsigned long actor = g_actor_begin + (unsigned long)i * ACTOR_SIZE;
        int camp, x, z, y;

        if (!rm(&camp, actor + ACTOR_CAMP_ID, 4))
            continue;
        if (camp != 1 && camp != 2)
            continue;
        if (!rm(&x, actor + ACTOR_POS_X, 4))
            continue;
        if (!rm(&z, actor + ACTOR_POS_Z, 4))
            continue;
        if (!rm(&y, actor + ACTOR_POS_Y, 4))
            continue;
        if (x == 0 && z == 0)
            continue;

        g_snapshot.heroes[count].index = i;
        g_snapshot.heroes[count].camp  = camp;
        g_snapshot.heroes[count].x     = x;
        g_snapshot.heroes[count].y     = y;
        g_snapshot.heroes[count].z     = z;
        count++;
    }

    g_snapshot.count = count;
    g_snapshot.valid = 1;

    pr_info("[hero-reader] === Hero Positions (count=%d) ===\n", count);
    for (i = 0; i < count; i++) {
        pr_info("[hero-reader] hero[%d] camp=%d pos=(%d,%d,%d)\n",
                g_snapshot.heroes[i].index,
                g_snapshot.heroes[i].camp,
                g_snapshot.heroes[i].x,
                g_snapshot.heroes[i].y,
                g_snapshot.heroes[i].z);
    }
}

/* 诊断: 读半个字 (只读), 帮用户人工定位 Actor 数组 */
static void do_peek(unsigned long addr, int count)
{
    int i;

    if (count <= 0)
        count = 8;
    if (count > 64)
        count = 64;

    pr_info("[hero-reader] peek 0x%lx x%d:\n", addr, count);
    for (i = 0; i < count; i++) {
        unsigned int v;

        if (!rm(&v, addr + (unsigned long)i * 4, 4)) {
            pr_info("[hero-reader]   +0x%x 不可读\n", i * 4);
            break;
        }
        pr_info("[hero-reader]   +0x%04x: %08x\n", i * 4, v);
    }
}

/* ============================================================
 * 指针链 (路径 B): domain → assemblies → image → classes → static_fields
 *
 * 偏移全部由本 .so 静态反汇编得出 (导出函数内部指令), 真机验证:
 *   Il2CppDomain:  +0x18 assemblies.begin, +0x20 assemblies.end
 *                  (s_domain 结构体位于 base+0xe344ea0; 由
 *                   il2cpp_domain_get_assemblies 内部的 0x3ace6dc 反汇编得出)
 *   Il2CppAssembly:+0x00 image
 *   Il2CppImage:   +0x00 name, +0x18 class_count
 *   Il2CppClass:   +0x10 name, +0x18 namespace, +0xb8 static_field_data
 * 该游戏指针带高位标记 (实测 0xb400 在 bit48-63), 取址前须去标记。
 * ============================================================ */

#define DOMAIN_STRUCT_OFF      0xe344ea0UL
#define OFF_DOMAIN_ASM_BEGIN   0x18UL
#define OFF_DOMAIN_ASM_END     0x20UL
#define OFF_ASM_IMAGE          0x00UL
#define OFF_IMAGE_NAME         0x00UL
#define OFF_IMAGE_CLASSCOUNT   0x18UL
#define OFF_CLASS_NAME         0x10UL
#define OFF_CLASS_NAMESPACE    0x18UL
#define OFF_CLASS_STATICFIELDS 0xb8UL
#define PTR_MASK               0x0000FFFFFFFFFFFFUL   /* 去高位标记 (bit48-63) */

static unsigned long untag(unsigned long p)
{
    return p & PTR_MASK;
}

/* 读目标进程一个 u64 指针并去标记; 失败返回 0 */
static unsigned long rptr(unsigned long addr)
{
    unsigned long v = 0;

    if (!rm(&v, addr, 8))
        return 0;
    return untag(v);
}

/* 读目标进程的 C 字符串 (最多 maxlen-1 字节) */
static int rstr(unsigned long addr, char *buf, int maxlen)
{
    int i;

    if (!addr)
        return 0;
    for (i = 0; i < maxlen - 1; i++) {
        char c;

        if (!rm(&c, addr + (unsigned long)i, 1))
            break;
        if (!c)
            break;
        buf[i] = c;
    }
    buf[i] = 0;
    return i;
}

/* 取 domain 指针 (s_domain 结构体地址) */
static unsigned long get_domain(void)
{
    if (!g_base)
        return 0;
    return untag(g_base + DOMAIN_STRUCT_OFF);
}

/* walk: 遍历 domain→assemblies→image, 打印每个 image 的名字与类数 */
static void do_walk(int maxprint)
{
    unsigned long dom, begin, end, n, i;

    if (!g_target_mm) {
        pr_warn("[hero-reader] walk: mm 未锁定\n");
        return;
    }
    dom = get_domain();
    if (!dom) {
        pr_warn("[hero-reader] walk: 需要先有 base\n");
        return;
    }
    if (!rm(&begin, dom + OFF_DOMAIN_ASM_BEGIN, 8) ||
        !rm(&end, dom + OFF_DOMAIN_ASM_END, 8)) {
        pr_warn("[hero-reader] walk: 读 domain(0x%lx) 的 assemblies 失败\n", dom);
        return;
    }
    begin = untag(begin);
    end = untag(end);
    if (!begin || end <= begin) {
        pr_warn("[hero-reader] walk: assemblies 区间异常 begin=0x%lx end=0x%lx\n",
                begin, end);
        return;
    }
    n = (end - begin) / 8;
    pr_info("[hero-reader] walk: domain=0x%lx assemblies=0x%lx-0x%lx (%lu 个)\n",
            dom, begin, end, n);
    if (n > 1000)
        n = 1000;
    for (i = 0; i < n && (maxprint <= 0 || (int)i < maxprint); i++) {
        unsigned long asm_p = rptr(begin + i * 8);
        unsigned long image, namep, cc = 0;
        char name[64];

        if (!asm_p)
            continue;
        image = rptr(asm_p + OFF_ASM_IMAGE);
        if (!image)
            continue;
        namep = rptr(image + OFF_IMAGE_NAME);
        rstr(namep, name, sizeof(name));
        rm(&cc, image + OFF_IMAGE_CLASSCOUNT, 4);
        pr_info("[hero-reader]   asm[%lu] 0x%lx image=0x%lx classes=%lu name=%s\n",
                i, asm_p, image, cc, name);
    }
}
/* classes <image_addr>: 探测 Il2CppImage 里 classes 数组的真实偏移 —
 * 对每个 8 字节对齐偏移 o 读 P=*(image+o), 若 *(P) 是对象且该对象 +0x10 是合法字符串
 * (Il2CppClass.name), 就认定 image+o 是 classes 数组。 */
static void do_classes(unsigned long image)
{
    int cc = 0, o;

    if (!image) {
        pr_warn("[hero-reader] classes: 需要 image 地址\n");
        return;
    }
    rm(&cc, image + OFF_IMAGE_CLASSCOUNT, 4);
    pr_info("[hero-reader] classes: image=0x%lx typeCount=%d, 找类数组 (判据: 元素的 image 字段==image)…\n",
            image, cc);
    for (o = 0x00; o <= 0x200; o += 8) {
        unsigned long arr = rptr(image + o);
        unsigned long first;
        int k;

        if (!arr)
            continue;
        first = rptr(arr);
        if (!first)
            continue;
        /* 该数组的第一个元素里, 某个字段应等于 image (类的 image 反向引用) */
        for (k = 0; k <= 0x18; k += 8) {
            unsigned long back = rptr(first + (unsigned long)k);

            if (back == image) {
                unsigned long nm = rptr(first + OFF_CLASS_NAME);
                char nmb[64] = "";

                if (nm)
                    rstr(nm, nmb, sizeof(nmb));
                pr_info("[hero-reader]   >>> image+0x%02x = 类数组! arr=0x%lx first=0x%lx "
                        "(image 字段 @+0x%x) name='%s'\n",
                        o, arr, first, k, nmb);
            }
        }
    }
}

/* findclass <名字>: 扫描 rw 区, 找 name@+0x10 == 目标名 的 Il2CppClass 对象。
 * 判据: *(V+0x10)=name字符串, *(V+0x18)=namespace字符串(可空), *(V+0xB8)=static_fields 指针。
 * 三字段同时成立 → 假阳性极低。用于绕过"按索引取类"的内部函数 (静态不可读)。 */
static char g_fc_name[40];
static int g_fc_hits;

/* 名字是否匹配 g_fc_name 中以 '|' 分隔的任一关键词 */
static int name_matches(const char *nm)
{
    const char *p = g_fc_name;

    if (!p[0])
        return 0;
    while (*p) {
        const char *e = p;
        int l;

        while (*e && *e != '|')
            e++;
        l = (int)(e - p);
        if (l > 0) {
            int i, ok = 1;

            for (i = 0; i < l && nm[i]; i++) {
                if (nm[i] != p[i]) {
                    ok = 0;
                    break;
                }
            }
            /* 子串匹配: 逐位置比较 */
            if (!ok) {
                const char *q = nm;

                ok = 0;
                while (*q && !ok) {
                    int j;

                    for (j = 0; j < l; j++) {
                        if (q[j] != p[j])
                            break;
                    }
                    if (j == l && l > 0)
                        ok = 1;
                    q++;
                }
            }
            if (ok)
                return 1;
        }
        if (*e == '|')
            e++;
        p = e;
    }
    return 0;
}

static int findclass_cb(void *udata, unsigned long start, unsigned long end,
                        unsigned long flags)
{
    unsigned long total = end - start, off = 0;

    (void)udata;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC))
        return 0;
    if (start < SCAN_LOW_ADDR_MIN)
        return 0;
    if (total > SCAN_MAX_REGION)
        total = SCAN_MAX_REGION;
    while (off < total && g_fc_hits < 60) {
        unsigned long want = total - off;
        int n, i;

        if (want > SCAN_CHUNK)
            want = SCAN_CHUNK;
        n = p_access_remote_vm(g_target_mm, start + off, g_scan_buf, (int)want, 0);
        if (n <= 0)
            break;
        for (i = 0; i + 0xC0 <= n; i += 8) {
            unsigned long np, nsp, sf = 0, V, img;
            char nm[64], ns[40], iname[40];

            __builtin_memcpy(&np, g_scan_buf + i + OFF_CLASS_NAME, 8);
            np = untag(np);
            if (np < 0x4000000000UL || np > 0x7200000000UL)
                continue;
            if (rstr(np, nm, sizeof(nm)) == 0)
                continue;
            if (!name_matches(nm))
                continue;
            /* 强判据: +0x00 必须指向一个 Il2CppImage (其 +0x00 是 `.dll` 名字) */
            V = start + off + (unsigned long)i;
            __builtin_memcpy(&img, g_scan_buf + i + 0, 8);
            img = untag(img);
            if (img < 0x4000000000UL || img > 0x7200000000UL)
                continue;
            iname[0] = 0;
            {
                unsigned long inp = rptr(img + OFF_IMAGE_NAME);

                if (!inp)
                    continue;
                if (rstr(inp, iname, sizeof(iname)) == 0)
                    continue;
                if (!strstr(iname, ".dll"))
                    continue;
            }
            __builtin_memcpy(&nsp, g_scan_buf + i + OFF_CLASS_NAMESPACE, 8);
            nsp = untag(nsp);
            ns[0] = 0;
            if (nsp >= 0x4000000000UL && nsp <= 0x7200000000UL)
                rstr(nsp, ns, sizeof(ns));
            rm(&sf, V + OFF_CLASS_STATICFIELDS, 8);
            pr_info("[hero-reader] findclass: '%s' class=0x%lx image='%s' ns='%s' static_fields=0x%lx\n",
                    nm, V, iname, ns, untag(sf));
            g_fc_hits++;
        }
        off += (unsigned long)n;
    }
    return g_fc_hits >= 60;
}

static void do_findclass(const char *name)
{
    int l = 0;

    while (name[l] && l < 39) {
        g_fc_name[l] = name[l];
        l++;
    }
    g_fc_name[l] = 0;
    g_fc_hits = 0;
    pr_info("[hero-reader] findclass: 找 '%s' …\n", g_fc_name);
    vma_walk(findclass_cb, NULL);
    pr_info("[hero-reader] findclass: 命中 %d 个\n", g_fc_hits);
}

/* 诊断: 按 IDA 结构偏移反查 Il2CppDomain —
 * 在含 (base+0xE340030) 的区内扫描 8 字节对齐的 u64, 找满足:
 *   值 V 是堆指针 且 *(V+0x18) 也是堆指针 (assemblies) 且 *(V+0x20) ∈ [30,800] (count)
 * 这一条就是 IDA 给出的 DOMAIN_ASSEMBLIES_PTR=0x18 / DOMAIN_ASSEMBLY_COUNT=0x20。 */
static unsigned long g_hunt_target = 0;
static int g_hunt_hits = 0;

static int hunt_cb(void *udata, unsigned long start, unsigned long end,
                   unsigned long flags)
{
    unsigned long total = end - start;
    unsigned long off = 0;
    int carry = 0;

    (void)udata;
    if (!(flags & VM_READ) || !(flags & VM_WRITE))
        return 0;
    if (start > g_hunt_target || g_hunt_target >= end)
        return 0;                        /* 只看含目标地址的区 */
    if (total > SCAN_MAX_REGION)
        total = SCAN_MAX_REGION;
    pr_info("[hero-reader] hunt: 区 0x%lx-0x%lx, 找 domain 候选…\n", start, end);

    while (off < total && g_hunt_hits < 12) {
        unsigned long want = total - off;
        int n, i, i0, i1;

        if (want > SCAN_CHUNK)
            want = SCAN_CHUNK;
        n = p_access_remote_vm(g_target_mm, start + off, g_scan_buf + carry, (int)want, 0);
        if (n <= 0)
            break;
        i0 = (carry + 7) / 8;
        i1 = (carry + n) / 8;
        for (i = i0; i < i1; i++) {
            unsigned long v, a18 = 0, c20 = 0;

            __builtin_memcpy(&v, g_scan_buf + i * 8, 8);
            if (v < 0x4000000000UL || v > 0x7200000000UL)
                continue;
            if (!rm(&a18, v + 0x18, 8))
                continue;
            if (!rm(&c20, v + 0x20, 4))
                continue;
            if (a18 >= 0x4000000000UL && a18 <= 0x7200000000UL &&
                c20 >= 30 && c20 <= 800) {
                unsigned long addr = start + off - (unsigned long)carry + (unsigned long)i * 8;

                pr_info("[hero-reader] domain 候选 @0x%lx (base+0x%lx) -> 0x%lx "
                        "(assemblies=0x%lx count=%lu)\n",
                        addr, addr - g_base, v, a18, c20);
                g_hunt_hits++;
            }
        }
        {
            int consumed = (carry + n) > SCAN_OVERLAP ? (carry + n) - SCAN_OVERLAP : 0;

            if (consumed > 0) {
                memmove(g_scan_buf, g_scan_buf + consumed, SCAN_OVERLAP);
                carry = SCAN_OVERLAP;
            } else {
                carry += n;
            }
            off += (unsigned long)consumed;
            if (consumed == 0 && carry >= SCAN_CHUNK)
                break;
        }
    }
    return g_hunt_hits >= 12;
}

static void do_hunt(void)
{
    g_hunt_hits = 0;
    if (!g_base) {
        pr_warn("[hero-reader] hunt: 需要先有 base\n");
        return;
    }
    g_hunt_target = g_base + S_DOMAIN_ADDR;
    pr_info("[hero-reader] hunt: 目标地址 = base+0x%lx = 0x%lx\n",
            (unsigned long)S_DOMAIN_ADDR, g_hunt_target);
    vma_walk(hunt_cb, NULL);
    pr_info("[hero-reader] hunt 结束, 候选 %d 个\n", g_hunt_hits);
}

/* 诊断: 打印一个 actor 块的原始 32 位字 (hex), 用于在主机侧换算/定位坐标字段 */
static void do_dump(unsigned long addr, int words)
{
    int i;

    if (words <= 0)
        words = ACTOR_SIZE / 4;          /* 默认整块 */
    if (words > 512)
        words = 512;
    pr_info("[hero-reader] dump 0x%lx x%d words:\n", addr, words);
    for (i = 0; i < words; i += 8) {
        int k;
        char line[200];
        int pos = 0;

        for (k = 0; k < 8 && i + k < words; k++) {
            unsigned int v;

            if (!rm(&v, addr + (unsigned long)(i + k) * 4, 4)) {
                pr_info("[hero-reader]   +0x%04x 不可读\n", (i + k) * 4);
                return;
            }
            pos += snprintf(line + pos, sizeof(line) - (unsigned)pos,
                            "%08x ", v);
        }
        pr_info("[hero-reader]   +0x%04x: %s\n", i * 4, line);
    }
}

/* 诊断: 放宽判据找候选 (只认 1008 步进 + camp@0x08 ∈ {1,2}), 打印候选布局。
 * 用于在真机上核对/重新确定 actor 布局常量。 */
static int g_find_count = 0;
static int find_cb(void *udata, unsigned long start, unsigned long end,
                   unsigned long flags)
{
    unsigned long off = 0;
    int carry = 0;
    unsigned long total = end - start;

    (void)udata;
    if (!(flags & VM_READ) || !(flags & VM_WRITE) || (flags & VM_EXEC))
        return 0;
    if (start < SCAN_LOW_ADDR_MIN)
        return 0;
    if (total > SCAN_MAX_REGION)
        total = SCAN_MAX_REGION;

    while (off < total && g_find_count < 5) {
        unsigned long want = total - off;
        int n, c;

        if (want > SCAN_CHUNK)
            want = SCAN_CHUNK;
        n = p_access_remote_vm(g_target_mm, start + off, g_scan_buf + carry, (int)want, 0);
        if (n <= 0)
            break;
        for (c = 8; c + 4 <= carry + n; c++) {
            int camp = ld32(g_scan_buf + c);
            int run = 0;
            unsigned long a;

            if (camp != 1 && camp != 2)
                continue;
            a = (unsigned long)(c - 8);
            while (scan_block_at(g_scan_buf, carry + n, a)) {
                run++;
                a += ACTOR_SIZE;
                if (run >= SCAN_BLOCK_MIN)
                    break;
            }
            if (run >= SCAN_BLOCK_MIN) {
                unsigned long base = start + off + (unsigned long)(c - 8);
                unsigned int v08, v18, v20, v24, v28;

                __builtin_memcpy(&v08, (char *)(g_scan_buf + c), 4);
                __builtin_memcpy(&v18, g_scan_buf + (c - 8) + 0x18, 4);
                __builtin_memcpy(&v20, g_scan_buf + (c - 8) + 0x20, 4);
                __builtin_memcpy(&v24, g_scan_buf + (c - 8) + 0x24, 4);
                __builtin_memcpy(&v28, g_scan_buf + (c - 8) + 0x28, 4);
                pr_info("[hero-reader] 候选#%d @0x%lx (区 0x%lx-0x%lx) run>=%d: "
                        "0x08=%08x 0x18=%08x 0x20=%08x 0x24=%08x 0x28=%08x\n",
                        g_find_count, base, start, end, run, v08, v18, v20, v24, v28);
                g_find_count++;
                c += ACTOR_SIZE - 1;
            }
        }
        {
            int consumed = (carry + n) > SCAN_OVERLAP ? (carry + n) - SCAN_OVERLAP : 0;

            if (consumed > 0) {
                memmove(g_scan_buf, g_scan_buf + consumed, SCAN_OVERLAP);
                carry = SCAN_OVERLAP;
            } else {
                carry += n;
            }
            off += (unsigned long)consumed;
            if (consumed == 0 && carry >= SCAN_CHUNK)
                break;
        }
    }
    return g_find_count >= 5;
}

static void do_find(void)
{
    g_relaxed = 1;
    g_find_count = 0;
    pr_info("[hero-reader] 放宽判据候选搜索 (1008 步进 + camp@0x08∈{1,2})…\n");
    vma_walk(find_cb, NULL);
    g_relaxed = 0;
    pr_info("[hero-reader] 候选搜索结束, 命中 %d 个\n", g_find_count);
}

/* 诊断: 打印 find_vma(mm, addr) 返回的 vm_area_struct 前 0x98 字节 (u64 逐字),
 * 用于在真机上确定 vm_start / vm_end / vm_file 的实际偏移 (纯内核态, 不碰 /proc)。 */
static void do_vma_probe(unsigned long addr)
{
    void *vma;
    int i;

    if (!g_target_mm || !p_find_vma) {
        pr_warn("[hero-reader] vma 探测不可用 (mm=%d find_vma=%d)\n",
                g_target_mm ? 1 : 0, p_find_vma ? 1 : 0);
        return;
    }
    vma = p_find_vma(g_target_mm, addr);
    if (!vma) {
        pr_warn("[hero-reader] vma: find_vma(0x%lx) = NULL\n", addr);
        return;
    }
    pr_info("[hero-reader] vma(0x%lx) = %lx, mm=%lx; 前 0x98 字节:\n",
            addr, (unsigned long)vma, (unsigned long)g_target_mm);
    for (i = 0; i < 0x98; i += 8) {
        unsigned long v;

        __builtin_memcpy(&v, (char *)vma + i, 8);
        pr_info("[hero-reader]   +0x%02x: %016lx\n", i, v);
    }
}

/* ============================================================
 * 状态复位 (仅在 reader 线程 / exit 里调用; mm 的取放单点)
 * ============================================================ */

static void reset_target_state(const char *why)
{
    if (g_target_mm) {
        p_mmput(g_target_mm);
        g_target_mm = NULL;
    }
    g_mm_pid = 0;
    g_base = 0;
    g_sdomain = 0;
    g_actor_begin = 0;
    g_actor_end = 0;
    g_maps_tries = 0;
    g_scan_done = 0;
    g_scan_passes = 0;
    g_snapshot.valid = 0;
    g_snapshot.count = 0;
    if (why)
        pr_info("[hero-reader] 状态复位: %s\n", why);
}

/* 锁定目标 mm: RCU 临界区内 find_task_by_vpid + get_task_mm 取引用,
 * 临界区外不再使用 task_struct 指针 (它没有引用保护)。 */
static void *pin_mm_by_pid(pid_t pid)
{
    void *tsk = NULL, *mm = NULL;

    if (!p_find_task_by_vpid || !p_get_task_mm)
        return NULL;
    if (p_rcu_read_lock && p_rcu_read_unlock) {
        p_rcu_read_lock();
        tsk = p_find_task_by_vpid(pid);
        if (tsk)
            mm = p_get_task_mm(tsk);
        p_rcu_read_unlock();
    } else {
        /* 降级: 内核没有 __rcu_read_lock 符号 (非 PREEMPT_RCU) —
         * 有极小竞态窗口, init 时已警告 */
        tsk = p_find_task_by_vpid(pid);
        if (tsk)
            mm = p_get_task_mm(tsk);
    }
    return mm;
}

/* ============================================================
 * reader 线程: 唯一的"状态机消费者"
 * ============================================================ */

static int reader_thread(void *data)
{
    int idle_ticks = 0, pin_fail = 0, read_fail = 0, hint_ticks = 0;

    (void)data;
    pr_info("[hero-reader] reader 线程启动\n");

    while (!p_kthread_should_stop()) {
        /* ---- 1. 消费请求槽 (固定顺序: reset → pid → base → actors → peek) ---- */
        if (g_req_reset) {
            g_req_reset = 0;
            g_req_pid_valid = 0;
            g_req_base_valid = 0;
            g_req_actors_valid = 0;
            g_req_peek_valid = 0;
            reset_target_state("ctl0 reset");
            g_target_pid = 0;
            pin_fail = read_fail = 0;
        }
        if (g_req_pid_valid) {
            g_req_pid_valid = 0;
            reset_target_state(NULL);    /* 清旧 mm/base/actors/snapshot */
            g_target_pid = g_req_pid;
            pin_fail = read_fail = 0;
            pr_info("[hero-reader] 目标 pid=%d\n", g_target_pid);
        }
        if (g_req_base_valid) {
            g_req_base_valid = 0;
            g_base = g_req_base;
            if (g_base)
                pr_info("[hero-reader] base=0x%lx (ctl0)\n", g_base);
        }
        if (g_req_actors_valid) {
            g_req_actors_valid = 0;
            g_actor_begin = g_req_actor_begin;
            g_actor_end = g_req_actor_end;
            pr_info("[hero-reader] actors=0x%lx-0x%lx (ctl0)\n",
                    g_actor_begin, g_actor_end);
        }
        if (g_req_peek_valid) {
            g_req_peek_valid = 0;
            if (g_target_mm)
                do_peek(g_req_peek_addr, g_req_peek_count);
            else
                pr_warn("[hero-reader] peek 失败: 目标 mm 未锁定\n");
        }
        if (g_req_dump_valid) {
            g_req_dump_valid = 0;
            if (g_target_mm)
                do_dump(g_req_dump_addr, g_req_dump_words);
            else
                pr_warn("[hero-reader] dump 失败: 目标 mm 未锁定\n");
        }
        if (g_req_fc_valid) {
            g_req_fc_valid = 0;
            do_findclass(g_req_fc_name);
        }
        if (g_req_classes_valid) {
            g_req_classes_valid = 0;
            do_classes(g_req_classes_addr);
        }
        if (g_req_walk) {
            g_req_walk = 0;
            do_walk(30);
        }
        if (g_req_hunt) {
            g_req_hunt = 0;
            if (g_target_mm)
                do_hunt();
            else
                pr_warn("[hero-reader] hunt 失败: 目标 mm 未锁定\n");
        }
        if (g_req_find) {
            g_req_find = 0;
            if (g_target_mm)
                do_find();
            else
                pr_warn("[hero-reader] find 失败: 目标 mm 未锁定\n");
        }
        if (g_req_vma_valid) {
            g_req_vma_valid = 0;
            do_vma_probe(g_req_vma_addr);
        }
        if (g_req_scan) {
            g_req_scan = 0;
            g_scan_done = 0;             /* 强制重扫 */
            g_scan_passes = 0;
            /* 显式请求: 直接执行 (不受 base 门限制 — 数组位置与 base 无关) */
            if (g_target_mm) {
                pr_info("[hero-reader] 手动 scan 开始…\n");
                if (scan_actor_arrays(1))
                    read_hero_positions();
                else
                    pr_warn("[hero-reader] 手动 scan 未命中 (扫描 %lu 个候选区)\n",
                            g_scan_passes);
            } else {
                pr_warn("[hero-reader] 手动 scan 失败: 目标 mm 未锁定\n");
            }
        }
        if (g_req_read) {
            g_req_read = 0;
            if (g_target_mm && g_base) {
                unsigned long sd = 0;

                if (rm(&sd, g_base + S_DOMAIN_ADDR, 8)) {
                    g_sdomain = sd;
                    pr_info("[hero-reader] read(手动): s_domain=0x%lx\n", sd);
                }
                if (g_actor_begin && g_actor_end)
                    read_hero_positions();
                else
                    pr_info("[hero-reader] read(手动): Actor 数组未设置 (ctl0 'actors <起> <止>')\n");
            } else {
                pr_warn("[hero-reader] read(手动): 未就绪 (pid=%d mm=%d base=0x%lx)\n",
                        g_target_pid, g_target_mm ? 1 : 0, g_base);
            }
        }

        /* ---- 2. 状态机 ---- */
        if (g_target_pid) {
            idle_ticks = 0;
            if (!g_target_mm) {
                g_target_mm = pin_mm_by_pid(g_target_pid);
                if (g_target_mm) {
                    g_mm_pid = g_target_pid;
                    pin_fail = 0;
                    pr_info("[hero-reader] 已锁定目标 mm (pid=%d)\n", g_target_pid);
                } else if (++pin_fail >= 20) {
                    pr_warn("[hero-reader] 连续 20 次无法锁定 pid=%d (已退出?); 清除目标\n",
                            g_target_pid);
                    g_target_pid = 0;
                    pin_fail = 0;
                }
            } else if (g_mm_pid != g_target_pid) {
                reset_target_state("pid 变更, 重新锁定");
            }

            if (g_target_mm) {
                if (!g_base)
                    try_read_maps_base();
                if (g_base) {
                    unsigned long sd = 0;

                    if (rm(&sd, g_base + S_DOMAIN_ADDR, 8)) {
                        read_fail = 0;
                        if (sd != g_sdomain) {
                            g_sdomain = sd;
                            pr_info("[hero-reader] s_domain=0x%lx\n", sd);
                        }
                        if (g_actor_begin && g_actor_end) {
                            read_hero_positions();
                        } else if (!g_scan_done) {
                            /* base 就绪 → 内核态自动发现 Actor 数组 (只做一次) */
                            g_scan_done = 1;
                            pr_info("[hero-reader] base 就绪, 开始内核态 Actor 自动发现 (扫描 %lu 个候选区)…\n",
                                    g_scan_passes);
                            if (scan_actor_arrays(0)) {
                                read_hero_positions();
                            } else {
                                pr_warn("[hero-reader] 自动发现未命中 (扫描 %lu 区); "
                                        "可 ctl0 'scan' 重试, 或 'actors <起> <止>' 手动指定\n",
                                        g_scan_passes);
                            }
                        } else if (hint_ticks++ % 60 == 0) {
                            pr_info("[hero-reader] 已就绪但未定位数组: ctl0 'scan' 重试 / "
                                    "'actors <起> <止>' 手动 / 'peek' 诊断\n");
                        }
                    } else if (++read_fail >= 10) {
                        pr_warn("[hero-reader] 目标内存连续 10 次不可读 — 重置目标\n");
                        reset_target_state(NULL);
                        g_target_pid = 0;
                        read_fail = 0;
                    }
                }
            }
        } else {
            if (++idle_ticks % 60 == 0) {
                pr_info("[hero-reader] 等待目标… (hook 触发=%d 次; 也可 ctl0 'set <pid> <base>')\n",
                        g_hook_calls);
            }
        }

        p_msleep(500);
    }

    pr_info("[hero-reader] reader 线程退出\n");
    return 0;
}

/* ============================================================
 * 生命周期
 * ============================================================ */

static long hero_reader_init(const char *args, const char *event, void *reserved)
{
    void *k;

    (void)reserved;
    pr_info("[hero-reader] v4.0.0 init: event=%s args=%s\n",
            event ? event : "(null)", args ? args : "(null)");

    if (!kallsyms_lookup_name) {
        pr_err("[hero-reader] FATAL: kallsyms_lookup_name 不可用\n");
        return -1;
    }
    if (task_struct_offset.comm_offset <= 0) {
        pr_err("[hero-reader] FATAL: comm_offset 未填充 (%d)\n",
               task_struct_offset.comm_offset);
        return -1;
    }

    /* 必需符号 — 缺失则拒绝加载 (只允许"真的存在"的函数名放进这里!) */
#define KSYM_REQ(t, var, name)                                              \
    p_##var = (t)kallsyms_lookup_name(name);                                \
    if (!p_##var) {                                                         \
        pr_err("[hero-reader] FATAL: 必需符号缺失: " name "\n");            \
        return -1;                                                          \
    }
    /* 可选符号 — 缺失只降级并告警 */
#define KSYM_OPT(t, var, name)                                              \
    p_##var = (t)kallsyms_lookup_name(name);                                \
    if (!p_##var)                                                           \
        pr_warn("[hero-reader] 可选符号缺失: " name " (相关能力降级)\n");

    KSYM_REQ(void *(*)(pid_t),                     find_task_by_vpid,    "find_task_by_vpid");
    KSYM_REQ(pid_t (*)(void *, int, void *),       task_pid_nr_ns,       "__task_pid_nr_ns");
    KSYM_REQ(void *(*)(void *),                    get_task_mm,          "get_task_mm");
    KSYM_REQ(void (*)(void *),                     mmput,                "mmput");
    KSYM_REQ(int (*)(void *, unsigned long, void *, int, unsigned int), access_remote_vm, "access_remote_vm");
    KSYM_REQ(void *(*)(int (*)(void *), void *, int, const char *, ...), kthread_create_on_node, "kthread_create_on_node");
    KSYM_REQ(int (*)(void *),                      wake_up_process,      "wake_up_process");
    KSYM_REQ(int (*)(void),                        kthread_should_stop,  "kthread_should_stop");
    KSYM_REQ(int (*)(void *),                      kthread_stop,         "kthread_stop");
    KSYM_REQ(void (*)(unsigned int),               msleep,               "msleep");

    KSYM_OPT(void (*)(void),                       rcu_read_lock,        "__rcu_read_lock");
    KSYM_OPT(void (*)(void),                       rcu_read_unlock,      "__rcu_read_unlock");
    KSYM_OPT(int (*)(void *, unsigned long, void *, int, unsigned int), access_process_vm, "access_process_vm");
    KSYM_OPT(void *(*)(const char *, int, int),    filp_open,            "filp_open");
    KSYM_OPT(long (*)(void *, void *, unsigned long, long long *), kernel_read, "kernel_read");
    KSYM_OPT(int (*)(void *, void *),              filp_close,           "filp_close");
    KSYM_OPT(void *(*)(void *, unsigned long),     find_vma,             "find_vma");

    /* cred 切换族: 内核态以目标进程身份读 /proc/<pid>/maps (hidepid 绕过) */
    KSYM_OPT(void *(*)(void *),                    override_creds,        "override_creds");
    KSYM_OPT(void (*)(void *),                     revert_creds,          "revert_creds");
    KSYM_OPT(void *(*)(void *),                    get_task_cred,         "get_task_cred");
    KSYM_OPT(void (*)(void *),                     put_cred,              "put_cred");

    if (!p_rcu_read_lock || !p_rcu_read_unlock)
        pr_warn("[hero-reader] RCU 原语缺失: 目标锁定存在极小竞态窗口\n");
    if (!p_access_process_vm)
        pr_warn("[hero-reader] access_process_vm 缺失: 自动捕获不可用, 用 ctl0 'set'\n");
    if (!p_filp_open || !p_kernel_read || !p_filp_close)
        pr_warn("[hero-reader] 文件符号缺失: 自动基址(maps)不可用, 用 ctl0 'set'\n");
    if (!p_override_creds || !p_revert_creds || !p_get_task_cred || !p_put_cred)
        pr_warn("[hero-reader] cred 符号缺失 (%d/%d/%d/%d): maps 读取可能仍被 hidepid 拦, 回退 VMA 遍历\n",
                p_override_creds ? 1 : 0, p_revert_creds ? 1 : 0,
                p_get_task_cred ? 1 : 0, p_put_cred ? 1 : 0);

    /* init args: "[pid] [0xbase]" 可选 */
    if (args && *args) {
        const char *p = args;
        long pidv = 0;
        unsigned long b = 0;

        if (parse_dec(p, &pidv) && pidv > 0) {
            g_target_pid = (pid_t)pidv;
            pr_info("[hero-reader] 目标来自 args: pid=%d\n", g_target_pid);
            while (*p == ' ')
                p++;
            while (*p >= '0' && *p <= '9')
                p++;
            if (parse_hex(p, &b) && b) {
                g_base = b;
                pr_info("[hero-reader] base 来自 args: 0x%lx\n", g_base);
            }
        }
    }

    /* hook access_process_vm (before 回调, 只做候选登记) */
    if (p_access_process_vm) {
        hook_err_t err = hook_wrap5((void *)p_access_process_vm,
                                    capture_access_vm, NULL, NULL);

        if (err == HOOK_NO_ERR) {
            g_hook_installed = 1;
            pr_info("[hero-reader] hooked access_process_vm\n");
        } else {
            pr_warn("[hero-reader] hook_wrap5 -> %d (继续, 无自动捕获)\n", err);
        }
    }

    /* reader 线程 (等待目标; 不做自动捕获也要起, 供 ctl0 驱动) */
    k = p_kthread_create_on_node(reader_thread, NULL, -1 /* NUMA_NO_NODE */,
                                 "hero_reader");
    if (!k || (unsigned long)k >= (unsigned long)-4095UL) {
        pr_err("[hero-reader] FATAL: kthread_create_on_node 失败 (%lx)\n",
               (unsigned long)k);
        return -1;   /* loader 会调用 exit 善后 (摘 hook) */
    }
    p_wake_up_process(k);
    g_kthread = k;
    pr_info("[hero-reader] reader kthread=%lx; 就绪 — dmesg | grep hero-reader\n", (unsigned long)k);

    return 0;
}

static long hero_reader_exit(void *reserved)
{
    (void)reserved;
    if (g_kthread) {
        p_kthread_stop(g_kthread);   /* 等待线程真正退出 */
        g_kthread = NULL;
    }
    if (g_hook_installed) {
        hook_unwrap((void *)p_access_process_vm, capture_access_vm, NULL);
        g_hook_installed = 0;
    }
    if (g_target_mm) {               /* 线程已停, 单点释放 */
        p_mmput(g_target_mm);
        g_target_mm = NULL;
    }
    pr_info("[hero-reader] exit (hook calls=%d)\n", g_hook_calls);
    return 0;
}

/* ============================================================
 * ctl0: 用户态控制通道
 * SukiSU: out_msg 恒为 NULL, int 返回值是唯一回传 (ksud 打印 rc);
 * 所有细节写 dmesg。APatch: out_msg 有效, 走兼容分支。
 * ============================================================ */

static long hero_reader_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char resp[256];

    if (!args || !*args)
        args = "status";
    resp[0] = 0;

    if (!strcmp(args, "status") || !strcmp(args, "info")) {
        snprintf(resp, sizeof(resp),
                 "pid=%d mm=%d base=0x%lx sdomain=0x%lx actors=0x%lx-0x%lx heroes=%d hook_calls=%d",
                 g_target_pid, g_target_mm ? 1 : 0, g_base, g_sdomain,
                 g_actor_begin, g_actor_end,
                 g_snapshot.valid ? g_snapshot.count : 0, g_hook_calls);
    } else if (!strcmp(args, "read")) {
        /* reader 线程执行并把结果打进 dmesg — ctl0 不直接碰 mm */
        g_req_read = 1;
        snprintf(resp, sizeof(resp), "read: 立即读取请求已入队 (结果看 dmesg)");
    } else if (!strncmp(args, "set ", 4)) {
        const char *p = args + 4;
        long pidv = 0;
        unsigned long b = 0;

        if (parse_dec(p, &pidv) && pidv > 0) {
            g_req_pid = (pid_t)pidv;
            g_req_pid_valid = 1;
            skip_token(&p);
            if (parse_hex(p, &b) && b) {
                g_req_base = b;
                g_req_base_valid = 1;
                snprintf(resp, sizeof(resp), "set: pid=%ld base=0x%lx 已入队", pidv, b);
            } else {
                snprintf(resp, sizeof(resp), "set: pid=%ld 已入队 (base 待定)", pidv);
            }
        } else {
            snprintf(resp, sizeof(resp), "set: 用法 'set <pid> [base_hex]'");
        }
    } else if (!strncmp(args, "pid ", 4)) {
        const char *p = args + 4;
        long pidv = 0;

        if (parse_dec(p, &pidv) && pidv > 0) {
            g_req_pid = (pid_t)pidv;
            g_req_pid_valid = 1;
            snprintf(resp, sizeof(resp), "pid=%ld 已入队", pidv);
        } else {
            snprintf(resp, sizeof(resp), "pid: 用法 'pid <n>'");
        }
    } else if (!strncmp(args, "base ", 5)) {
        const char *p = args + 5;
        unsigned long b = 0;

        if (parse_hex(p, &b) && b) {
            g_req_base = b;
            g_req_base_valid = 1;
            snprintf(resp, sizeof(resp), "base=0x%lx 已入队", b);
        } else {
            snprintf(resp, sizeof(resp), "base: 用法 'base <hex>'");
        }
    } else if (!strncmp(args, "actors ", 7)) {
        const char *p = args + 7;
        unsigned long b = 0, e = 0;

        if (parse_hex(p, &b)) {
            skip_token(&p);
            if (parse_hex(p, &e) && e > b) {
                g_req_actor_begin = b;
                g_req_actor_end = e;
                g_req_actors_valid = 1;
                snprintf(resp, sizeof(resp), "actors=0x%lx-0x%lx 已入队", b, e);
            } else {
                snprintf(resp, sizeof(resp), "actors: 用法 'actors <起hex> <止hex>'");
            }
        } else {
            snprintf(resp, sizeof(resp), "actors: 用法 'actors <起hex> <止hex>'");
        }
    } else if (!strncmp(args, "peek ", 5)) {
        const char *p = args + 5;
        unsigned long a = 0;
        long cnt = 0;

        if (parse_hex(p, &a) && a) {
            skip_token(&p);
            parse_dec(p, &cnt);
            g_req_peek_addr = a;
            g_req_peek_count = (int)cnt;
            g_req_peek_valid = 1;
            snprintf(resp, sizeof(resp), "peek 0x%lx x%ld 已入队 (结果看 dmesg)", a, cnt);
        } else {
            snprintf(resp, sizeof(resp), "peek: 用法 'peek <地址hex> [个数]'");
        }
    } else if (!strncmp(args, "vma ", 4)) {
        const char *p = args + 4;
        unsigned long a = 0;

        if (parse_hex(p, &a) && a) {
            g_req_vma_addr = a;
            g_req_vma_valid = 1;
            snprintf(resp, sizeof(resp), "vma 0x%lx 探测已入队 (结果看 dmesg)", a);
        } else {
            snprintf(resp, sizeof(resp), "vma: 用法 'vma <地址hex>'");
        }
    } else if (!strcmp(args, "scan")) {
        g_req_scan = 1;
        snprintf(resp, sizeof(resp), "scan: 内核态自动发现已入队 (结果看 dmesg)");
    } else if (!strcmp(args, "find")) {
        g_req_find = 1;
        snprintf(resp, sizeof(resp), "find: 放宽判据候选搜索已入队 (结果看 dmesg)");
    } else if (!strcmp(args, "hunt")) {
        g_req_hunt = 1;
        snprintf(resp, sizeof(resp), "hunt: domain 反查已入队 (结果看 dmesg)");
    } else if (!strcmp(args, "walk")) {
        g_req_walk = 1;
        snprintf(resp, sizeof(resp), "walk: 指针链遍历已入队 (结果看 dmesg)");
    } else if (!strncmp(args, "classes ", 8)) {
        const char *p = args + 8;
        unsigned long a = 0;

        if (parse_hex(p, &a) && a) {
            g_req_classes_addr = a;
            g_req_classes_valid = 1;
            snprintf(resp, sizeof(resp), "classes 0x%lx 探测已入队 (结果看 dmesg)", a);
        } else {
            snprintf(resp, sizeof(resp), "classes: 用法 'classes <image地址hex>'");
        }
    } else if (!strncmp(args, "findclass ", 10)) {
        const char *p = args + 10;
        int l = 0;

        while (*p == ' ')
            p++;
        while (p[l] && l < 39) {
            g_req_fc_name[l] = p[l];
            l++;
        }
        g_req_fc_name[l] = 0;
        g_req_fc_valid = 1;
        snprintf(resp, sizeof(resp), "findclass '%s' 已入队 (结果看 dmesg)", g_req_fc_name);
    } else if (!strncmp(args, "dump ", 5)) {
        const char *p = args + 5;
        unsigned long a = 0;
        long n = 0;

        if (parse_hex(p, &a) && a) {
            skip_token(&p);
            parse_dec(p, &n);
            g_req_dump_addr = a;
            g_req_dump_words = (int)n;
            g_req_dump_valid = 1;
            snprintf(resp, sizeof(resp), "dump 0x%lx x%ld 已入队 (结果看 dmesg)", a, n);
        } else {
            snprintf(resp, sizeof(resp), "dump: 用法 'dump <地址hex> [字数]'");
        }
    } else if (!strcmp(args, "reset")) {
        g_req_reset = 1;
        snprintf(resp, sizeof(resp), "reset 已入队");
    } else {
        snprintf(resp, sizeof(resp),
                 "未知命令: %s (可用: status/read/scan/set/pid/base/actors/peek/reset)", args);
    }

    /* 细节一律进 dmesg (SukiSU 的唯一信息通道) */
    pr_info("[hero-reader] ctl0 [%s] => %s\n", args, resp);

    /* APatch 原生路径才有字符串回传; SukiSU 上 out_msg=NULL → 跳过 */
    if (out_msg && outlen > 0) {
        int len = (int)strlen(resp);

        if (len > outlen - 1)
            len = outlen - 1;
        if (len > 0)
            compat_copy_to_user(out_msg, resp, len + 1);
    }
    return 0;
}

KPM_INIT(hero_reader_init);
KPM_CTL0(hero_reader_ctl0);
KPM_EXIT(hero_reader_exit);
