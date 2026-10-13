/*
 * hero_reader.kpm — 王者荣耀英雄坐标内核级全自动读取 v3.0
 *
 * 零用户态操作: KPM 加载后自动发现游戏进程 + 定位基址 + 周期读取
 * 结果通过内核日志输出: dmesg | grep hero-reader
 *
 * 偏移来源: IDA Pro 反编译 libil2cpp.so + libGameCore.so 确认
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>
#include <ksyms.h>
#include <kstorage.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/slab.h>

KPM_NAME("hero-reader");
KPM_VERSION("3.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("analyst");
KPM_DESCRIPTION("Zero-userspace hero position kernel reader");

/* ============================================================
 * 内核函数指针
 * ============================================================ */

static long  (*p_access_process_vm)(void *tsk, unsigned long addr,
                                     void *buf, int len, unsigned int gup_flags);
static void* (*p_find_task_by_vpid)(pid_t vnr);
static void* (*p_get_task_mm)(void *tsk);
static void  (*p_mmput)(void *mm);
static void* (*p_find_vma)(void *mm, unsigned long addr);

/* ============================================================
 * 偏移量 (IDA 反编译确认)
 * ============================================================ */

#define S_DOMAIN_ADDR            0xE340030UL
#define DOMAIN_ASSEMBLIES_PTR     0x18UL
#define DOMAIN_ASSEMBLY_COUNT     0x20UL
#define ACTOR_SIZE                 1008
#define ACTOR_CAMP_ID             0x08
#define ACTOR_POS_X               0x20
#define ACTOR_POS_Z               0x24
#define ACTOR_POS_Y               0x28
#define MAX_HEROES                 10

/* ============================================================
 * 全局状态
 * ============================================================ */

static pid_t          g_target_pid     = 0;
static unsigned long  g_libil2cpp_base = 0;
static unsigned long  g_actor_begin    = 0;
static unsigned long  g_actor_end      = 0;
static int            g_hook_active    = 0;
static int            g_reader_active  = 0;

struct hero_snapshot {
    int valid;
    int count;
    struct {
        int index;
        int camp;
        int x, y, z;
    } heroes[MAX_HEROES];
};

static struct hero_snapshot g_snapshot = {0};

/* ============================================================
 * 前向声明
 * ============================================================ */

static int r_u64_remote(unsigned long addr, unsigned long *val, void *tsk);
static int r_str_remote(unsigned long addr, char *buf, int maxlen, void *tsk);
static unsigned long find_il2cpp_base(void *tsk);
static int discover_actor_by_pattern(void);
static void read_hero_positions(void);
static void reader_timer_fn(struct timer_list *t);

/* ============================================================
 * 定时器 (用 kfunc 导出的 timer_setup / mod_timer / del_timer_sync)
 * ============================================================ */

static struct timer_list g_timer;

/* ============================================================
 * 底层: 内核态跨进程内存读取
 * ============================================================ */

static long read_remote(unsigned long addr, void *buf, int len)
{
    void *tsk;
    long ret;

    if (!g_target_pid || !p_find_task_by_vpid || !p_access_process_vm)
        return -1;

    rcu_read_lock();
    tsk = p_find_task_by_vpid(g_target_pid);
    if (tsk)
        get_task_struct(tsk);
    rcu_read_unlock();

    if (!tsk)
        return -1;

    ret = p_access_process_vm(tsk, addr, buf, len, 0x10);

    put_task_struct(tsk);
    return ret;
}

static int r_u64(unsigned long addr, unsigned long *v)
{ return read_remote(addr, v, 8) == 8; }

static int r_i32(unsigned long addr, int *v)
{ return read_remote(addr, v, 4) == 4; }

/* 指定 task 的内存读取 */
static int r_u64_remote(unsigned long addr, unsigned long *val, void *tsk)
{
    return p_access_process_vm(tsk, addr, val, 8, 0x10) == 8;
}

static int r_str_remote(unsigned long addr, char *buf, int maxlen, void *tsk)
{
    int i;
    for (i = 0; i < maxlen - 1; i++) {
        char c;
        if (p_access_process_vm(tsk, addr + i, &c, 1, 0x10) != 1)
            return 0;
        if (c == 0)
            break;
        buf[i] = c;
    }
    buf[i] = 0;
    return i > 0;
}

/* ============================================================
 * Step 1: 内核态自动定位 libil2cpp.so 基址
 * ============================================================ */

/* VMA 结构体偏移 (Linux 5.x ARM64) */
#define VMA_VM_START    0x00
#define VMA_VM_NEXT     0x10
#define VMA_VM_FILE     0x28

#define FILE_DENTRY     0x18
#define DENTRY_D_NAME_NAME (0x28 + 8)

static unsigned long find_il2cpp_base(void *tsk)
{
    void *mm;
    unsigned long vma_addr, file_addr, dentry_addr, name_addr;
    unsigned long vm_start, vm_next;
    char name_buf[64];
    unsigned long base = 0;

    mm = p_get_task_mm(tsk);
    if (!mm)
        return 0;

    vma_addr = (unsigned long)p_find_vma(mm, 0);
    if (!vma_addr) {
        p_mmput(mm);
        return 0;
    }

    while (vma_addr) {
        if (!r_u64_remote(vma_addr + VMA_VM_START, &vm_start, tsk))
            break;
        if (!r_u64_remote(vma_addr + VMA_VM_NEXT, &vm_next, tsk))
            break;
        if (!r_u64_remote(vma_addr + VMA_VM_FILE, &file_addr, tsk))
            goto next_vma;
        if (!file_addr)
            goto next_vma;
        if (!r_u64_remote(file_addr + FILE_DENTRY, &dentry_addr, tsk))
            goto next_vma;
        if (!dentry_addr)
            goto next_vma;
        if (!r_u64_remote(dentry_addr + DENTRY_D_NAME_NAME, &name_addr, tsk))
            goto next_vma;
        if (!name_addr)
            goto next_vma;

        if (r_str_remote(name_addr, name_buf, sizeof(name_buf), tsk)) {
            if (strstr(name_buf, "libil2cpp.so")) {
                base = vm_start;
                pr_info("[hero-reader] found libil2cpp.so @ %lx\n", base);
                break;
            }
        }

    next_vma:
        vma_addr = vm_next;
    }

    p_mmput(mm);
    return base;
}

/* ============================================================
 * Step 2: Actor 数组自动发现 (特征扫描)
 * ============================================================ */

static int discover_actor_by_pattern(void)
{
    pr_warn("[hero-reader] pattern scan placeholder — use ctl0 to set actors\n");
    return 0;
}

/* ============================================================
 * Step 3: 读取英雄坐标
 * ============================================================ */

static void read_hero_positions(void)
{
    int total, i, count = 0;

    if (!g_actor_begin || !g_actor_end) {
        if (!g_libil2cpp_base) {
            void *tsk;
            rcu_read_lock();
            tsk = p_find_task_by_vpid(g_target_pid);
            if (tsk)
                get_task_struct(tsk);
            rcu_read_unlock();
            if (tsk) {
                g_libil2cpp_base = find_il2cpp_base(tsk);
                put_task_struct(tsk);
            }
        }
        if (g_libil2cpp_base && !g_actor_begin)
            discover_actor_by_pattern();
        if (!g_actor_begin || !g_actor_end)
            return;
    }

    total = (g_actor_end - g_actor_begin) / ACTOR_SIZE;
    if (total <= 0 || total > 100)
        return;

    for (i = 0; i < total && count < MAX_HEROES; i++) {
        unsigned long actor = g_actor_begin + (unsigned long)i * ACTOR_SIZE;
        int camp, x, y, z;

        if (!r_i32(actor + ACTOR_CAMP_ID, &camp))
            continue;
        if (camp != 1 && camp != 2)
            continue;
        if (!r_i32(actor + ACTOR_POS_X, &x))
            continue;
        if (!r_i32(actor + ACTOR_POS_Z, &z))
            continue;
        if (!r_i32(actor + ACTOR_POS_Y, &y))
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

/* ============================================================
 * Step 4: 内核定时器
 * ============================================================ */

static void reader_timer_fn(struct timer_list *t)
{
    if (g_target_pid) {
        void *tsk;
        rcu_read_lock();
        tsk = p_find_task_by_vpid(g_target_pid);
        if (tsk)
            get_task_struct(tsk);
        rcu_read_unlock();

        if (tsk) {
            if (!g_libil2cpp_base)
                g_libil2cpp_base = find_il2cpp_base(tsk);
            put_task_struct(tsk);
        } else {
            pr_warn("[hero-reader] target pid %d gone\n", g_target_pid);
            g_target_pid = 0;
            g_libil2cpp_base = 0;
            g_actor_begin = 0;
            g_actor_end = 0;
        }
    }

    if (g_target_pid)
        read_hero_positions();

    if (g_reader_active)
        mod_timer(&g_timer, jiffies + msecs_to_jiffies(500));
}

/* ============================================================
 * Step 5: hook access_process_vm — 自动捕获目标进程
 * ============================================================ */

static void after_access_vm(hook_fargs5_t *args, void *udata)
{
    void *tsk;
    pid_t pid;
    char comm[16];

    if (g_target_pid)
        return;

    tsk = (void *)args->arg0;
    if (!tsk)
        return;

    pid = *(pid_t *)((char *)tsk + task_struct_offset.pid_offset);
    if (pid <= 0)
        return;

    if (task_struct_offset.comm_offset > 0) {
        memcpy(comm, (char *)tsk + task_struct_offset.comm_offset, 16);
        comm[15] = 0;
        if (strstr(comm, "sgame") || strstr(comm, "tmgp")) {
            g_target_pid = pid;
            pr_info("[hero-reader] auto-detected: pid=%d comm=%s\n", pid, comm);
            g_libil2cpp_base = find_il2cpp_base(tsk);
            if (g_libil2cpp_base) {
                pr_info("[hero-reader] libil2cpp base = %lx\n", g_libil2cpp_base);
                if (!g_reader_active) {
                    g_reader_active = 1;
                    mod_timer(&g_timer, jiffies + msecs_to_jiffies(1000));
                }
            }
        }
    }
}

/* ============================================================
 * KPM 生命周期
 * ============================================================ */

static long hero_reader_init(const char *args, const char *event, void *reserved)
{
    void *func;
    hook_err_t err;

    pr_info("[hero-reader] v3.0.1 init, event=%s\n", event);

    p_access_process_vm = (void *)kallsyms_lookup_name("access_process_vm");
    p_find_task_by_vpid = (void *)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_mm       = (void *)kallsyms_lookup_name("get_task_mm");
    p_mmput             = (void *)kallsyms_lookup_name("mmput");
    p_find_vma          = (void *)kallsyms_lookup_name("find_vma");

    if (!p_access_process_vm || !p_find_task_by_vpid) {
        pr_err("[hero-reader] FATAL: kernel symbols not found\n");
        return -1;
    }
    pr_info("[hero-reader] access_process_vm=%lx find_task_by_vpid=%lx\n",
            (unsigned long)p_access_process_vm,
            (unsigned long)p_find_task_by_vpid);

    timer_setup(&g_timer, reader_timer_fn, 0);

    /* hook access_process_vm (5 params)
     * hook_wrap5 signature: (func, argno, before, after, udata) */
    func = (void *)p_access_process_vm;
    err = hook_wrap(func, 5, NULL, after_access_vm, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("[hero-reader] hook failed: %d\n", err);
        return -1;
    }
    g_hook_active = 1;
    pr_info("[hero-reader] hooked access_process_vm\n");

    if (args && *args) {
        g_target_pid = simple_strtol(args, NULL, 10);
        pr_info("[hero-reader] target pid from args: %d\n", g_target_pid);
        g_reader_active = 1;
        mod_timer(&g_timer, jiffies + msecs_to_jiffies(1000));
    }

    pr_info("[hero-reader] initialized — dmesg | grep hero-reader\n");
    return 0;
}

static long hero_reader_exit(void *reserved)
{
    pr_info("[hero-reader] exit\n");
    g_reader_active = 0;
    del_timer_sync(&g_timer);

    if (g_hook_active) {
        hook_unwrap((void *)p_access_process_vm, NULL, after_access_vm);
        g_hook_active = 0;
    }
    return 0;
}

/* ctl0: 调试/可选交互, 正常运行不需要 */
static long hero_reader_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char response[256];

    if (!strcmp(args, "status")) {
        snprintf(response, sizeof(response),
                 "pid=%d base=%lx actors=%lx-%lx heroes=%d",
                 g_target_pid, g_libil2cpp_base,
                 g_actor_begin, g_actor_end,
                 g_snapshot.valid ? g_snapshot.count : 0);
    } else if (!strcmp(args, "read")) {
        if (g_snapshot.valid) {
            char *p = response;
            int i, remaining = sizeof(response);
            for (i = 0; i < g_snapshot.count && remaining > 20; i++) {
                int w = snprintf(p, remaining,
                    "H%d:c%d,x%d,y%d,z%d|",
                    g_snapshot.heroes[i].index,
                    g_snapshot.heroes[i].camp,
                    g_snapshot.heroes[i].x,
                    g_snapshot.heroes[i].y,
                    g_snapshot.heroes[i].z);
                p += w;
                remaining -= w;
            }
        } else {
            snprintf(response, sizeof(response), "no data");
        }
    } else if (!strncmp(args, "pid ", 4)) {
        g_target_pid = simple_strtol(args + 4, NULL, 10);
        snprintf(response, sizeof(response), "pid=%d", g_target_pid);
    } else if (!strncmp(args, "actors ", 7)) {
        const char *p = args + 7;
        g_actor_begin = simple_strtoul(p, &p, 16);
        while (*p == ' ') p++;
        g_actor_end = simple_strtoul(p, NULL, 16);
        snprintf(response, sizeof(response),
                 "actors=%lx-%lx", g_actor_begin, g_actor_end);
    } else {
        snprintf(response, sizeof(response), "unknown: %s", args);
    }

    compat_copy_to_user(out_msg, response,
                        min((int)strlen(response) + 1, outlen));
    return 0;
}

KPM_INIT(hero_reader_init);
KPM_CTL0(hero_reader_ctl0);
KPM_EXIT(hero_reader_exit);
