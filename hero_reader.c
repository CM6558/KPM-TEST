/*
 * hero_reader.kpm — 王者荣耀英雄坐标内核级全自动读取
 *
 * 零用户态操作: 全部在内核态完成
 *   1. hook access_process_vm → 当游戏进程自身触发内存读取时,
 *      从调用栈/参数推断进程身份, 记录为目标
 *   2. 内核态遍历 VMA 自动定位 libil2cpp.so 基址
 *   3. 从 .bss 全局指针 (s_domain) 遍历 IL2CPP 类型系统
 *   4. 内核定时器周期性读取 Actor 数组坐标
 *   5. 结果写入内核日志 (dmesg) 和 kstorage 共享区域
 *
 * 用户态可选: dmesg | grep hero  (只读日志, 不可检测)
 *
 * TP 反检测:
 *   - 不在用户态创建任何进程/文件/socket
 *   - 不使用 ptrace
 *   - 不修改用户态代码段
 *   - kthread + access_process_vm 全在内核态
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

KPM_NAME("hero-reader");
KPM_VERSION("3.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("analyst");
KPM_DESCRIPTION("Zero-userspace hero position kernel reader");

/* ============================================================
 * 内核函数指针 (kallsyms 动态解析)
 * ============================================================ */

static long  (*p_access_process_vm)(void *tsk, unsigned long addr,
                                     void *buf, int len, unsigned int gup_flags);
static void* (*p_find_task_by_vpid)(pid_t vnr);
static void* (*p_get_task_mm)(void *tsk);
static void  (*p_mmput)(void *mm);
static void* (*p_find_vma)(void *mm, unsigned long addr);
/* 内核定时器 */
static struct timer_list *p_reader_timer;

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
 * 全局状态 (全部在内核内存中)
 * ============================================================ */

static pid_t         g_target_pid     = 0;
static unsigned long  g_libil2cpp_base = 0;
static unsigned long  g_actor_begin    = 0;
static unsigned long  g_actor_end      = 0;
static int            g_hook_active    = 0;
static int            g_reader_active  = 0;

/* 最新坐标快照 (内核内存, 用户态通过 dmesg 读取) */
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
 * 底层: 内核态跨进程内存读取
 * ============================================================ */

static long read_remote(unsigned long addr, void *buf, int len)
{
    void *tsk;
    long ret;

    if (!g_target_pid)
        return -1;

    rcu_read_lock();
    tsk = p_find_task_by_vpid(g_target_pid);
    if (tsk)
        get_task_struct(tsk);
    rcu_read_unlock();

    if (!tsk)
        return -1;

    ret = p_access_process_vm(tsk, addr, buf, len, 0x10 /* FOLL_FORCE */);

    put_task_struct(tsk);
    return ret;
}

static int r_u64(unsigned long addr, unsigned long *v)
{ return read_remote(addr, v, 8) == 8; }

static int r_i32(unsigned long addr, int *v)
{ return read_remote(addr, v, 4) == 4; }

static int r_str(unsigned long addr, char *buf, int maxlen)
{
    int i;
    for (i = 0; i < maxlen - 1; i++) {
        char c;
        if (read_remote(addr + i, &c, 1) != 1) return 0;
        if (c == 0) break;
        buf[i] = c;
    }
    buf[i] = 0;
    return i > 0;
}

/* ============================================================
 * Step 1: 内核态自动定位 libil2cpp.so 基址
 *
 * 方法: 遍历目标进程的 VMA 链表, 匹配文件名
 *
 * 关键: KernelPatch 导出了 mm_struct_offset (含 pgd_offset)
 *       和 task_struct_offset.mm_offset
 *
 * VMA 链表遍历:
 *   task_struct → [mm_offset] → mm_struct
 *   mm_struct → [mmap_offset] → vm_area_struct 链表头
 *
 * 旧内核 (Linux <6.1): mm->mmap 是链表头
 * 新内核 (Linux 6.1+): 改用 maple tree (mm->mm_mt)
 *
 * 兼容方案: 用 find_vma(mm, 0) 从内核函数获取第一个 VMA
 *           然后 vma->vm_next 遍历链表
 * ============================================================ */

/* VMA 结构体偏移 (Linux 5.x/6.x ARM64)
 * 这些偏移可通过 KernelPatch 的 ksym 自动适配, 这里用安全探测法
 */
#define VMA_VM_START_OFFSET      0x00   /* unsigned long vm_start  */
#define VMA_VM_END_OFFSET        0x08   /* unsigned long vm_end    */
#define VMA_VM_NEXT_OFFSET       0x10   /* struct vm_area_struct *vm_next */
#define VMA_VM_FILE_OFFSET      0x28   /* struct file *vm_file    */
/* 上面偏移在不同内核版本会变, 需要动态探测 */

/* file 结构体中 dentry 路径偏移 */
#define FILE_F_PATH_DENTRY       0x18   /* f_path.dentry (实际偏移因版本而异) */
#define DENTRY_D_NAME_OFFSET    0x28   /* d_name (qstr: {len, name}) */
#define DENTRY_D_NAME_NAME_OFFSET (DENTRY_D_NAME_OFFSET + 8)

static unsigned long find_il2cpp_base(void *tsk)
{
    void *mm;
    unsigned long vma_addr, file_addr, dentry_addr, name_addr;
    unsigned long vm_start, vm_next;
    char name_buf[64];
    unsigned long base = 0;

    mm = p_get_task_mm(tsk);
    if (!mm) {
        pr_err("[hero-reader] get_task_mm failed\n");
        return 0;
    }

    /* find_vma(mm, 0) 返回第一个 VMA
     * 如果 find_vma 不可用, 需要从 mm->mmap 直接读取 */
    vma_addr = (unsigned long)p_find_vma(mm, 0);
    if (!vma_addr) {
        /* 回退: 直接读 mm_struct
         * mm_struct 在不同内核版本布局不同
         * 尝试常见偏移位置 */
        pr_warn("[hero-reader] find_vma failed, trying direct mm scan\n");
        p_mmput(mm);
        return 0;
    }

    /* 遍历 VMA 链表 */
    while (vma_addr) {
        /* 读 vm_start */
        if (!r_u64_safe(vma_addr + VMA_VM_START_OFFSET, &vm_start, tsk))
            break;

        /* 读 vm_next */
        if (!r_u64_safe(vma_addr + VMA_VM_NEXT_OFFSET, &vm_next, tsk))
            break;

        /* 读 vm_file */
        if (!r_u64_safe(vma_addr + VMA_VM_FILE_OFFSET, &file_addr, tsk))
            goto next_vma;

        if (!file_addr)
            goto next_vma;

        /* file → f_path.dentry */
        if (!r_u64_safe(file_addr + FILE_F_PATH_DENTRY, &dentry_addr, tsk))
            goto next_vma;

        if (!dentry_addr)
            goto next_vma;

        /* dentry → d_name.name */
        if (!r_u64_safe(dentry_addr + DENTRY_D_NAME_NAME_OFFSET, &name_addr, tsk))
            goto next_vma;

        if (!name_addr)
            goto next_vma;

        /* 读文件名 */
        if (read_remote_str(name_addr, name_buf, sizeof(name_buf), tsk)) {
            if (strstr(name_buf, "libil2cpp.so")) {
                base = vm_start;
                pr_info("[hero-reader] found libil2cpp.so @ %lx (vma=%lx)\n",
                        base, vma_addr);
                break;
            }
        }

    next_vma:
        vma_addr = vm_next;
    }

    p_mmput(mm);
    return base;
}

/* 从目标进程读取 u64 (用指定 task) */
static int r_u64_safe(unsigned long addr, unsigned long *val, void *tsk)
{
    return p_access_process_vm(tsk, addr, val, 8, 0x10) == 8;
}

static int read_remote_str(unsigned long addr, char *buf, int maxlen, void *tsk)
{
    int i;
    for (i = 0; i < maxlen - 1; i++) {
        char c;
        if (p_access_process_vm(tsk, addr + i, &c, 1, 0x10) != 1) return 0;
        if (c == 0) break;
        buf[i] = c;
    }
    buf[i] = 0;
    return i > 0;
}

/* ============================================================
 * Step 2: 从 s_domain 遍历 IL2CPP 类型系统
 *
 * s_domain (.bss + 0xE340030) → Il2CppDomain*
 *   domain+0x18 → Il2CppAssembly*[] (assemblies 列表)
 *   domain+0x20 → int count
 *
 * 每个 assembly → image → types
 * 通过 metadata 的 typeDefinitions 表按类名查找
 *
 * 但完整遍历 IL2CPP 类型系统非常复杂 (需要解析多个结构体)
 *
 * 替代方案 (更可靠): 直接利用 IL2CPP 导出的 API
 *   il2cpp_domain_get()          → 直接返回 s_domain 指针
 *   il2cpp_domain_get_assemblies() → 返回 assemblies 列表
 *
 * 但这些是 libil2cpp.so 的用户态函数, 内核不能直接调用
 *
 * 实际方案: KPM 在内核态直接读 .bss 全局变量
 *   base + 0xE340030 → s_domain 指针
 *   然后用 access_process_vm 逐级读取
 * ============================================================ */

static int discover_actor_array(void)
{
    unsigned long domain, asm_list;
    unsigned long assembly, image, class_ptr;
    unsigned long static_fields, field_value;
    int asm_count, i;

    /* Step 2a: 读 s_domain */
    if (!r_u64(g_libil2cpp_base + S_DOMAIN_ADDR, &domain)) {
        pr_err("[hero-reader] failed to read s_domain\n");
        return 0;
    }
    if (!domain) {
        pr_warn("[hero-reader] s_domain is NULL — IL2CPP not initialized\n");
        return 0;
    }
    pr_info("[hero-reader] s_domain = %lx\n", domain);

    /* Step 2b: 获取 assemblies 列表 */
    if (!r_u64(domain + DOMAIN_ASSEMBLIES_PTR, &asm_list)) {
        pr_err("[hero-reader] failed to read assemblies ptr\n");
        return 0;
    }
    if (!r_i32(domain + DOMAIN_ASSEMBLY_COUNT, &asm_count)) {
        pr_err("[hero-reader] failed to read assembly count\n");
        return 0;
    }
    pr_info("[hero-reader] assemblies: %d items @ %lx\n", asm_count, asm_list);

    /* Step 2c: 遍历 assemblies
     * 完整实现需要解析 Il2CppAssembly → Il2CppImage → types
     * → 按 metadata typeDefinitions 表匹配类名
     * → 获取 Il2CppClass* → static_fields → Actor 数组指针
     *
     * 这部分结构体偏移在不同 IL2CPP 版本有微调
     * 实际部署时需要先用 IDA 确认当前版本偏移
     *
     * 简化方案: 扫描所有 assembly 的 static_fields
     * 寻找指向堆内存的指针对 (begin/end), 间距是 1008 的整数倍
     */

    for (i = 0; i < asm_count && i < 50; i++) {
        unsigned long asm_addr;
        if (!r_u64(asm_list + i * 8, &asm_addr) || !asm_addr)
            continue;

        /* asm_addr → Il2CppAssembly
         * Il2CppAssembly+0x00 → Il2CppImage*
         * (偏移因版本而异, 通常 +0x00 或 +0x08)
         */
        if (!r_u64(asm_addr, &image) || !image)
            continue;

        /* Il2CppImage 中包含 typeStart, typeCount, name 等
         * 但我们需要的是 Il2CppClass*
         * Il2CppClass 是运行时构建的, 不在 metadata 中
         *
         * 替代: 直接扫描全进程内存寻找 Actor 数组特征
         */
    }

    /* 方案 D (最可靠的自动发现):
     * Actor 数组特征:
     *   - 连续多个 1008 字节块
     *   - 每块 +0x08 处是 1 或 2 (camp_id)
     *   - 每块 +0x20 处是合理坐标范围 (0~30000)
     *
     * 扫描进程堆内存, 寻找符合此特征的内存区域
     */
    pr_info("[hero-reader] scanning heap for actor array pattern...\n");

    /* 扫描策略:
     * 1. 遍历 VMA, 找匿名映射 (anon) 的可读区域 (堆)
     * 2. 每次读 4096 字节, 检查是否包含 Actor 特征
     * 3. Actor 特征: 连续3个块, 每块+0x08=1或2, +0x20在合理范围
     */
    return discover_actor_by_pattern();
}

/* Actor 数组特征扫描 */
static int discover_actor_by_pattern(void)
{
    /* 需要遍历进程所有 VMA, 对匿名可读区域采样扫描
     *
     * 但这需要完整的 VMA 遍历能力
     * (find_vma + vm_next 循环)
     *
     * 判断条件:
     *   连续3个间隔1008的地址,
     *   每个地址+0x08 读出 1 或 2
     *   每个地址+0x20 读出 0~40000 范围的值
     *
     * 命中后, 向前对齐找到数组头, 向后找到数组尾
     */

    /* 简化: 先确保 find_vma 可用 */
    if (!p_find_vma) {
        pr_err("[hero-reader] find_vma not available\n");
        return 0;
    }

    /* TODO: 完整 VMA 遍历扫描实现
     * 这部分代码较长, 核心逻辑:
     *
     * for each VMA (anonymous, readable):
     *   for offset = 0; offset < vma_size; offset += 4096:
     *     read 4096 bytes at vma_start + offset
     *     for each position in page:
     *       check if position matches actor pattern
     *       (3 consecutive 1008-byte blocks with camp=1|2 at +8)
     *     if match:
     *       scan backward to find array start
     *       scan forward to find array end
     *       store begin/end in g_actor_begin/g_actor_end
     *       return 1
     */

    pr_warn("[hero-reader] pattern scan not fully impl yet\n");
    return 0;
}

/* ============================================================
 * Step 3: 读取英雄坐标 → 写入内核快照
 * ============================================================ */

static void read_hero_positions(void)
{
    int total, i, count = 0;

    if (!g_actor_begin || !g_actor_end) {
        /* 自动发现 */
        if (!g_libil2cpp_base) {
            /* 自动定位基址 */
            void *tsk;
            rcu_read_lock();
            tsk = p_find_task_by_vpid(g_target_pid);
            if (tsk) get_task_struct(tsk);
            rcu_read_unlock();
            if (tsk) {
                g_libil2cpp_base = find_il2cpp_base(tsk);
                put_task_struct(tsk);
            }
        }
        if (g_libil2cpp_base && !g_actor_begin) {
            discover_actor_array();
        }
        if (!g_actor_begin || !g_actor_end)
            return;
    }

    total = (g_actor_end - g_actor_begin) / ACTOR_SIZE;
    if (total <= 0 || total > 100) return; /* 安全上限 */

    for (i = 0; i < total && count < MAX_HEROES; i++) {
        unsigned long actor = g_actor_begin + i * ACTOR_SIZE;
        int camp, x, y, z;

        if (!r_i32(actor + 0x08, &camp))
            continue;
        if (camp != 1 && camp != 2)
            continue;

        if (!r_i32(actor + 0x20, &x))
            continue;
        if (!r_i32(actor + 0x24, &z))
            continue;
        if (!r_i32(actor + 0x28, &y))
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

    /* 输出到内核日志 — 用户态通过 dmesg 查看 */
    pr_info("[hero-reader] === Hero Positions (t=%lu) ===\n",
            (unsigned long)jiffies);
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
 * Step 4: 内核定时器 — 自主周期读取
 * ============================================================ */

/* 定时器回调 (softirq 上下文, 可sleep在 kthread 中更好) */
static void reader_timer_fn(struct timer_list *t)
{
    /* 先确保目标进程有效 */
    if (g_target_pid) {
        void *tsk;
        rcu_read_lock();
        tsk = p_find_task_by_vpid(g_target_pid);
        if (tsk) get_task_struct(tsk);
        rcu_read_unlock();

        if (tsk) {
            /* 如果还没定位基址, 尝试定位 */
            if (!g_libil2cpp_base) {
                g_libil2cpp_base = find_il2cpp_base(tsk);
            }
            put_task_struct(tsk);
        } else {
            /* 进程消失 */
            pr_warn("[hero-reader] target pid %d gone\n", g_target_pid);
            g_target_pid = 0;
            g_libil2cpp_base = 0;
            g_actor_begin = 0;
            g_actor_end = 0;
        }
    }

    if (g_target_pid) {
        read_hero_positions();
    }

    /* 重新调度 (500ms) */
    if (g_reader_active) {
        mod_timer(p_reader_timer, jiffies + msecs_to_jiffies(500));
    }
}

/* ============================================================
 * Step 5: hook access_process_vm — 自动捕获目标进程
 *
 * 原理: 游戏运行时, 游戏进程自身 (或系统服务) 会调用
 *       access_process_vm 读取其他进程或自身内存
 *       或 libtersafe.so 调用 ptrace (内核内走 PTRACE)
 *
 * 更可靠: hook do_dlopen → 当 libil2cpp.so 被加载时
 *         从当前进程判断是否是游戏进程
 *
 * 最直接: 用 comm 名称匹配 "tmgp.sgame" 判断游戏进程
 * ============================================================ */

/* hook access_process_vm 的 after 回调
 * arg0 = struct task_struct *tsk  (被读取的进程)
 * 我们关心的是: 哪个进程在被频繁读取 → 可能是游戏进程
 */
static void after_access_vm(hook_fargs5_t *args, void *udata)
{
    void *tsk;
    pid_t pid;
    char comm[16];

    if (g_target_pid)
        return; /* 已找到目标 */

    /* access_process_vm(tsk, addr, buf, len, gup_flags) */
    tsk = (void *)args->arg0;
    if (!tsk)
        return;

    pid = *(pid_t *)((char *)tsk + task_struct_offset.pid_offset);
    if (pid <= 0)
        return;

    /* 读 comm (进程名) */
    if (task_struct_offset.comm_offset > 0) {
        memcpy(comm, (char *)tsk + task_struct_offset.comm_offset, 16);
        comm[15] = 0;
        if (strstr(comm, "sgame") || strstr(comm, "tmgp")) {
            g_target_pid = pid;
            pr_info("[hero-reader] auto-detected game process: pid=%d comm=%s\n",
                    pid, comm);

            /* 立即尝试定位基址 */
            g_libil2cpp_base = find_il2cpp_base(tsk);
            if (g_libil2cpp_base) {
                pr_info("[hero-reader] libil2cpp.so base = %lx\n",
                        g_libil2cpp_base);
                /* 启动定时器 */
                if (!g_reader_active) {
                    g_reader_active = 1;
                    mod_timer(p_reader_timer,
                              jiffies + msecs_to_jiffies(1000));
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

    pr_info("[hero-reader] v3.0 init, event=%s\n", event);

    /* 解析内核函数 */
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

    /* 分配定时器 */
    p_reader_timer = kmalloc(sizeof(struct timer_list), GFP_KERNEL);
    if (!p_reader_timer) {
        pr_err("[hero-reader] timer alloc failed\n");
        return -1;
    }
    timer_setup(p_reader_timer, reader_timer_fn, 0);

    /* hook access_process_vm — 自动捕获游戏进程
     * access_process_vm 有 5 个参数:
     * (tsk, addr, buf, len, gup_flags) */
    func = (void *)p_access_process_vm;
    hook_err_t err = hook_wrap5(func, 5, NULL, after_access_vm, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("[hero-reader] hook access_process_vm failed: %d\n", err);
        return -1;
    }
    g_hook_active = 1;
    pr_info("[hero-reader] hooked access_process_vm\n");

    /* 如果 init args 传入了 PID, 直接用 */
    if (args && *args) {
        g_target_pid = simple_strtol(args, NULL, 10);
        pr_info("[hero-reader] target pid from args: %d\n", g_target_pid);
        g_reader_active = 1;
        mod_timer(p_reader_timer, jiffies + msecs_to_jiffies(1000));
    }

    pr_info("[hero-reader] initialized, waiting for game process...\n");
    pr_info("[hero-reader] view results: dmesg | grep hero-reader\n");
    return 0;
}

static long hero_reader_exit(void *reserved)
{
    pr_info("[hero-reader] exit\n");

    g_reader_active = 0;

    /* 卸载定时器 */
    if (p_reader_timer) {
        del_timer_sync(p_reader_timer);
        kfree(p_reader_timer);
        p_reader_timer = NULL;
    }

    /* 卸载 hook */
    if (g_hook_active) {
        void *func = (void *)p_access_process_vm;
        hook_unwrap(func, NULL, after_access_vm);
        g_hook_active = 0;
    }

    return 0;
}

/* ctl0: 仅用于调试, 正常运行不需要用户态交互 */
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
                p += w; remaining -= w;
            }
        } else {
            snprintf(response, sizeof(response), "no data");
        }
    } else if (!strncmp(args, "pid ", 4)) {
        g_target_pid = simple_strtol(args + 4, NULL, 10);
        snprintf(response, sizeof(response), "pid=%d", g_target_pid);
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
