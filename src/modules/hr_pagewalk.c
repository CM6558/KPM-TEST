/* hr_pagewalk.c — 页表 walk + VMA 遍历 + ELF base 定位 */
#include "hr_internal.h"

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
