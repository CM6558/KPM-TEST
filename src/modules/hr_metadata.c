/* hr_metadata.c — IL2CPP metadata 验证/大小/转储 */
#include "hr_internal.h"

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
