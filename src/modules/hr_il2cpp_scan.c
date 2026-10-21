/* hr_il2cpp_scan.c — IL2CPP class/field/static_fields 查找/do_classinfo/do_findfield/do_findstatic/do_fields + 全内存扫描(do_scanseq/do_scanval/do_scanlive/do_findobj) — 最大的诊断模块 */
#include "hr_internal.h"

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
