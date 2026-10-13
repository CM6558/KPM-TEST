#!/bin/sh
# check_kpm.sh — KPM 产物静态自检 (kpm-dev-kit 检查清单做成 CI 门)
#
# 校验项:
#   1. ELF 类型: ET_REL (可重定位) + AArch64
#   2. 必备节: .kpm.info / .kpm.init / .kpm.exit (.kpm.ctl0 可选)
#   3. 未定义符号白名单: kf_* (KP kfunc 桩) + 固定集合 (KP 导出符号)。
#      改动白名单 = 显式新增一条对外部符号的依赖, 必须先在 KP 导出表核对;
#      这正是历史上 "手工 extern snprintf" 之类的坑的拦截门。
#
# 用法: sh scripts/check_kpm.sh [hero_reader.kpm]

set -u

KPM="${1:-hero_reader.kpm}"

READELF="$(command -v llvm-readelf || command -v readelf || true)"
if [ -z "$READELF" ]; then
    echo "check_kpm: 找不到 llvm-readelf / readelf" >&2
    exit 2
fi

[ -f "$KPM" ] || { echo "check_kpm: 文件不存在: $KPM" >&2; exit 2; }

fail=0
die() { printf 'FAIL: %s\n' "$*" >&2; fail=1; }

# ---- 1. ELF 头 ----
hdr="$("$READELF" -h "$KPM")"
echo "$hdr" | grep -q 'Type:.*REL'         || die "ELF 类型不是 REL (需 ET_REL 可重定位)"
echo "$hdr" | grep -q 'Machine:.*AArch64'  || die "Machine 不是 AArch64"

# ---- 2. 节 ----
secs="$("$READELF" -SW "$KPM")"
for s in .kpm.info .kpm.init .kpm.exit; do
    echo "$secs" | grep -q " $s " || die "缺少必备节 $s"
done
echo "$secs" | grep -q ' .kpm.ctl0 ' || echo "note: 无 .kpm.ctl0 (可选节)"

# ---- 3. 未定义符号白名单 ----
# kf_*            : KP kfunc 桩 (linux/string.h、linux/kernel.h 等引入)
# 其余固定集合    : KP 导出表里的符号 (见 SukiSU_KernelPatch_patch 的 KP_EXPORT_SYMBOL)
allow_plain=" task_struct_offset printk kallsyms_lookup_name compat_copy_to_user hook_wrap hook_unwrap_remove "
und="$("$READELF" -sW "$KPM" | awk '$7=="UND" && $8!=""{print $8}' | sort -u)"
if [ -z "$und" ]; then
    die "未定义符号为空 (可疑 — 至少应有 printk / kallsyms_lookup_name)"
else
    for sym in $und; do
        case "$sym" in
            kf_*) ;;
            *)
                case "$allow_plain" in
                    *" $sym "*) ;;
                    *) die "未定义符号不在白名单: $sym (先在 KP 导出表核对, 再更新本脚本的白名单)" ;;
                esac
                ;;
        esac
    done
fi

# ---- 汇总 ----
size=$(wc -c < "$KPM" | tr -d ' ')
echo "check_kpm: $KPM ($size B)"
echo "  ELF: ET_REL / AArch64 — OK"
echo "  .kpm.* 节数: $(echo "$secs" | grep -c '\.kpm\.')"
echo "  UND 符号:"
printf '%s\n' "$und" | sed 's/^/    /'

if [ "$fail" -ne 0 ]; then
    echo "check_kpm: 未通过" >&2
    exit 1
fi
echo "check_kpm: 全部通过"
