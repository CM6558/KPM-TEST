#!/system/bin/sh
# vt-drive.sh — 设备侧驱动脚本 (v5)
#
# 用法（root）:
#   su -c 'sh /data/local/tmp/vt-drive.sh dumpmeta'    # 完整转储 global-metadata.dat
#   su -c 'sh /data/local/tmp/vt-drive.sh findmeta'
#   su -c 'sh /data/local/tmp/vt-drive.sh walk'
#   su -c 'sh /data/local/tmp/vt-drive.sh findclass Actor|Hero'
#   su -c 'sh /data/local/tmp/vt-drive.sh log 30'
#
# 说明:
#   - 游戏会重启, 每次调用都自动重新取 pid 并 set。
#   - base 由内核自己定位 (s_domain 结构体 + 校验), 这里不再手工计算。
#   - 结果一律在 dmesg (SukiSU 上 ctl0 无字符串回传)。

KPM=hero-reader
GAME=${GAME:-com.tencent.tmgp.sgame}
KSUD=/data/adb/ksud

[ "$(id -u)" = "0" ] || { echo "需要 root: su -c 'sh $0 ...'"; exit 1; }

game_pid() { pidof "$GAME" 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+$' | head -n 1; }

CTL="$1"; shift 2>/dev/null
[ -n "$CTL" ] || CTL=status

if [ "$CTL" = "log" ]; then
    dmesg | grep 'hero-reader' | tail -n "${1:-30}"
    exit 0
fi

PID=$(game_pid)
[ -n "$PID" ] || { echo "游戏未运行 ($GAME)"; exit 1; }
echo "pid=$PID"

$KSUD kpm control "$KPM" "set $PID" >/dev/null
# 等 reader 线程锁定 mm (通常 <1s)
sleep 2

$KSUD kpm control "$KPM" "$CTL $*"
echo "已下发: $CTL $*  (结果看 dmesg: sh $0 log)"
