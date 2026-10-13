#!/system/bin/sh
# vt-drive.sh — 设备侧驱动脚本：一条命令完成"取 pid/基址 → set → 执行命令"
#
# 用法（root）:
#   su -c 'sh /data/local/tmp/vt-drive.sh walk'
#   su -c 'sh /data/local/tmp/vt-drive.sh findclass Actor|Hero'
#   su -c 'sh /data/local/tmp/vt-drive.sh dump 0x6e9df83ea0 16'
#   su -c 'sh /data/local/tmp/vt-drive.sh scan'
#   su -c 'sh /data/local/tmp/vt-drive.sh log'
#
# 说明:
#   - 游戏会重启, 每次调用都重新取 pid 与 base, 不需要手工维护。
#   - base 算法: maps 里 libil2cpp 的第二处 file_off=0 映射 (r-xp 起点 − 0x3a84000)。
#   - 结果一律在 dmesg (SukiSU 上 ctl0 无字符串回传)。

KPM=hero-reader
GAME=${GAME:-com.tencent.tmgp.sgame}
KSUD=/data/adb/ksud
TEXT_OFF=0x3a84000          # .text 的 vaddr (本版本 libil2cpp)

[ "$(id -u)" = "0" ] || { echo "需要 root: su -c 'sh $0 ...'"; exit 1; }

game_pid() { pidof "$GAME" 2>/dev/null | tr ' ' '\n' | head -n 1; }

# 内核/用户态都能读到 maps 时用它算 base; 失败则让核心自己定位
game_base() {
    PID=$1
    RX=$(grep 'libil2cpp\.so' /proc/$PID/maps 2>/dev/null | grep ' r-xp ' | head -n 1 | cut -d'-' -f1)
    [ -n "$RX" ] || return 1
    # shell 十六进制减法 (Android toybox sh 支持 $(( )) 的 16 进制)
    printf '0x%x' $(( 0x$RX - $TEXT_OFF ))
}

CTL="$1"; shift 2>/dev/null
[ -n "$CTL" ] || CTL=status

if [ "$CTL" = "log" ]; then
    dmesg | grep 'hero-reader' | tail -n "${1:-30}"
    exit 0
fi

PID=$(game_pid)
[ -n "$PID" ] || { echo "游戏未运行 ($GAME)"; exit 1; }
BASE=$(game_base "$PID")
echo "pid=$PID base=${BASE:-<内核自定>}"

if [ -n "$BASE" ]; then
    $KSUD kpm control "$KPM" "set $PID $BASE" >/dev/null
else
    $KSUD kpm control "$KPM" "set $PID" >/dev/null
fi
sleep 3

$KSUD kpm control "$KPM" "$CTL $*"
echo "已下发: $CTL $*  (结果看 dmesg)"
