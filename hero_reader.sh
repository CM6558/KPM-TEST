#!/system/bin/sh
# hero_reader.sh — 设备侧驱动脚本: 加载 / 控制 / 卸载 hero_reader.kpm
#
# 用法 (root):
#   su -c 'sh /data/local/tmp/hero_reader.sh start'    # 加载模块 + 立即接管游戏进程
#   su -c 'sh /data/local/tmp/hero_reader.sh stop'     # 彻底卸载 (摘 hook / 停线程 / 放 mm)
#   su -c 'sh /data/local/tmp/hero_reader.sh status'   # 模块状态 + 最近日志
#   su -c 'sh /data/local/tmp/hero_reader.sh watch'    # 持续看结果 (Ctrl+C 退出)
#
# 前置: KernelPatch / SukiSU (ksud kpm 可用) + /data/local/tmp/hero_reader.kpm
#
# 注意 (SukiSU 实测口径):
#   - 现代 SukiSU 上 ctl0 没有字符串回传, ksud 只打印 int 返回码;
#     所有结果以 dmesg 为准 (本脚本已内置 dmesg 回显)。
#   - start 会尽量自动完成: 找游戏 pid + 从 /proc/PID/maps 读 libil2cpp.so 基址 →
#     ctl0 'set <pid> <base>'。读不到 maps 时只发 pid, 基址由模块内核侧自行定位。
#   - 游戏未运行时也无需等待: 模块 hook 会在游戏启动后自动捕获目标。

KPM_NAME=hero-reader
KPM_FILE=${KPM_FILE:-/data/local/tmp/hero_reader.kpm}
GAME=${GAME:-com.tencent.tmgp.sgame}
TAG='[hero-reader-ctl]'

if [ "$(id -u)" != "0" ]; then
    echo "$TAG 需要 root: su -c 'sh $0 $*'"
    exit 1
fi

KSUD=''
for p in /data/adb/ksud /data/adb/kpatch/ksud; do
    if [ -x "$p" ]; then
        KSUD="$p"
        break
    fi
done
if [ -z "$KSUD" ]; then
    if command -v ksud >/dev/null 2>&1; then
        KSUD=ksud
    fi
fi
if [ -z "$KSUD" ]; then
    echo "$TAG 找不到 ksud (KernelSU/SukiSU 未安装?)"
    exit 1
fi

kpm() { "$KSUD" kpm "$@"; }

dmesg_tail() {
    dmesg | grep 'hero-reader' | tail -n "${1:-12}"
}

find_game_pid() {
    pidof "$GAME" 2>/dev/null | tr ' ' '\n' | head -n 1
}

# 从 /proc/PID/maps 读 libil2cpp.so 首个映射的起始地址 (root shell 可能受
# SELinux 限制; 失败时返回空, 交给模块内核侧自行定位)。
find_base_for_pid() {
    grep 'libil2cpp\.so' "/proc/$1/maps" 2>/dev/null | head -n 1 | cut -d'-' -f1
}

CMD=${1:-status}

case "$CMD" in
start)
    if kpm list 2>/dev/null | grep -q "$KPM_NAME"; then
        echo "$TAG 模块已在加载列表 — 先卸载再重载"
        kpm unload "$KPM_NAME" 2>/dev/null
    fi
    echo "$TAG 加载 $KPM_FILE ..."
    if ! kpm load "$KPM_FILE"; then
        echo "$TAG 加载失败 (rc != 0) — 原因看 dmesg:"
        dmesg_tail 20
        exit 1
    fi
    sleep 1
    if ! kpm list 2>/dev/null | grep -q "$KPM_NAME"; then
        echo "$TAG 加载命令返回成功但模块不在列表 — 原因看 dmesg:"
        dmesg_tail 20
        exit 1
    fi
    echo "$TAG 已加载"

    PID=$(find_game_pid)
    if [ -n "$PID" ]; then
        BASE=$(find_base_for_pid "$PID")
        if [ -n "$BASE" ]; then
            echo "$TAG 游戏 pid=$PID base=0x$BASE — 下发 'set'"
            kpm control "$KPM_NAME" "set $PID 0x$BASE"
        else
            echo "$TAG 游戏 pid=$PID; shell 读不到 maps (SELinux?) — 只发 pid, 基址由内核侧定位"
            kpm control "$KPM_NAME" "set $PID"
        fi
        sleep 1
    else
        echo "$TAG 游戏未运行 — hook 会在游戏启动后自动捕获 (或稍后重跑 start)"
    fi
    echo "$TAG 状态:"
    dmesg_tail 10
    ;;

stop)
    kpm control "$KPM_NAME" "reset" 2>/dev/null
    if kpm unload "$KPM_NAME" 2>/dev/null; then
        echo "$TAG 已卸载"
    else
        echo "$TAG 卸载失败 (模块本就未加载?)"
    fi
    if kpm list 2>/dev/null | grep -q "$KPM_NAME"; then
        echo "$TAG 警告: 模块仍在列表中"
        exit 1
    fi
    dmesg_tail 5
    ;;

status)
    kpm list 2>/dev/null | grep "$KPM_NAME" || echo "$TAG 模块未加载"
    kpm control "$KPM_NAME" "status" 2>/dev/null
    sleep 1
    dmesg_tail 15
    ;;

watch)
    echo "$TAG 持续输出 (Ctrl+C 退出):"
    while :; do
        dmesg | grep 'hero-reader' | tail -n 25
        echo "-- $(date '+%H:%M:%S') --"
        sleep 2
    done
    ;;

*)
    echo "用法: sh $0 start|stop|status|watch"
    exit 1
    ;;
esac
