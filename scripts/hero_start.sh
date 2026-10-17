#!/system/bin/sh
# ============================================================
# Hero 一键启动 (root)。App 需你手动打开并点「启动悬浮窗」。
#
#   sh /data/local/tmp/hero_start.sh           # 启动; 若已在运行 → 先停止再重启 (默认)
#   sh /data/local/tmp/hero_start.sh 300       # 指定周期 ms (默认 200)
#   sh /data/local/tmp/hero_start.sh keep      # 已在运行则保持不变 (不重启)
#   sh /data/local/tmp/hero_start.sh stop      # 停止全部
#   sh /data/local/tmp/hero_start.sh status    # 看状态
# ============================================================
MOD=/data/local/tmp/hero_reader.kpm
BIN=/data/local/tmp/heroes.bin
BRIDGE=/data/local/tmp/hero_bridge
LOG=/data/local/tmp/hero.log
DPID=/data/local/tmp/hero_daemon.pid
BPID=/data/local/tmp/hero_bridge.pid
GAME=com.tencent.tmgp.sgame
GAME_COMM=$GAME                 # 传完整包名; 模块内部按 comm 后 15 位比对
PORT=8787
KSUD=/data/adb/ksud
MNAME=$(cat /data/local/tmp/hero_mod.name 2>/dev/null); [ -z "$MNAME" ] && MNAME="hero-reader"

mod_loaded() { "$KSUD" kpm list 2>/dev/null | grep -qx "$MNAME"; }
# 游戏 pid 不再用用户态 pidof: 由模块遍历内核 task 链表定位 (setcomm)

# 幂等加载: 同名可能残留多条(历史重复加载), 先循环卸载到干净再加载
# 循环卸载到名字彻底消失 (同名可能有多条记录)
unload_all() {
    i=0
    while [ $i -lt 8 ]; do
        "$KSUD" kpm list 2>/dev/null | grep -qx "$MNAME" || return 0
        "$KSUD" kpm unload "$MNAME" >/dev/null 2>&1
        sleep 0.5
        i=$((i+1))
    done
    "$KSUD" kpm list 2>/dev/null | grep -qx "$MNAME" && return 1
    return 0
}

# 幂等加载: 先清干净再加载, 避免同名多条
ensure_loaded() {
    [ -x "$KSUD" ] || return 0
    unload_all
    "$KSUD" kpm load "$MOD" >/dev/null 2>&1
}
ts()         { date '+%H:%M:%S'; }
daemon_alive() { [ -f "$DPID" ] && kill -0 "$(cat "$DPID" 2>/dev/null)" 2>/dev/null; }

########################################################################
# 守护本体 (后台): 等游戏 → set pid → herobin → 保活桥接 → 游戏重启自动重设
########################################################################
if [ "$1" = --daemon ]; then
    IV=${2:-200}
    echo $$ > "$DPID"
    trap 'p=$(cat "$DPID" 2>/dev/null); [ "$p" = "$$" ] && rm -f "$DPID"; exit 0' TERM INT
    ensure_loaded
    echo "[$(ts)] 守护启动, 周期 ${IV}ms, 游戏 $GAME (内核态定位 $GAME_COMM)"
    CUR=""
    while :; do
        # 注意: 这里绝不能 ensure_loaded(它会先卸载), 否则每秒重装模块
        mod_loaded || "$KSUD" kpm load "$MOD" >/dev/null 2>&1
        # setcomm 幂等: 同名不会重置状态; 模块会自己处理游戏重启/pid 复用
        "$KSUD" kpm control "$MNAME" "setcomm $GAME_COMM" >/dev/null 2>&1
        if [ "$CUR" != "1" ]; then
            "$KSUD" kpm control "$MNAME" "herobin $BIN $IV" >/dev/null 2>&1
            echo "[$(ts)] 内核定位 $GAME_COMM, herobin ${IV}ms"
            CUR=1
        fi
        if ! pidof hero_bridge >/dev/null 2>&1; then
            setsid "$BRIDGE" "$BIN" "$PORT" >/dev/null 2>&1 </dev/null &
            echo $! > "$BPID"
            echo "[$(ts)] 桥接已起 ws://127.0.0.1:$PORT/ws"
        fi
        sleep 2
    done
fi

########################################################################
# 停止
########################################################################
do_stop() {
    "$KSUD" kpm control "$MNAME" 'herobin stop' >/dev/null 2>&1
    if [ -f "$DPID" ]; then kill "$(cat "$DPID")" 2>/dev/null; rm -f "$DPID"; fi
    pkill -f "hero_start.sh --daemon" >/dev/null 2>&1
    "$KSUD" kpm unload "$MNAME" >/dev/null 2>&1
    if [ -f "$BPID" ]; then kill "$(cat "$BPID")" 2>/dev/null; rm -f "$BPID"; fi
    pkill -x hero_bridge >/dev/null 2>&1
    echo "已停止: herobin / 模块 / 桥接 / 守护"
}

case "$1" in
stop)   do_stop; exit 0;;
status)
    BINPID=$(od -An -tu4 -j 36 -N 4 "$BIN" 2>/dev/null | tr -d ' ')
    if [ -z "$BINPID" ] || [ "$BINPID" = 0 ]; then
        # bin 只在局内刷新; 局外直接让模块做一次内核态 findpid, 从日志取结果
        "$KSUD" kpm control "$MNAME" 'diag on' >/dev/null 2>&1
        "$KSUD" kpm control "$MNAME" "findpid $GAME_COMM" >/dev/null 2>&1
        sleep 1
        BINPID=$(dmesg 2>/dev/null | grep "findpid '$GAME_COMM' ->" | tail -1 | sed "s/.*-> \\([0-9]*\\).*/\\1/")
    fi
    echo "模块 num : $("$KSUD" kpm num 2>/dev/null)"
    echo "游戏 pid : ${BINPID:-?}  (内核态定位)"
    echo "守护 pid : $(cat "$DPID" 2>/dev/null)"
    echo "桥接 pid : $(pidof hero_bridge)"
    echo "bin 文件 : $(ls -l "$BIN" 2>/dev/null)"
    echo "bin 时间 : $(stat -c %y "$BIN" 2>/dev/null)"
    exit 0;;
esac

# 参数: [周期ms] [keep]
KEEP=0; IV=200
for a in "$@"; do
    case "$a" in
        keep)     KEEP=1 ;;
        '')       : ;;
        *[!0-9]*) : ;;
        *)        IV=$a ;;
    esac
done

# 默认重启: 已有 hero 进程/模块就先停再起; 'keep' 则保持现状
if [ "$KEEP" = 1 ]; then
    if daemon_alive; then
        echo "已在运行, 保持不变 (keep)"
        sh "$0" status
        exit 0
    fi
elif mod_loaded || pidof hero_bridge >/dev/null 2>&1 || daemon_alive; then
    echo "检测到已在运行 → 先停止再重启 (加 'keep' 可保持不变)"
    do_stop
    sleep 1
fi

# 后台起守护 (setsid: 脱离当前会话, 父 shell 退出后不会被杀)
setsid sh "$0" --daemon "$IV" >>"$LOG" 2>&1 </dev/null &
sleep 2
echo "已在后台启动 (周期 ${IV}ms)。日志: $LOG"
echo "现在请打开 App 并点「启动悬浮窗」。"
tail -n 6 "$LOG" 2>/dev/null
