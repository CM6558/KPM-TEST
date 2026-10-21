#!/system/bin/sh
# ============================================================
# Hero 一键结束 (root)：先清理硬件断点 → 停 herobin → 停守护 → 卸载模块(重试)
#
#   sh /data/local/tmp/hero_stop.sh          # 停止全部
#   sh /data/local/tmp/hero_stop.sh clean    # 停止并删除 heroes.bin
# ============================================================
BIN=/data/local/tmp/heroes.bin
DPID=/data/local/tmp/hero_daemon.pid
BPID=/data/local/tmp/hero_bridge.pid
KSUD=/data/adb/ksud
MNAME=$(cat /data/local/tmp/hero_mod.name 2>/dev/null); [ -z "$MNAME" ] && MNAME="hero-reader"

echo "== 停止 Hero =="

# 0) 先注销所有硬件断点（必须在卸载模块之前，否则模块引用被占住卸不掉）
"$KSUD" kpm control "$MNAME" 'diag on' >/dev/null 2>&1
"$KSUD" kpm control "$MNAME" 'hwbp off' >/dev/null 2>&1
sleep 1

# 1) 模块周期写
"$KSUD" kpm control "$MNAME" 'herobin stop' >/dev/null 2>&1 && echo "· herobin 已停"

# 2) 守护进程
if [ -f "$DPID" ]; then
    kill "$(cat "$DPID")" 2>/dev/null && echo "· 守护已停 (pid $(cat "$DPID"))"
    rm -f "$DPID"
fi
pkill -f "hero_start.sh --daemon" >/dev/null 2>&1
sleep 1

# 3) 卸载模块: 循环到名字彻底消失
i=0
while [ $i -lt 8 ] && "$KSUD" kpm list 2>/dev/null | grep -qx "$MNAME"; do
    "$KSUD" kpm unload "$MNAME" >/dev/null 2>&1
    sleep 0.5
    i=$((i+1))
done
if "$KSUD" kpm list 2>/dev/null | grep -qx "$MNAME"; then
    echo "· !! 模块仍在内核中"
else
    echo "· 模块已卸载"
fi

# 4) 桥接
if [ -f "$BPID" ]; then kill "$(cat "$BPID")" 2>/dev/null; rm -f "$BPID"; fi
pkill -x hero_bridge >/dev/null 2>&1 && echo "· 桥接已停"

# 5) 可选清文件
if [ "$1" = clean ]; then rm -f "$BIN" && echo "· 已删除 $BIN"; fi

echo "--- 复查 ---"
echo "模块 num : $("$KSUD" kpm num 2>/dev/null)"
echo "守护 pid : $(cat "$DPID" 2>/dev/null)"
echo "桥接 pid : $(pidof hero_bridge)"
BINPID=$(od -An -tu4 -j 36 -N 4 "$BIN" 2>/dev/null | tr -d ' ')
echo "游戏 pid : ${BINPID:-?}  (最后一次内核定位)"
echo "完成。"
