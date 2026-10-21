#!/system/bin/sh
# Hero 方案B 一键启动 (root)。放到 /data/adb/service.d/ 可开机自启。
# 依赖: KPM 模块 hero_reader.kpm、用户态桥接 hero_bridge
MOD=/data/local/tmp/hero_reader.kpm
BIN=/data/local/tmp/heroes.bin
BRIDGE=/data/local/tmp/hero_bridge
GAME=com.tencent.tmgp.sgame

# 1) 加载模块 (已加载会报错, 忽略)
/data/adb/ksud kpm load "$MOD" 2>/dev/null

# 2) 等游戏进程
until pidof "$GAME" >/dev/null 2>&1; do sleep 2; done
PID=$(pidof "$GAME" | tr ' ' '\n' | head -1)

# 3) 设目标 + 开二进制输出(100ms)
/data/adb/ksud kpm control hero-reader "set $PID"
/data/adb/ksud kpm control hero-reader "herobin $BIN 100"

# 4) 起桥接 (若未运行)
if ! pidof hero_bridge >/dev/null 2>&1; then
  nohup "$BRIDGE" "$BIN" 8787 >/data/local/tmp/bridge.log 2>&1 &
fi
