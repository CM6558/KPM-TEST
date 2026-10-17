#!/system/bin/sh
# 构建 WS 桥接 (设备/Termux 本机 clang 即可)
set -e
cd "$(dirname "$0")"
${CC:-cc} -O2 -o hero_bridge hero_bridge.c -lpthread -lm
echo "OK -> $(pwd)/hero_bridge"
