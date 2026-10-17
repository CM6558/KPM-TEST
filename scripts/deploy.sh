#!/data/data/com.termux/files/usr/bin/sh
# ============================================================
# 重新部署 + 启动 (termux 侧)
#   sh ~/kpmwork/deploy.sh          # 部署并启动
#   sh ~/kpmwork/deploy.sh status   # 只看状态
#
# 关键点:
#  - 模块名固定为 hero-reader (HR_MOD_NAME), 不再版本化
#  - 重新部署前必须先 root 停止旧实例: 同名模块“File exists”时无法覆盖,
#    直接 load 会静默失败, 导致跑的还是旧构建 (本机 KP unload 需循环重试)
#  - /data/local/tmp 被清空也能一条命令恢复
# ============================================================
H=$(cd "$(dirname "$0")" && pwd)
# 设备上源码在 ~/kpmwork/KPM-TEST-work；仓库里就在根目录
if [ -d "$H/KPM-TEST-work" ]; then W=$H/KPM-TEST-work; else W=$H; fi
SRC=$W/hero_reader.c
KPM=$W/hero_reader.kpm
BR=$H/bridge/hero_bridge
ST=$H/hero_start.sh
SP=$H/hero_stop.sh
KSUD=/data/adb/ksud

if [ "$1" = "status" ]; then
    su -c "sh /data/local/tmp/hero_start.sh status" 2>&1 | head -8
    exit 0
fi

for f in "$SRC" "$KPM" "$BR" "$ST" "$SP"; do
    [ -f "$f" ] || { echo "缺少 $f"; exit 1; }
done

NAME=$(grep -m1 'define HR_MOD_NAME' "$SRC" | sed 's/.*"\(.*\)".*/\1/')
[ -z "$NAME" ] && { echo "解析模块名失败"; exit 1; }
echo "· 模块名: $NAME"

su -c "mkdir -p /data/local/tmp
echo '$NAME' > /data/local/tmp/hero_mod.name
cp -f '$KPM' /data/local/tmp/hero_reader.kpm
cp -f '$BR'  /data/local/tmp/hero_bridge
cp -f '$ST'  /data/local/tmp/hero_start.sh
cp -f '$SP'  /data/local/tmp/hero_stop.sh
chmod 755 /data/local/tmp/hero_start.sh /data/local/tmp/hero_stop.sh /data/local/tmp/hero_bridge /data/local/tmp/hero_reader.kpm
sync"

# 先干净停止 (必须 root; 循环卸载到名字消失, 否则新构建加载不上)
echo "· 停止旧实例"
su -c "sh /data/local/tmp/hero_stop.sh" 2>&1 | grep -E "模块|守护|桥接" | head -4

su -c "sh /data/local/tmp/hero_start.sh" 2>&1 | tail -4
