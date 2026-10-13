#!/system/bin/sh
# hero_reader.sh — 用户态驱动脚本
# 配合 hero_reader.kpm 使用
# 前置: KernelSU + KernelPatch 已安装, hero_reader.kpm 已加载

KPM_NAME="hero-reader"
LOG_TAG="[hero-reader-ctl]"

# 检查 kpmctl 是否可用
if ! command -v kpmctl >/dev/null 2>&1; then
    echo "$LOG_TAG Error: kpmctl not found"
    echo "$LOG_TAG Install KernelPatch manager app first"
    exit 1
fi

# Step 1: 查找王者荣耀进程 PID
find_pid() {
    PID=$(pidof com.tencent.tmgp.sgame 2>/dev/null | awk '{print $1}')
    if [ -z "$PID" ]; then
        echo "$LOG_TAG Error: 王者荣耀未运行"
        exit 1
    fi
    echo "$LOG_TAG target pid: $PID"
}

# Step 2: 从 /proc/PID/maps 获取 libil2cpp.so 基址
find_base() {
    BASE=$(grep 'libil2cpp.so$' /proc/$PID/maps 2>/dev/null | head -1 | cut -d'-' -f1)
    if [ -z "$BASE" ]; then
        echo "$LOG_TAG Error: libil2cpp.so not found in maps"
        echo "$LOG_TAG 提示: 游戏可能还没进入战斗场景"
        exit 1
    fi
    echo "$LOG_TAG libil2cpp.so base: 0x$BASE"
}

# Step 3: 通过 kpmctl 发送控制命令
kpm_cmd() {
    kpmctl control "$KPM_NAME" "$1"
}

# Step 4: 主流程
echo "=== Hero Position Reader ==="

find_pid
find_base

# 设置 PID
echo "$LOG_TAG setting pid..."
kpm_cmd "pid $PID"

# 设置基址
echo "$LOG_TAG setting base..."
kpm_cmd "base 0x$BASE"

# 验证 s_domain 可读
echo "$LOG_TAG checking s_domain..."
RESULT=$(kpm_cmd "auto")
echo "$LOG_TAG auto result: $RESULT"

# 读取坐标
echo "$LOG_TAG reading hero positions..."
RESULT=$(kpm_cmd "read")
echo "$LOG_TAG result: $RESULT"

# 解析输出
echo ""
echo "=== Hero Positions ==="
echo "$RESULT" | tr '|' '\n' | while read line; do
    if echo "$line" | grep -q "HERO:"; then
        echo "$line"
    fi
done

# 持续读取模式
read -p "持续读取? (y/n): " CONT
if [ "$CONT" = "y" ]; then
    while true; do
        clear
        echo "=== Hero Positions (按 Ctrl+C 退出) ==="
        echo "time: $(date '+%H:%M:%S')"
        RESULT=$(kpm_cmd "read")
        echo "$RESULT" | tr '|' '\n' | while read line; do
            if echo "$line" | grep -q "HERO:"; then
                echo "$line"
            fi
        done
        sleep 0.5
    done
fi
