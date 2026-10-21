#!/system/bin/sh
# dump_hero_detail.sh — 一次性 dump 所有 Hero 的详细内存数据
# 用法: su -c 'sh /data/local/tmp/dump_hero_detail.sh' > /data/local/tmp/hero_dump.txt 2>&1
#
# 依赖: hero_reader.kpm 已加载, setcomm 已设
# 输出: 写到 stdout, 重定向到文件
#
# Dump 内容(每个 Hero):
#   1. Hero 本身 (1008 字节 = 252 words @ +0x000)
#   2. *(Hero+0x10) 子对象 (128 字节 = 32 words)
#   3. *(Hero+0x60) 子对象 (64 字节 = 16 words)  [可能是位置/方向缓存 A]
#   4. *(Hero+0x78) 子对象 (64 字节 = 16 words)  [可能是方向缓存 B]
#   5. Transform 链: Hero+0xA8 → Node+0x10 → Link+0 → Transform+0x60 → VInt3 (8 words)
#   6. *(Hero+0x28) config_id, *(Hero+0x34) camp 确认
#
# 在两个时间点跑:
#   T1: 开局(刚进游戏, 迷雾中)
#   T2: 对局 2-5 分钟后(英雄移动过)
#   T3: 游戏结束(迷雾关闭)
#
# 对比 T1 vs T2 vs T3, 找哪些字段只在 T1 更新(=不实时), 哪些在 T2 仍更新(=实时)

KSUD="/data/adb/ksud"
CMD="$KSUD kpm control hero-reader"
TMP="/data/local/tmp/hr_dump"

# helper: peek addr count → 输出 hex dump
peek() {
  $CMD "peek $1 $2"
}

# helper: 等待 dmesg 输出
sleep 0.3

echo "=========================================="
echo "=== Hero Detail Dump $(date) ==="
echo "=========================================="
echo ""

# Step 1: 跑 read_rootactor_chain 获取所有 Hero 地址
echo "--- Step 1: read_rootactor_chain (获取 Hero 地址列表) ---"
$CMD "fullchain" > "$TMP_fullchain" 2>&1
sleep 1
# 从 dmesg 抓 hero 地址
dmesg | grep '\[hero-reader\].*hero=0x' | tail -20 > "$TMP_heroes"
echo "Heroes found:"
cat "$TMP_heroes"
echo ""

# Step 2: 解析 Hero 地址
# dmesg 格式: [hero-reader]   [#00] slot=0 hero=0x764ba00000 cfg=105 camp=1 ...
# 提取 hero=0xXXXX
HEROES=$(cat "$TMP_heroes" | sed -n 's/.*hero=\(0x[0-9a-f]*\).*/\1/p')
echo "--- Hero addresses ---"
echo "$HEROES"
echo ""

# Step 3: 对每个 Hero dump 详细数据
echo "--- Step 3: Detailed dump per Hero ---"
for HERO in $HEROES; do
  echo ""
  echo "============================================"
  echo "=== Hero @ $HERO ==="
  echo "============================================"

  # 3a: Hero 本身 1008 字节 (252 words)
  echo "--- +0x000: Hero object (1008 bytes / 252 words) ---"
  peek "$HERO" 252
  sleep 0.2
  dmesg | grep '\[hero-reader\]   +0x' | tail -252

  # 3b: *(Hero+0x10) 子对象 (32 words)
  echo "--- +0x010: *(Hero+0x10) sub-object (32 words) ---"
  peek "$HERO" 1  # 先读 Hero+0x10 处的指针
  sleep 0.1
  PTR10=$(dmesg | grep '\[hero-reader\]   +0x0010' | tail -1 | sed 's/.*: //' | awk '{print "0x"$1}')
  echo "*(Hero+0x10) = $PTR10"
  if [ -n "$PTR10" ]; then
    PTR10_DEC=$(printf "%d" "$PTR10" 2>/dev/null)
    if [ -n "$PTR10_DEC" ] && [ "$PTR10_DEC" -gt 1000000000 ]; then
      peek "$PTR10" 32
      sleep 0.2
      dmesg | grep '\[hero-reader\]   +0x' | tail -32
    fi
  fi

  # 3c: *(Hero+0x60) 子对象 (16 words) — 可能是物理位置缓存
  echo "--- +0x060: *(Hero+0x60) sub-object A (16 words) ---"
  peek "$HERO" 6  # 读到 +0x18
  sleep 0.1
  # 读 Hero+0x60 处的 4 字节
  # peek 输出格式: +0xNNNN: HHHHHHHH
  # 我们要 +0x0060 (word offset 24)
  # 但 peek 只能从给定地址开始读, 不能指定 offset
  # 所以直接 peek Hero+0x60 的地址
  HERO60=$((HERO + 0x60))
  peek "0x$(printf '%x' $HERO60)" 2
  sleep 0.1
  dmesg | grep '\[hero-reader\]   +0x' | tail -2
  # 如果 +0x60 是指针, 读它指向的对象
  VAL60=$(dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //')
  echo "*(Hero+0x60) = $VAL60"
  if [ -n "$VAL60" ]; then
    VAL60_PTR=$(printf "0x%s" "$VAL60")
    VAL60_DEC=$(printf "%d" "$VAL60_PTR" 2>/dev/null)
    if [ -n "$VAL60_DEC" ] && [ "$VAL60_DEC" -gt 1000000000 ]; then
      echo "--- *(Hero+0x60) target (16 words) ---"
      peek "$VAL60_PTR" 16
      sleep 0.2
      dmesg | grep '\[hero-reader\]   +0x' | tail -16
    fi
  fi

  # 3d: *(Hero+0x78) 子对象 (16 words) — 可能是方向缓存
  echo "--- +0x078: *(Hero+0x78) sub-object B (16 words) ---"
  HERO78=$((HERO + 0x78))
  peek "0x$(printf '%x' $HERO78)" 2
  sleep 0.1
  dmesg | grep '\[hero-reader\]   +0x' | tail -2
  VAL78=$(dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //')
  echo "*(Hero+0x78) = $VAL78"
  if [ -n "$VAL78" ]; then
    VAL78_PTR=$(printf "0x%s" "$VAL78")
    VAL78_DEC=$(printf "%d" "$VAL78_PTR" 2>/dev/null)
    if [ -n "$VAL78_DEC" ] && [ "$VAL78_DEC" -gt 1000000000 ]; then
      echo "--- *(Hero+0x78) target (16 words) ---"
      peek "$VAL78_PTR" 16
      sleep 0.2
      dmesg | grep '\[hero-reader\]   +0x' | tail -16
    fi
  fi

  # 3e: Transform 链: Hero+0xA8 → Node+0x10 → Link+0 → Transform+0x60 → VInt3
  echo "--- +0x0A8: Transform chain ---"
  HERO_A8=$((HERO + 0xA8))
  peek "0x$(printf '%x' $HERO_A8)" 1
  sleep 0.1
  NODE=$(dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //')
  echo "Node = *(Hero+0xA8) = $NODE"
  if [ -n "$NODE" ]; then
    NODE_PTR=$(printf "0x%s" "$NODE")
    NODE_DEC=$(printf "%d" "$NODE_PTR" 2>/dev/null)
    if [ -n "$NODE_DEC" ] && [ "$NODE_DEC" -gt 1000000000 ]; then
      # Node+0x10
      NODE_10=$((NODE_PTR + 0x10))
      peek "0x$(printf '%x' $NODE_10)" 1
      sleep 0.1
      LINK=$(dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //')
      echo "Link = *(Node+0x10) = $LINK"
      if [ -n "$LINK" ]; then
        LINK_PTR=$(printf "0x%s" "$LINK")
        # Link+0 = Transform
        peek "$LINK_PTR" 1
        sleep 0.1
        TRANSFORM=$(dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //')
        echo "Transform = *(Link+0x00) = $TRANSFORM"
        if [ -n "$TRANSFORM" ]; then
          TRANSFORM_PTR=$(printf "0x%s" "$TRANSFORM")
          # Transform+0x60
          TRANSFORM_60=$((TRANSFORM_PTR + 0x60))
          peek "0x$(printf '%x' $TRANSFORM_60)" 1
          sleep 0.1
          VINT3=$(dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //')
          echo "VInt3 = *(Transform+0x60) = $VINT3"
          if [ -n "$VINT3" ]; then
            VINT3_PTR=$(printf "0x%s" "$VINT3")
            # VInt3: X, Y, Z (3 int32)
            peek "$VINT3_PTR" 4
            sleep 0.1
            dmesg | grep '\[hero-reader\]   +0x' | tail -4
          fi
        fi
      fi
    fi
  fi

  echo ""
  echo "--- Summary for Hero @ $HERO ---"
  # 提取关键字段
  peek "$HERO" 1  # +0x00
  sleep 0.1
  WORD0=$(dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //')

  echo "Hero+0x00 (vtable?) = $WORD0"
  echo "Hero+0x08 (runtime_id) = (see dump above)"
  echo "Hero+0x20 (spawn/direction X) = (see dump above)"
  echo "Hero+0x28 (spawn/direction Y) = (see dump above)"

done

echo ""
echo "=========================================="
echo "=== Dump complete $(date) ==="
echo "=========================================="
echo ""
echo "Run this script at 3 time points:"
echo "  T1: Start of game (enemies at base, fog active)"
echo "  T2: 2-5 min into game (heroes moved)"
echo "  T3: End of game (fog cleared)"
echo ""
echo "Compare T1 vs T2 vs T3 outputs:"
echo "  Fields that change between T1→T2 but NOT T2→T3 = stale (not updated)"
echo "  Fields that keep changing T1→T2→T3 = live (real-time position)"
echo "  Fields that are 55000 in T2 but correct in T1/T3 = ViewManager spoofed"
