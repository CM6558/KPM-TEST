#!/system/bin/sh
# auto_dump_hero.sh — 自动检测游戏阶段, 连续采集 Hero 内存 dump
#
# 用法: su -c 'sh /data/local/tmp/auto_dump_hero.sh' &
# 启动后:
#   1. 等待进入游戏 (count > 0)
#   2. 检测到开局 (英雄在出生点不动) → dump T1
#   3. 等 60 秒 (对局中) → dump T2
#   4. 等待游戏结束 (count 变化或坐标清零) → dump T3
#   5. 自动退出
#
# 输出: /data/local/tmp/dump_T1.txt, dump_T2.txt, dump_T3.txt
# 完成: /data/local/tmp/dump_DONE 标记文件

KSUD="/data/adb/ksud"
CMD="$KSUD kpm control hero-reader"
OUTDIR="/data/local/tmp"
LOG="$OUTDIR/auto_dump.log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# --- peek helpers ---
dmesg_last() { dmesg | grep '\[hero-reader\].*hero=0x' | tail -n "$1"; }

peek1_val() {
  $CMD "peek $1 1" >/dev/null 2>&1
  sleep 0.3
  dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //' | tr -d ' \r\n'
}

peekN_lines() {
  $CMD "peek $1 $2" >/dev/null 2>&1
  sleep 0.3
  dmesg | grep '\[hero-reader\]   +0x' | tail -n "$2"
}

is_ptr() {
  V=$(printf "%d" "$1" 2>/dev/null)
  [ -z "$V" ] && return 1
  [ "$V" -lt 4294967296 ] && return 1
  [ "$V" -gt 140737488355327 ] && return 1
  return 0
}

untag_val() {
  echo "$1" | sed 's/^0x//' | tail -c 13
  echo "0x$(echo "$1" | sed 's/^0x//' | tail -c 13)"
}

# --- dump 一个 Hero 的完整数据 ---
dump_hero() {
  HERO=$1
  echo "============================================"
  echo "=== Hero @ $HERO ==="
  echo "=== $(date '+%Y-%m-%d %H:%M:%S') ==="
  echo "============================================"

  # Hero 本身 252 words (1008 bytes)
  echo "--- [HERO] 252 words (1008 bytes) ---"
  peekN_lines "$HERO" 252

  # 自动跟踪 Hero 里的所有指针 (1 层, 每个 32 words)
  echo "--- [HERO] auto ptr tracking ---"
  # 重新读, 解析每个 word
  HERO_WORDS=$(peekN_lines "$HERO" 252 | sed 's/.*: //' | tr -d ' \r\n')
  I=0
  for W in $HERO_WORDS; do
    OFFSET=$(printf "0x%03x" $((I * 4)))
    # 8 字节对齐: 每 2 个 word 组成一个 64-bit 值
    if [ $((I % 2)) -eq 0 ]; then
      # 读 next word 组合成 64-bit
      NEXT_W=$(echo "$HERO_WORDS" | cut -d' ' -f$((I + 2)) 2>/dev/null)
      if [ -n "$NEXT_W" ]; then
        COMBINED="0x${NEXT_W}${W}"  # 小端: 高位在后面
        if is_ptr "$COMBINED"; then
          CLEAN_PTR=$(untag_val "$COMBINED")
          echo "  [HERO+$OFFSET] ptr=$CLEAN_PTR → dump 32 words"
          echo "  --- *(HERO+$OFFSET) = $CLEAN_PTR ---"
          peekN_lines "$CLEAN_PTR" 32
        fi
      fi
    fi
    I=$((I + 1))
  done

  # Transform 链完整 dump
  echo "--- [TRANSFORM] chain ---"
  HERO_A8=$(printf "0x%x" $((HERO + 0xA8)))
  NODE_RAW=$(peek1_val "$HERO_A8")
  NODE="0x$(echo "$NODE_RAW" | sed 's/^0x//' | tail -c 13)"
  echo "Node = $NODE"
  if is_ptr "$NODE"; then
    echo "  --- Node (32 words) ---"
    peekN_lines "$NODE" 32
    NODE_10=$(printf "0x%x" $((NODE + 0x10)))
    LINK_RAW=$(peek1_val "$NODE_10")
    LINK="0x$(echo "$LINK_RAW" | sed 's/^0x//' | tail -c 13)"
    echo "Link = $LINK"
    if is_ptr "$LINK"; then
      echo "  --- Link (32 words) ---"
      peekN_lines "$LINK" 32
      TRANSFORM_RAW=$(peek1_val "$LINK")
      TRANSFORM="0x$(echo "$TRANSFORM_RAW" | sed 's/^0x//' | tail -c 13)"
      echo "Transform = $TRANSFORM"
      if is_ptr "$TRANSFORM"; then
        echo "  --- Transform (32 words = 128 bytes) ---"
        peekN_lines "$TRANSFORM" 32
        TR_60=$(printf "0x%x" $((TRANSFORM + 0x60)))
        VINT3_RAW=$(peek1_val "$TR_60")
        VINT3="0x$(echo "$VINT3_RAW" | sed 's/^0x//' | tail -c 13)"
        echo "VInt3 = $VINT3"
        if is_ptr "$VINT3"; then
          echo "  --- VInt3 (4 words) ---"
          peekN_lines "$VINT3" 4
        fi
      fi
    fi
  fi
  echo "--- End Hero @ $HERO ---"
  echo ""
}

# --- 采集一次所有 Hero 的 dump ---
collect_dump() {
  TAG=$1
  OUTFILE="$OUTDIR/dump_${TAG}.txt"
  log "Collecting ${TAG} dump to $OUTFILE"

  echo "=== ${TAG} dump $(date) ===" > "$OUTFILE"

  # 先跑 read_rootactor_chain 拿 Hero 地址
  $CMD "fullchain" >> "$OUTFILE" 2>&1
  sleep 1

  # 从 dmesg 抓 Hero 地址
  HEROES=$(dmesg | grep '\[hero-reader\].*hero=0x' | tail -20 | sed -n 's/.*hero=\(0x[0-9a-f]*\).*/\1/p')
  echo "Heroes: $HEROES" >> "$OUTFILE"

  # 对每个 Hero 采集
  for HERO in $HEROES; do
    dump_hero "$HERO" >> "$OUTFILE" 2>&1
  done

  log "${TAG} dump complete: $OUTFILE ($(wc -l < "$OUTFILE") lines)"
}

# --- 获取当前英雄坐标摘要 (用于检测阶段) ---
get_coords_summary() {
  $CMD "fullchain" >/dev/null 2>&1
  sleep 0.8
  # 抓所有 hero 的坐标行
  dmesg | grep '\[hero-reader\].*hero=0x' | tail -20
}

# --- 批量获取坐标 (用于变化检测) ---
get_coord_hash() {
  # 跑 fullchain, 返回所有英雄坐标的 hash
  $CMD "fullchain" >/dev/null 2>&1
  sleep 0.8
  dmesg | grep '\[hero-reader\].*hero=0x' | tail -20 | sed 's/.*pos=(/(/' | md5sum | cut -d' ' -f1
}

# --- 主逻辑 ---
log "=== Auto Dump Hero Started ==="
rm -f "$OUTDIR/dump_DONE"

# ============ 阶段 0: 等待进入游戏 ============
log "Phase 0: Waiting for game start (count > 0)..."
while true; do
  HASH=$(get_coord_hash)
  HERO_INFO=$(dmesg | grep -c '\[hero-reader\].*hero=0x' | tail -1)
  HERO_COUNT=$(dmesg | grep '\[hero-reader\].*hero=0x' | tail -20 | wc -l)
  if [ "$HERO_COUNT" -gt 0 ]; then
    log "Game started: $HERO_COUNT heroes detected"
    break
  fi
  log "  waiting... (heroes=$HERO_COUNT)"
  sleep 5
done

# 等一下让数据稳定
sleep 3

# ============ 阶段 1: T1 = 开局 ============
log "Phase 1: Detecting game start (heroes at base, coords stable)..."

# 检测方法: 连续 5 次坐标 hash 相同 (英雄不动)
PREV_HASH=""
STABLE_COUNT=0
MAX_WAIT=120
WAITED=0

while [ "$WAITED" -lt "$MAX_WAIT" ]; do
  HASH=$(get_coord_hash)
  if [ "$HASH" = "$PREV_HASH" ]; then
    STABLE_COUNT=$((STABLE_COUNT + 1))
    log "  coords stable ($STABLE_COUNT/3) hash=$HASH"
    if [ "$STABLE_COUNT" -ge 3 ]; then
      log "T1: Coords stable for 3 cycles — game start (heroes at base)"
      break
    fi
  else
    STABLE_COUNT=0
    log "  coords changing... hash=$HASH (was $PREV_HASH)"
  fi
  PREV_HASH="$HASH"
  WAITED=$((WAITED + 8))
  sleep 8
done

if [ "$STABLE_COUNT" -ge 3 ]; then
  collect_dump "T1"
else
  log "T1: Timeout waiting for stable coords, dumping anyway"
  collect_dump "T1"
fi

# ============ 阶段 2: T2 = 对局中 ============
log "Phase 2: Waiting 60s for mid-game..."
sleep 60
log "T2: Mid-game dump"
collect_dump "T2"

# ============ 阶段 3: T3 = 游戏结束 ============
log "Phase 3: Detecting game end..."
# 检测方法: 英雄数量突然变化 (从 10 变成 0 或其他)
# 或者坐标全部归零
PREV_COUNT=$HERO_COUNT
MAX_WAIT_END=600  # 最多等 10 分钟
WAITED=0
T3_DONE=0

while [ "$WAITED" -lt "$MAX_WAIT_END" ]; do
  $CMD "fullchain" >/dev/null 2>&1
  sleep 0.8
  CUR_COUNT=$(dmesg | grep -c '\[hero-reader\].*hero=0x' | tail -20 | wc -l)

  # 看坐标是否全 0
  ANY_NONZERO=$(dmesg | grep '\[hero-reader\].*hero=0x' | tail -20 | grep -c 'pos=(' | grep -vc 'pos=(0,0)')

  if [ "$CUR_COUNT" -lt "$PREV_COUNT" ] || [ "$ANY_NONZERO" -eq 0 ]; then
    log "Game end detected: hero count $PREV_COUNT → $CUR_COUNT, nonzero=$ANY_NONZERO"
    sleep 2  # 等一下让迷雾关闭
    T3_DONE=1
    break
  fi

  log "  waiting for game end... heroes=$CUR_COUNT nonzero=$ANY_NONZERO"
  PREV_COUNT=$CUR_COUNT
  WAITED=$((WAITED + 10))
  sleep 10
done

if [ "$T3_DONE" -eq 1 ]; then
  log "T3: Game end dump"
  collect_dump "T3"
else
  log "T3: Timeout, skipping (no game end detected in 10 min)"
fi

# ============ 结束 ============
touch "$OUTDIR/dump_DONE"
log "=== Auto Dump Hero Complete ==="
log "Output files:"
log "  $OUTDIR/dump_T1.txt"
log "  $OUTDIR/dump_T2.txt"
if [ "$T3_DONE" -eq 1 ]; then
  log "  $OUTDIR/dump_T3.txt"
fi
log "Pull with: adb pull $OUTDIR/dump_T1.txt && adb pull $OUTDIR/dump_T2.txt && adb pull $OUTDIR/dump_T3.txt"
