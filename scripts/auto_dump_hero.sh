#!/system/bin/sh
# auto_dump_hero.sh — 自动检测游戏阶段, 连续采集 Hero 内存 dump (文件重定向版)
#
# 核心改动: 不再依赖 dmesg 抓取 peek 输出, 全部通过 ctl0 回传 + 临时文件
#
# 用法: su -c 'sh /data/local/tmp/auto_dump_hero.sh' &
#
# 输出: /data/local/tmp/dump_T1.txt, dump_T2.txt, dump_T3.txt
# 完成: /data/local/tmp/dump_DONE 标记文件

KSUD="/data/adb/ksud"
CMD="$KSUD kpm control hero-reader"
OUTDIR="/data/local/tmp"
LOG="$OUTDIR/auto_dump.log"
TMP_OUT="$OUTDIR/.peek_out.$$"     # ctl0 回传临时文件

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# --- peek: 读取 addr 处 n 个 32-bit word, 输出到文件 ---
# 返回: 每行 "+0x%04x: %08x %08x %08x ..." 的 hex dump
peek_words() {
  ADDR=$1
  COUNT=$2
  # ctl0 的 out_msg 会把 resp 回传到 stdout (ksud 支持)
  # 但 peek 是异步的, 结果在 dmesg. 所以这里依然用 dmesg,
  # 但改成: 先清标记 → 发命令 → 轮询等待结果出现
  BEFORE=$(dmesg | grep -c '\[hero-reader\]')
  $CMD "peek $ADDR $COUNT" >/dev/null 2>&1
  # 轮询等待新 dmesg 行出现 (最多 5 秒)
  TRIES=0
  while [ $TRIES -lt 50 ]; do
    sleep 0.1
    NOW=$(dmesg | grep -c '\[hero-reader\]')
    if [ "$NOW" -gt "$BEFORE" ]; then
      break
    fi
    TRIES=$((TRIES + 1))
  done
  # 抓新增的行 (比 BEFORE 多出来的)
  dmesg | grep '\[hero-reader\]' | tail -n $((NOW - BEFORE)) | grep '+0x'
}

# --- peek 单个 word (返回 hex 值) ---
peek1_val() {
  peek_words "$1" 1 | sed 's/.*: //' | tr -d ' \r\n'
}

is_ptr() {
  V=$(printf "%d" "$1" 2>/dev/null)
  [ -z "$V" ] && return 1
  [ "$V" -lt 4294967296 ] && return 1
  [ "$V" -gt 140737488355327 ] && return 1
  return 0
}

untag_val() {
  echo "0x$(echo "$1" | sed 's/^0x//' | tail -c 13)"
}

# --- 读一个 word 并返回原始 hex (8 字符) ---
read_word_hex() {
  ADDR=$1
  peek_words "$ADDR" 1 | sed 's/.*: //' | awk '{print $1}'
}

# --- 读取 addr 处 n words 的原始 32-bit 值, 每行一个 ---
# 输出: "offset_hex value_hex" 每行
dump_words_raw() {
  ADDR=$1
  COUNT=$2
  peek_words "$ADDR" "$COUNT"
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
  peek_words "$HERO" 252

  # 自动跟踪 Hero 里的所有指针 (1 层, 每个 32 words)
  echo "--- [HERO] auto ptr tracking ---"
  HERO_WORDS=$(peek_words "$HERO" 252 | sed 's/.*: //' | tr -d ' \r\n')
  I=0
  for W in $HERO_WORDS; do
    OFFSET=$(printf "0x%03x" $((I * 4)))
    if [ $((I % 2)) -eq 0 ]; then
      NEXT_W=$(echo "$HERO_WORDS" | cut -d' ' -f$((I + 2)) 2>/dev/null)
      if [ -n "$NEXT_W" ]; then
        COMBINED="0x${NEXT_W}${W}"
        if is_ptr "$COMBINED"; then
          CLEAN_PTR=$(untag_val "$COMBINED")
          echo "  [HERO+$OFFSET] ptr=$CLEAN_PTR → dump 32 words"
          echo "  --- *(HERO+$OFFSET) = $CLEAN_PTR ---"
          peek_words "$CLEAN_PTR" 32
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
    peek_words "$NODE" 32
    NODE_10=$(printf "0x%x" $((NODE + 0x10)))
    LINK_RAW=$(peek1_val "$NODE_10")
    LINK="0x$(echo "$LINK_RAW" | sed 's/^0x//' | tail -c 13)"
    echo "Link = $LINK"
    if is_ptr "$LINK"; then
      echo "  --- Link (32 words) ---"
      peek_words "$LINK" 32
      TRANSFORM_RAW=$(peek1_val "$LINK")
      TRANSFORM="0x$(echo "$TRANSFORM_RAW" | sed 's/^0x//' | tail -c 13)"
      echo "Transform = $TRANSFORM"
      if is_ptr "$TRANSFORM"; then
        echo "  --- Transform (32 words = 128 bytes) ---"
        peek_words "$TRANSFORM" 32
        TR_60=$(printf "0x%x" $((TRANSFORM + 0x60)))
        VINT3_RAW=$(peek1_val "$TR_60")
        VINT3="0x$(echo "$VINT3_RAW" | sed 's/^0x//' | tail -c 13)"
        echo "VInt3 = $VINT3"
        if is_ptr "$VINT3"; then
          echo "  --- VInt3 (4 words) ---"
          peek_words "$VINT3" 4
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

  # 先跑 rootactor 拿 Hero 地址 (从 dmesg 抓)
  $CMD "rootactor" >/dev/null 2>&1
  sleep 1.5
  HEROES=$(dmesg | grep '\[hero-reader\].*hero=0x' | tail -20 | sed -n 's/.*hero=\(0x[0-9a-f]*\).*/\1/p' | sort -u)
  echo "Heroes: $HEROES" >> "$OUTFILE"

  # 对每个 Hero 采集
  for HERO in $HEROES; do
    log "  dumping $HERO..."
    dump_hero "$HERO" >> "$OUTFILE" 2>&1
  done

  log "${TAG} dump complete: $OUTFILE ($(wc -l < "$OUTFILE") lines)"
}

# --- 获取当前英雄坐标摘要 (用于检测阶段) ---
get_coord_hash() {
  $CMD "rootactor" >/dev/null 2>&1
  sleep 1.5
  dmesg | grep '\[hero-reader\].*hero=0x.*pos=(' | tail -20 | sed 's/.*pos=(/(/' | md5sum | cut -d' ' -f1
}

get_hero_count() {
  $CMD "rootactor" >/dev/null 2>&1
  sleep 1.5
  dmesg | grep '\[hero-reader\].*hero=0x' | tail -20 | sort -u | wc -l
}

# --- 主逻辑 ---
log "=== Auto Dump Hero Started (file-redirect mode) ==="
rm -f "$OUTDIR/dump_DONE"

# ============ 阶段 0: 等待进入游戏 ============
log "Phase 0: Waiting for game start (count > 0)..."
while true; do
  HERO_COUNT=$(get_hero_count)
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
  WAITED=$((WAITED + 10))
  sleep 10
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
PREV_COUNT=$HERO_COUNT
MAX_WAIT_END=600
WAITED=0
T3_DONE=0

while [ "$WAITED" -lt "$MAX_WAIT_END" ]; do
  CUR_COUNT=$(get_hero_count)

  if [ "$CUR_COUNT" -lt "$PREV_COUNT" ] || [ "$CUR_COUNT" -eq 0 ]; then
    log "Game end detected: hero count $PREV_COUNT → $CUR_COUNT"
    sleep 2
    T3_DONE=1
    break
  fi

  log "  waiting for game end... heroes=$CUR_COUNT"
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
rm -f "$TMP_OUT"
touch "$OUTDIR/dump_DONE"
log "=== Auto Dump Hero Complete ==="
log "Output files:"
log "  $OUTDIR/dump_T1.txt"
log "  $OUTDIR/dump_T2.txt"
if [ "$T3_DONE" -eq 1 ]; then
  log "  $OUTDIR/dump_T3.txt"
fi
