#!/system/bin/sh
# auto_dump_hero.sh — 全文件重定向 + T2 连续多次采集版
#
# 采集策略:
#   T1: 开局坐标稳定后 dump 1 次
#   T2: 从 T1 结束后开始, 每 30 秒 dump 一次, 共 10 次 (覆盖 0~5 分钟全部窗口)
#   T3: 检测到游戏结束后 dump 1 次
#
# 输出: dump_T1.txt, dump_T2_00.txt ~ dump_T2_09.txt, dump_T3.txt
# 完成: dump_DONE 标记文件

KSUD="/data/adb/ksud"
CMD="$KSUD kpm control hero-reader"
OUTDIR="/data/local/tmp"
LOG="$OUTDIR/auto_dump.log"
STATFILE="$OUTDIR/.herostat.tmp"

T2_INTERVAL=30     # T2 每次采集间隔 (秒)
T2_MAX=10          # T2 最多采集次数 (30s × 10 = 300s = 5min 覆盖)

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

get_hero_count() {
  $CMD "herostat $STATFILE" >/dev/null 2>&1
  sleep 0.5
  COUNT=$(sed -n 's/^count=//p' "$STATFILE" 2>/dev/null)
  echo "${COUNT:-0}"
}

get_coord_hash() {
  $CMD "herostat $STATFILE" >/dev/null 2>&1
  sleep 0.5
  grep 'pos=(' "$STATFILE" 2>/dev/null | md5sum | cut -d' ' -f1
}

collect_dump() {
  TAG=$1
  OUTFILE="$OUTDIR/dump_${TAG}.txt"
  $CMD "dumpphase $TAG $OUTFILE" >/dev/null 2>&1
  sleep 1
  LINES=$(wc -l < "$OUTFILE" 2>/dev/null)
  HEROES=$(grep -c '^=== Hero' "$OUTFILE" 2>/dev/null)
  log "${TAG}: $OUTFILE ($LINES lines, $HEROES heroes)"
}

# --- 主逻辑 ---
log "=== Auto Dump Hero Started (multi-T2 mode) ==="
rm -f "$OUTDIR/dump_DONE" "$STATFILE"
rm -f "$OUTDIR"/dump_T2_*.txt

# ============ 阶段 0: 等待进入游戏 ============
log "Phase 0: Waiting for game start..."
while true; do
  COUNT=$(get_hero_count)
  if [ "$COUNT" -gt 0 ] 2>/dev/null; then
    log "Game started: $COUNT heroes"
    break
  fi
  log "  waiting... (heroes=$COUNT)"
  sleep 5
done

sleep 3

# ============ 阶段 1: T1 = 开局 (坐标稳定) ============
log "Phase 1: Detecting stable coords (heroes at base)..."
PREV_HASH=""
STABLE_COUNT=0
MAX_WAIT=30
WAITED=0

while [ "$WAITED" -lt "$MAX_WAIT" ]; do
  HASH=$(get_coord_hash)
  if [ "$HASH" = "$PREV_HASH" ] && [ -n "$HASH" ]; then
    STABLE_COUNT=$((STABLE_COUNT + 1))
    log "  stable ($STABLE_COUNT/3)"
    if [ "$STABLE_COUNT" -ge 3 ]; then
      log "T1: Coords stable — at base"
      break
    fi
  else
    STABLE_COUNT=0
    log "  changing..."
  fi
  PREV_HASH="$HASH"
  WAITED=$((WAITED + 10))
  sleep 10
done

# 无论是否稳定都立即 dump (中途启动时坐标不会稳定)
collect_dump "T1"

# ============ 阶段 2: T2 连续多次 ============
log "Phase 2: Multi-T2 collection (${T2_MAX} dumps, ${T2_INTERVAL}s interval = $(( T2_MAX * T2_INTERVAL / 60 ))min coverage)"

I=0
while [ "$I" -lt "$T2_MAX" ]; do
  TAG=$(printf "T2_%02d" $I)
  collect_dump "$TAG"
  log "  T2 progress: $((I + 1))/${T2_MAX} (elapsed $(( (I + 1) * T2_INTERVAL ))s)"
  I=$((I + 1))
  if [ "$I" -lt "$T2_MAX" ]; then
    sleep "$T2_INTERVAL"
  fi
done

# ============ 阶段 3: T3 = 游戏结束 ============
log "Phase 3: Detecting game end..."
MAX_WAIT_END=600
WAITED=0
T3_DONE=0

while [ "$WAITED" -lt "$MAX_WAIT_END" ]; do
  CUR_COUNT=$(get_hero_count)
  if [ "$CUR_COUNT" -eq 0 ] 2>/dev/null || [ "$CUR_COUNT" -lt 5 ] 2>/dev/null; then
    log "Game end detected: heroes=$CUR_COUNT"
    sleep 2
    T3_DONE=1
    break
  fi
  log "  waiting... heroes=$CUR_COUNT"
  WAITED=$((WAITED + 10))
  sleep 10
done

if [ "$T3_DONE" -eq 1 ]; then
  collect_dump "T3"
else
  log "T3: Timeout, dumping anyway"
  collect_dump "T3"
fi

# ============ 结束 ============
rm -f "$STATFILE"
touch "$OUTDIR/dump_DONE"
log "=== Auto Dump Hero Complete ==="
log "Files:"
log "  dump_T1.txt  (开局)"
ls "$OUTDIR"/dump_T2_*.txt 2>/dev/null | while read f; do log "  $(basename $f)"; done
log "  dump_T3.txt  (结束)"
log "Total files: $(ls "$OUTDIR"/dump_T*.txt 2>/dev/null | wc -l)"
