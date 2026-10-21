#!/system/bin/sh
# auto_dump_hero.sh — 全文件重定向版, 零 dmesg 依赖
#
# 内核新增 ctl0 命令:
#   herostat <path>        → 写英雄摘要到文件 (count/cfg/camp/pos/dead)
#   dumpphase <tag> <path> → 写所有英雄完整 1008B + Transform 链到文件
#
# 用法: su -c 'sh /data/local/tmp/auto_dump_hero.sh' &
# 输出: /data/local/tmp/dump_T1.txt, dump_T2.txt, dump_T3.txt
# 完成: /data/local/tmp/dump_DONE 标记文件

KSUD="/data/adb/ksud"
CMD="$KSUD kpm control hero-reader"
OUTDIR="/data/local/tmp"
LOG="$OUTDIR/auto_dump.log"
STATFILE="$OUTDIR/.herostat.tmp"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# --- 从 herostat 文件读英雄数 ---
get_hero_count() {
  $CMD "herostat $STATFILE" >/dev/null 2>&1
  sleep 0.5
  COUNT=$(sed -n 's/^count=//p' "$STATFILE" 2>/dev/null)
  echo "${COUNT:-0}"
}

# --- 从 herostat 文件生成坐标 hash (变化检测) ---
get_coord_hash() {
  $CMD "herostat $STATFILE" >/dev/null 2>&1
  sleep 0.5
  grep 'pos=(' "$STATFILE" 2>/dev/null | md5sum | cut -d' ' -f1
}

# --- 采集完整 dump (纯文件重定向) ---
collect_dump() {
  TAG=$1
  OUTFILE="$OUTDIR/dump_${TAG}.txt"
  log "Collecting ${TAG} dump to $OUTFILE"
  $CMD "dumpphase $TAG $OUTFILE" >/dev/null 2>&1
  sleep 1
  LINES=$(wc -l < "$OUTFILE" 2>/dev/null)
  HEROES=$(grep -c '^=== Hero' "$OUTFILE" 2>/dev/null)
  log "${TAG} dump complete: $OUTFILE ($LINES lines, $HEROES heroes)"
}

# --- 主逻辑 ---
log "=== Auto Dump Hero Started (zero-dmesg mode) ==="
rm -f "$OUTDIR/dump_DONE" "$STATFILE"

# ============ 阶段 0: 等待进入游戏 ============
log "Phase 0: Waiting for game start..."
while true; do
  COUNT=$(get_hero_count)
  if [ "$COUNT" -gt 0 ] 2>/dev/null; then
    log "Game started: $COUNT heroes detected"
    break
  fi
  log "  waiting... (heroes=$COUNT)"
  sleep 5
done

sleep 3

# ============ 阶段 1: T1 = 开局 (坐标稳定检测) ============
log "Phase 1: Detecting game start (heroes at base)..."

PREV_HASH=""
STABLE_COUNT=0
MAX_WAIT=120
WAITED=0

while [ "$WAITED" -lt "$MAX_WAIT" ]; do
  HASH=$(get_coord_hash)
  if [ "$HASH" = "$PREV_HASH" ] && [ -n "$HASH" ]; then
    STABLE_COUNT=$((STABLE_COUNT + 1))
    log "  coords stable ($STABLE_COUNT/3)"
    if [ "$STABLE_COUNT" -ge 3 ]; then
      log "T1: Coords stable — heroes at base"
      break
    fi
  else
    STABLE_COUNT=0
    log "  coords changing..."
  fi
  PREV_HASH="$HASH"
  WAITED=$((WAITED + 10))
  sleep 10
done

collect_dump "T1"

# ============ 阶段 2: T2 = 对局中 ============
log "Phase 2: Waiting 60s for mid-game..."
sleep 60
log "T2: Mid-game dump"
collect_dump "T2"

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
  log "  waiting for game end... heroes=$CUR_COUNT"
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
log "  $OUTDIR/dump_T1.txt"
log "  $OUTDIR/dump_T2.txt"
log "  $OUTDIR/dump_T3.txt"
