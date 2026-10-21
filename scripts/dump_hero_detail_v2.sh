#!/system/bin/sh
# dump_hero_detail_v2.sh — 完整版 Hero 内存 dump + 自动指针跟踪
# 用法: su -c 'sh /data/local/tmp/dump_hero_detail_v2.sh' > /data/local/tmp/hero_dump.txt 2>&1
#
# 和 v1 的区别:
#   - dump Node/Link/Transform 对象本身(不光跟指针)
#   - 自动跟踪 Hero 对象里所有疑似指针(>0x100000000), 每个 dump 32 words
#   - 这样不管位置字段在哪个子对象里, 都能被一次性捕获

KSUD="/data/adb/ksud"
CMD="$KSUD kpm control hero-reader"
TMP="/data/local/tmp/hr_dump_$$"
DMESG_DELAY=0.3

# 读 peek 输出的最后 N 行
dmesg_tail() {
  dmesg | grep '\[hero-reader\]   +0x' | tail -n "$1"
}

# peek 地址, 返回第一个 word 的 hex (不带 0x)
peek1() {
  $CMD "peek $1 1"
  sleep $DMESG_DELAY
  dmesg | grep '\[hero-reader\]   +0x0000' | tail -1 | sed 's/.*: //' | tr -d ' \r\n'
}

# peek 地址 count words, 打印所有行
peekN() {
  $CMD "peek $1 $2"
  sleep $DMESG_DELAY
  dmesg | grep '\[hero-reader\]   +0x' | tail -n "$2"
}

# 判断 hex 值是否合法指针 (> 0x100000000 且 < 0x800000000000)
is_ptr() {
  VAL=$1
  # 用 shell arithmetic 比较
  VAL_DEC=$(printf "%d" "$VAL" 2>/dev/null)
  if [ -z "$VAL_DEC" ]; then return 1; fi
  if [ "$VAL_DEC" -lt 4294967296 ]; then return 1; fi  # < 0x100000000
  if [ "$VAL_DEC" -gt 140737488355327 ]; then return 1; fi  # > 0x7FFFFFFFFFFF
  return 0
}

# 去掉高 4 字节(MTE tag), 只保留 48 位
untag() {
  VAL=$1
  # 取低 12 hex chars (48 bit)
  VAL_CLEAN=$(echo "$VAL" | sed 's/^0x//' | tail -c 13)
  echo "0x$VAL_CLEAN"
}

# dump 一个地址, 如果是合法指针, 递归 dump 该对象 32 words
dump_ptr_obj() {
  ADDR=$1
  LABEL=$2
  DEPTH=$3
  
  if [ "$DEPTH" -gt 3 ]; then return; fi  # 最多递归 3 层
  
  echo "--- [$LABEL] dump $ADDR (32 words / 128 bytes) ---"
  peekN "$ADDR" 32
  
  # 也跟踪该对象里的指针
  # 解析 32 words 里每个 word, 如果是合法指针则递归 dump
  WORDS=$(peekN "$ADDR" 32 | sed 's/.*: //' | tr -d ' \r\n')
  I=0
  for W in $WORDS; do
    OFFSET=$(printf "0x%03x" $((I * 4)))
    if is_ptr "0x$W"; then
      CLEAN=$(untag "0x$W")
      echo "  [$LABEL+$OFFSET] -> ptr $CLEAN (auto-tracking)"
      dump_ptr_obj "$CLEAN" "$LABEL+$OFFSET" $((DEPTH + 1))
    fi
    I=$((I + 1))
  done
}

echo "=========================================="
echo "=== Hero Detail Dump V2 (auto ptr tracking) $(date) ==="
echo "=========================================="
echo ""

# Step 1: 获取 Hero 地址列表
echo "--- Step 1: read_rootactor_chain ---"
$CMD "fullchain"
sleep 1
dmesg | grep '\[hero-reader\].*hero=0x' | tail -20 > "$TMP_heroes"
echo "Heroes found:"
cat "$TMP_heroes"
echo ""

# Step 2: 解析 Hero 地址
HEROES=$(cat "$TMP_heroes" | sed -n 's/.*hero=\(0x[0-9a-f]*\).*/\1/p')

# Step 3: 对每个 Hero 完整 dump + 自动指针跟踪
for HERO in $HEROES; do
  echo ""
  echo "============================================"
  echo "=== Hero @ $HERO (full dump + auto ptr tracking) ==="
  echo "============================================"

  # 3a: Hero 本身 1008 字节 (252 words)
  echo "--- [HERO] object dump (252 words / 1008 bytes) ---"
  peekN "$HERO" 252

  # 3b: 自动找出 Hero 里的所有疑似指针, 逐个 dump
  echo ""
  echo "--- [HERO] auto-tracking pointers ---"
  echo "Parsing 252 words for pointers..."
  
  # 重新 peek 一次, 拿到完整输出
  peekN "$HERO" 252 | while IFS= read -r LINE; do
    # 解析格式: "  +0xNNNN: HHHHHHHH"
    OFFSET=$(echo "$LINE" | sed -n 's/.*+\(0x[0-9a-f]*\):.*/\1/p')
    VALUE=$(echo "$LINE" | sed 's/.*: //' | tr -d ' \r\n')
    
    if [ -n "$VALUE" ]; then
      if is_ptr "0x$VALUE"; then
        CLEAN=$(untag "0x$VALUE")
        echo "  [HERO+$OFFSET] -> ptr $CLEAN → dumping..."
        
        # 判断是否之前已经 dump 过 (避免重复)
        # 对每个新指针 dump 32 words
        echo "  --- *(HERO+$OFFSET) = $CLEAN (32 words) ---"
        peekN "$CLEAN" 32
        
        # 检查这个子对象里的指针 (递归 1 层)
        SUB_WORDS=$(dmesg | grep '\[hero-reader\]   +0x' | tail -32 | sed 's/.*: //' | tr -d ' \r\n')
        J=0
        for SW in $SUB_WORDS; do
          if is_ptr "0x$SW"; then
            CLEAN2=$(untag "0x$SW")
            echo "    [SUB+$J] -> ptr $CLEAN2 → dumping (16 words)..."
            echo "    --- *(SUB+$J) = $CLEAN2 (16 words) ---"
            peekN "$CLEAN2" 16
          fi
          J=$((J + 1))
        done
      fi
    fi
  done

  # 3c: Transform 链完整 dump (Node/Link/Transform 对象本身)
  echo ""
  echo "--- [HERO+0xA8] Transform chain (full object dumps) ---"
  
  # Hero+0xA8 = Node*
  NODE_RAW=$(peek1 "$HERO")
  # 这里上面是 peek Hero+0x0 拿的就是 vtable, 其实需要 peek $HERO+0xA8 处的
  # 但 peek 命令传的是地址, 不是 hero+OFFSET
  HERO_A8=$(printf "0x%x" $((HERO + 0xA8)))
  NODE_RAW=$(peek1 "$HERO_A8")
  NODE=$(untag "0x$NODE_RAW")
  echo "Node = *(Hero+0xA8) = $NODE"
  
  if is_ptr "$NODE"; then
    echo "  --- Node object (32 words / 128 bytes) ---"
    peekN "$NODE" 32
    
    # Node+0x10 = Link*
    NODE_10=$(printf "0x%x" $((NODE + 0x10)))
    LINK_RAW=$(peek1 "$NODE_10")
    LINK=$(untag "0x$LINK_RAW")
    echo "Link = *(Node+0x10) = $LINK"
    
    if is_ptr "$LINK"; then
      echo "  --- Link object (32 words / 128 bytes) ---"
      peekN "$LINK" 32
      
      # Link+0 = Transform*
      TRANSFORM_RAW=$(peek1 "$LINK")
      TRANSFORM=$(untag "0x$TRANSFORM_RAW")
      echo "Transform = *(Link+0x00) = $TRANSFORM"
      
      if is_ptr "$TRANSFORM"; then
        echo "  --- Transform object (32 words / 128 bytes) ---"
        peekN "$TRANSFORM" 32
        
        # Transform+0x60 = VInt3*
        TRANSFORM_60=$(printf "0x%x" $((TRANSFORM + 0x60)))
        VINT3_RAW=$(peek1 "$TRANSFORM_60")
        VINT3=$(untag "0x$VINT3_RAW")
        echo "VInt3 = *(Transform+0x60) = $VINT3"
        
        if is_ptr "$VINT3"; then
          echo "  --- VInt3 object (8 words / 32 bytes) ---"
          peekN "$VINT3" 8
        fi
      fi
    fi
  fi

  echo ""
  echo "--- End Hero @ $HERO ---"
  echo ""
done

# 清理临时文件
rm -f "$TMP_heroes" 2>/dev/null

echo ""
echo "=========================================="
echo "=== Dump V2 complete $(date) ==="
echo "=========================================="
echo ""
echo "Run at T1 (start), T2 (2-5min), T3 (end) for 3-way diff."
echo "Each Hero now includes: 1008B object + all pointer targets (128B each, 2 levels deep) + full Transform chain."
