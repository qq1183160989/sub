#!/bin/bash
set -u

echo "=== 容器启动 $(date -u '+%F %T UTC') ==="
mkdir -p "$OUT_DIR" "$STATE_DIR"

# 订阅 HTTP 服务（局域网 / frp 备用），常驻
python3 /app/serve.py &
sleep 1

INTERVAL=${FILTER_INTERVAL:-21600}

while true; do
  echo "=== 开始筛选 $(date -u '+%F %T UTC') ==="
  if python3 /app/filter.py; then
    echo "=== 可用 $(grep -c '://' "$OUT_DIR/live-links.txt" 2>/dev/null || echo 0) 条 ==="
    python3 /app/push.py || echo "=== 推送失败（不影响本地服务）==="
  else
    echo "=== 本轮失败，保留上一版文件 ==="
  fi
  echo "=== 下次运行：$(date -u -d "+${INTERVAL} seconds" '+%F %T UTC') ==="
  sleep "$INTERVAL"
done