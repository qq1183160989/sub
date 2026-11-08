#!/bin/bash
set -u

echo "=== 容器启动 $(date -u '+%F %T UTC') ==="

# 订阅 HTTP 服务，常驻
python3 /app/serve.py &
SERVER_PID=$!
sleep 1

INTERVAL=${FILTER_INTERVAL:-21600}

while true; do
  echo "=== 开始筛选 $(date -u '+%F %T UTC') ==="
  if python3 /app/filter.py; then
    echo "=== 筛选完成，可用 $(grep -c '://' /app/out/live-links.txt 2>/dev/null || echo 0) 条 ==="
  else
    echo "=== 本轮失败，保留上一版文件 ==="
  fi
  echo "=== 下次运行：$(date -u -d "+${INTERVAL} seconds" '+%F %T UTC') ==="
  sleep "$INTERVAL"
done