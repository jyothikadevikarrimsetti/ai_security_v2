#!/bin/bash
# Stop all XenSQL + QueryVault services

BASE="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$BASE/.service_pids"
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

if [ ! -f "$PID_FILE" ]; then
  echo "No PID file found — killing by port"
  for port in 8900 8950; do
    lsof -ti tcp:$port | xargs kill -9 2>/dev/null && echo -e "  ${GREEN}✓${NC} Killed port $port" || true
  done
  exit 0
fi

while read pid name; do
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" && echo -e "  ${GREEN}✓${NC} Stopped $name (PID $pid)"
  else
    echo -e "  ${RED}✗${NC} $name (PID $pid) not running"
  fi
done < "$PID_FILE"

rm -f "$PID_FILE"
echo "All services stopped."
