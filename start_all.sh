#!/bin/bash
# ============================================================
# XenSQL + QueryVault — Start All Services
# ============================================================
# Starts XenSQL (port 8900) and QueryVault (port 8950)
# Usage: ./start_all.sh
# Stop:  ./stop_all.sh
# ============================================================

BASE="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$BASE/logs"
mkdir -p "$LOG_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()  { echo -e "${GREEN}[START]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN ]${NC} $1"; }

PID_FILE="$BASE/.service_pids"
> "$PID_FILE"

port_in_use() { lsof -ti tcp:"$1" > /dev/null 2>&1; }

start_service() {
  local name="$1" dir="$2" module="$3" port="$4"

  if port_in_use "$port"; then
    info "$name already running on port $port — skipping"
    return 0
  fi

  local python="$dir/.venv/bin/python"
  if [ ! -f "$python" ]; then
    python=$(which python3)
  fi

  info "Starting $name on port $port…"
  cd "$dir"
  "$python" -m uvicorn "$module" --host 0.0.0.0 --port "$port" \
    >> "$LOG_DIR/${name}.log" 2>&1 &
  local pid=$!
  echo "$pid $name" >> "$PID_FILE"
  echo "  PID $pid → $LOG_DIR/${name}.log"
  cd "$BASE"
  sleep 0.3
}

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║      XenSQL + QueryVault — Two Product Architecture  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Product Services ─────────────────────────────────────────
start_service "XenSQL"     "$BASE/xensql"     "app.main:app"  8900 || true
start_service "QueryVault" "$BASE/queryvault"  "app.main:app"  8950 || true

# ── Health Check ─────────────────────────────────────────────
echo ""
info "Waiting 3s for services to boot…"
sleep 3

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║                   Service Status                    ║"
echo "╚══════════════════════════════════════════════════════╝"

check_health() {
  local name="$1" url="$2"
  if curl -sf --max-time 3 "$url" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} $name ($url)"
  else
    echo -e "  ${RED}✗${NC} $name ($url)"
  fi
}

check_health "XenSQL"     "http://localhost:8900/health"
check_health "QueryVault" "http://localhost:8950/health"

echo ""
echo -e "${GREEN}Swagger UIs:${NC}"
echo "  XenSQL:     http://localhost:8900/docs"
echo "  QueryVault: http://localhost:8950/docs"
echo ""
echo "Logs: $LOG_DIR/"
echo "PIDs: $PID_FILE"
echo ""
echo "To stop: ./stop_all.sh"
