#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="/data/accounting/app/nexa-accounting"
API_DIR="$APP_ROOT/apps/api"
PY="$API_DIR/.venv/bin/python"

cd "$API_DIR"

if [ ! -x "$PY" ]; then
  echo "ERROR: Python venv missing at $PY"
  exit 1
fi

set -a
source "$API_DIR/.env"
set +a

exec "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8650}"
