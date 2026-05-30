#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8001}"
FRONTEND_HOST="${FRONTEND_HOST:-0.0.0.0}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

PIDS=()

cleanup() {
  if ((${#PIDS[@]} > 0)); then
    kill "${PIDS[@]}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

if ! command_exists "$PYTHON_BIN"; then
  echo "Python executable not found: $PYTHON_BIN" >&2
  exit 1
fi

if ! command_exists npm; then
  echo "npm is required to start the frontend." >&2
  exit 1
fi

cd "$BACKEND_DIR"

if [[ ! -d ".venv" ]]; then
  "$PYTHON_BIN" -m venv .venv
fi

# shellcheck disable=SC1091
source ".venv/bin/activate"

python -m pip install -r requirements.txt
python manage.py migrate

export EML_ANALYZER_SYNC_TASKS="${EML_ANALYZER_SYNC_TASKS:-1}"
python manage.py runserver "$BACKEND_HOST:$BACKEND_PORT" &
PIDS+=("$!")

cd "$FRONTEND_DIR"

if [[ ! -d "node_modules" ]]; then
  npm install
fi

npm run dev -- --host "$FRONTEND_HOST" --port "$FRONTEND_PORT" &
PIDS+=("$!")

echo "Backend:  http://$BACKEND_HOST:$BACKEND_PORT"
echo "Frontend: http://127.0.0.1:$FRONTEND_PORT"
echo "Press Ctrl+C to stop both servers."

wait -n "${PIDS[@]}"
