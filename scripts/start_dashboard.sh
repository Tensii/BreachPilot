#!/bin/bash
# BreachConsole Startup Script

# Get the script's directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$DIR")"

cd "$PROJECT_ROOT/breachconsole/backend"
# Use root venv if available
if [ -f "$PROJECT_ROOT/.venv/bin/activate" ]; then
    . "$PROJECT_ROOT/.venv/bin/activate"
elif [ -f ".venv/bin/activate" ]; then
    . .venv/bin/activate
fi

echo "[*] Cleaning up previous processes..."
fuser -k 8080/tcp 1337/tcp >/dev/null 2>&1 || true
pkill -f vite || true
pkill -f "uvicorn main:app" || true

echo "[*] Starting Backend on port 8080..."
# Start backend in background
uvicorn main:app --host 0.0.0.0 --port 8080 --loop asyncio > backend.log 2>&1 &
BACKEND_PID=$!
echo "[*] Backend started with PID $BACKEND_PID"

cd "$PROJECT_ROOT/breachconsole/frontend"
echo "[*] Starting Frontend on port 1337..."
npm run dev -- --host 0.0.0.0 --port 1337
