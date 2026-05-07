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

echo "[*] Starting Backend on port 8080..."
pkill -f "uvicorn main:app" || true
# Start backend in background
uvicorn main:app --host 0.0.0.0 --port 8080 --http h11 --ws wsproto --loop asyncio > backend.log 2>&1 &
BACKEND_PID=$!
echo "[*] Backend started with PID $BACKEND_PID"

cd "$PROJECT_ROOT/breachconsole/frontend"
echo "[*] Starting Frontend on port 1337..."
npm run dev -- --host 0.0.0.0 --port 1337
