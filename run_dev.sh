#!/usr/bin/env bash
# ============================================================
# run_dev.sh — Local development startup script (Linux / macOS)
#
# Starts FastAPI backend (port 8000) and React frontend (port 5173)
# concurrently using background processes.  No Docker required.
#
# Prerequisites:
#   1. Python 3.11+ virtualenv activated (or conda env)
#   2. pip install -r requirements.txt
#   3. cd frontend && npm install
#   4. .env file exists with all required keys (see .env.example)
#
# Usage:
#   chmod +x run_dev.sh
#   ./run_dev.sh
#
# Author : Member 3 — Vercel Setup & API Skeleton
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo " Agentic SOC Analyst — Local Dev Startup"
echo "============================================================"

# ---- Check .env exists ---------------------------------------------------
if [ ! -f ".env" ]; then
    echo "[WARN] .env not found. Copying from .env.example ..."
    cp ".env.example" ".env"
    echo "[WARN] Please fill in your API keys in .env before running agents."
fi

# ---- Sanity checks -------------------------------------------------------
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.11+ and try again."
    exit 1
fi

if ! command -v node &>/dev/null; then
    echo "[ERROR] node not found. Install Node.js 18+ and try again."
    exit 1
fi

if ! command -v uvicorn &>/dev/null; then
    echo "[ERROR] uvicorn not found. Run: pip install -r requirements.txt"
    exit 1
fi

# ---- Install frontend deps if missing ------------------------------------
if [ ! -d "frontend/node_modules" ]; then
    echo "[INFO] Installing frontend dependencies ..."
    cd frontend && npm install && cd ..
fi

# ---- Cleanup on Ctrl-C ---------------------------------------------------
cleanup() {
    echo ""
    echo "[INFO] Shutting down dev servers ..."
    kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
    echo "[INFO] Done."
}
trap cleanup INT TERM

# ---- Start backend -------------------------------------------------------
echo ""
echo "[INFO] Starting FastAPI backend on http://localhost:8000 ..."
uvicorn api.main:app --reload --port 8000 --host 0.0.0.0 &
BACKEND_PID=$!

sleep 1   # brief pause so backend starts before frontend

# ---- Start frontend ------------------------------------------------------
echo "[INFO] Starting React frontend on http://localhost:5173 ..."
cd frontend && npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "============================================================"
echo " Both servers are running."
echo " Backend  : http://localhost:8000"
echo " Frontend : http://localhost:5173"
echo " API Docs : http://localhost:8000/docs"
echo " Press Ctrl-C to stop both."
echo "============================================================"
echo ""

# ---- Wait for either process to exit -------------------------------------
wait "$BACKEND_PID" "$FRONTEND_PID"
