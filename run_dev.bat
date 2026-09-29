@echo off
REM ============================================================
REM run_dev.bat — Local development startup script (Windows)
REM
REM Starts FastAPI backend (port 8000) and React frontend (port 5173)
REM in two separate windows. No Docker required.
REM
REM Prerequisites:
REM   1. Python 3.11+ virtualenv activated  (or conda env)
REM   2. pip install -r requirements.txt
REM   3. cd frontend && npm install
REM   4. .env file exists with all required keys (see .env.example)
REM
REM Author : Member 3 — Vercel Setup & API Skeleton
REM ============================================================

setlocal

REM ---- Resolve project root (directory containing this script) ----
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ============================================================
echo  Agentic SOC Analyst — Local Dev Startup
echo ============================================================

REM ---- Check .env exists ----
if not exist ".env" (
    echo [WARN] .env not found. Copying from .env.example ...
    copy ".env.example" ".env" >nul
    echo [WARN] Please fill in your API keys in .env before running agents.
)

REM ---- Check Python environment ----
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found on PATH. Install Python 3.11+ and try again.
    pause
    exit /b 1
)

REM ---- Check Node environment ----
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found on PATH. Install Node.js 18+ and try again.
    pause
    exit /b 1
)

REM ---- Install frontend deps if node_modules missing ----
if not exist "frontend\node_modules" (
    echo [INFO] Installing frontend dependencies ...
    cd frontend
    npm install
    cd ..
)

echo.
echo [INFO] Starting FastAPI backend on http://localhost:8000 ...
echo [INFO] API docs will be at http://localhost:8000/docs
echo.

REM Start FastAPI in a new terminal window
start "SOC-Analyst Backend" cmd /k "cd /d %ROOT% && uvicorn api.main:app --reload --port 8000 --host 0.0.0.0"

REM Small delay so the backend window opens first
timeout /t 2 /nobreak >nul

echo [INFO] Starting React frontend on http://localhost:5173 ...
echo.

REM Start React dev server in a new terminal window
start "SOC-Analyst Frontend" cmd /k "cd /d %ROOT%\frontend && npm run dev"

echo.
echo ============================================================
echo  Both servers are starting in separate windows.
echo  Backend  : http://localhost:8000
echo  Frontend : http://localhost:5173
echo  API Docs : http://localhost:8000/docs
echo ============================================================
echo  Press any key to exit this launcher (servers keep running).
echo ============================================================
pause >nul
