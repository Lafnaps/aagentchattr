@echo off
REM agentchattr — starts server (if not running) + Codex wrapper (auto-approve mode)
cd /d "%~dp0.."

REM Auto-create venv and install deps on first run
if not exist ".venv" (
    python -m venv .venv
    .venv\Scripts\pip install -q -r requirements.txt >nul 2>nul
)
call .venv\Scripts\activate.bat

REM Pre-flight: check that codex CLI is installed
where codex >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Error: "codex" was not found on PATH.
    echo   Install it first, then try again.
    echo.
    pause
    exit /b 1
)

REM Server is managed by the 'Agentchattr Server' Scheduled Task (R1):
REM launchers are wait-only and never start the server themselves.
call "%~dp0wait-for-server.bat"
if %errorlevel% neq 0 (
    pause
    exit /b 1
)

python wrapper.py codex -- --dangerously-bypass-approvals-and-sandbox
