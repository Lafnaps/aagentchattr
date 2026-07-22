@echo off
REM agentchattr - claude-test1-fable (Fable-INFRA, OD-001) (account .claude-test1, WC V:\Programming\Projects\TradeStation-AI\test1)
set "CLAUDE_CONFIG_DIR=C:\Users\A\.claude-test1"
cd /d "%~dp0.."

REM Auto-create venv and install deps on first run
if not exist ".venv" (
    python -m venv .venv
    .venv\Scripts\pip install -q -r requirements.txt >nul 2>nul
)
call .venv\Scripts\activate.bat

REM Pre-flight: check that claude CLI is installed
where claude >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Error: "claude" was not found on PATH.
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

python wrapper.py claude-test1-fable --dangerously-skip-permissions
if %errorlevel% neq 0 (
    echo.
    echo   Agent exited unexpectedly. Check the output above.
    pause
)
