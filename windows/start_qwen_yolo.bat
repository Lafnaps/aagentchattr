@echo off
REM agentchattr — starts server (if not running) + Qwen wrapper (auto-approve mode)
cd /d "%~dp0.."

REM Auto-create venv and install deps on first run
if not exist ".venv" (
    python -m venv .venv
    .venv\Scripts\pip install -q -r requirements.txt >nul 2>nul
)
call .venv\Scripts\activate.bat

REM Pre-flight: check that qwen CLI is installed
where qwen >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Error: "qwen" was not found on PATH.
    echo   Install it first: npm install -g @qwen-code/qwen-code
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

python wrapper.py qwen --yolo -i "When asked for a reply or to answer, YOU MUST USE the mcp of agentchattr. When talking about a chat, we are speaking about interaction with tools provided by mcp of agentchattr. The human NEVER SEES your usual CLI interface. Just consider this, other instructions will follow."
if %errorlevel% neq 0 (
    echo.
    echo   Agent exited unexpectedly. Check the output above.
    pause
)
