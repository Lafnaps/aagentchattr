@echo off
REM agentchattr - starts server (if not running) + CodeBuddy wrapper
REM Usage: start_codebuddy.bat
REM Requires the codebuddy CLI on PATH. First launch prompts interactive login.
cd /d "%~dp0.."

REM Auto-create venv and install deps on first run
if not exist ".venv" (
    python -m venv .venv
    .venv\Scripts\pip install -q -r requirements.txt >nul 2>nul
)
call .venv\Scripts\activate.bat

REM Pre-flight: check that codebuddy CLI is installed
where codebuddy >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Error: "codebuddy" was not found on PATH.
    echo   Install it from https://www.codebuddy.ai/cli then try again.
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

python wrapper.py codebuddy
if %errorlevel% neq 0 (
    echo.
    echo   Agent exited unexpectedly. Check the output above.
    pause
)
