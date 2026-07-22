@echo off
REM agentchattr - starts server (if not running) + GitHub Copilot CLI wrapper
REM Usage: start_copilot.bat
REM Requires the copilot CLI on PATH. First launch prompts GitHub login.
cd /d "%~dp0.."

REM Auto-create venv and install deps on first run
if not exist ".venv" (
    python -m venv .venv
    .venv\Scripts\pip install -q -r requirements.txt >nul 2>nul
)
call .venv\Scripts\activate.bat

REM Pre-flight: check that copilot CLI is installed
where copilot >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Error: "copilot" was not found on PATH.
    echo   Install with: npm install -g @github/copilot
    echo   See https://github.com/github/copilot-cli for details.
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

python wrapper.py copilot
if %errorlevel% neq 0 (
    echo.
    echo   Agent exited unexpectedly. Check the output above.
    pause
)
