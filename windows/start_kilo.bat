@echo off
REM agentchattr — starts server (if not running) + Kilo wrapper
REM Usage: start_kilo.bat [provider/model]
REM   e.g. start_kilo.bat anthropic/claude-sonnet-4-20250514
REM   Omit the model to use Kilo's configured default.
cd /d "%~dp0.."

REM Auto-create venv and install deps on first run
if not exist ".venv" (
    python -m venv .venv
    .venv\Scripts\pip install -q -r requirements.txt >nul 2>nul
)
call .venv\Scripts\activate.bat

REM Pre-flight: check that kilo CLI is installed
where kilo >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Error: "kilo" was not found on PATH.
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

if "%~1"=="" (
    python wrapper.py kilo
) else (
    python wrapper.py kilo -- -m %1
)
if %errorlevel% neq 0 (
    echo.
    echo   Agent exited unexpectedly. Check the output above.
    pause
)
