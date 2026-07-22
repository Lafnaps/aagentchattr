@echo off
REM agentchattr - bounded wait-only helper (R1, id4941/id4945).
REM The server is OWNED by the 'Agentchattr Server' Scheduled Task
REM (AI\Infra\launchers\Install-AgentchattrServerTask.ps1 + Run-AgentchattrServer.ps1).
REM This helper NEVER starts it. Usage: wait-for-server.bat [port] [tries]
REM Exit 0 = port listening; exit 1 = still down after ~tries seconds.
setlocal
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8300"
set "TRIES=%~2"
if "%TRIES%"=="" set "TRIES=30"
set /a COUNT=0
:wait_loop
netstat -ano | findstr ":%PORT%" | findstr LISTENING >nul 2>&1
if %errorlevel% equ 0 (
    echo agentchattr server: LISTENING on :%PORT%
    endlocal & exit /b 0
)
set /a COUNT+=1
if %COUNT% geq %TRIES% (
    echo agentchattr server did NOT come up on :%PORT% after %TRIES% tries.
    echo It is managed by the 'Agentchattr Server' Scheduled Task; launchers never start it.
    echo Install ^(staged Disabled^): pwsh -File V:\Programming\Projects\AI\Infra\launchers\Install-AgentchattrServerTask.ps1
    endlocal & exit /b 1
)
REM ping = 1s delay that works without console stdin (timeout /t requires it)
ping -n 2 127.0.0.1 >nul
goto :wait_loop
