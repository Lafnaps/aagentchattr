@echo off
REM agentchattr — server wait/status only (R1): the server itself is managed by
REM the 'Agentchattr Server' Scheduled Task and is NEVER started from here.
REM Install (staged Disabled): pwsh -File V:\Programming\Projects\AI\Infra\launchers\Install-AgentchattrServerTask.ps1
call "%~dp0wait-for-server.bat"
echo.
echo === wait-for-server exited with code %ERRORLEVEL% ===
pause
