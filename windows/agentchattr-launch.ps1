# agentchattr-launch.ps1 — канонический adapter запуска обёрнутого агента.
# Воссоздан 2026-07-20 (Fable, класс B по OD-012): прежний файл существовал
# только в отозванном WIP f54fdf9 и исчез с диска 14.07 вместе с отзывом
# restart-wrapper кандидата. Эта версия — минимальная (venv -> сервер ->
# wrapper), БЕЗ handoff-механики отозванного контура. Паттерн — как в
# проверенных windows\start_*.bat. Постфактум-ревью: Sol (автор Fable).
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
    [string]$Agent,
    [string]$ConfigDir,
    [string[]]$AgentArgs,
    [switch]$Safe,
    [int]$ServerPort = 8300,
    [string]$WindowTitle,
    [switch]$ValidateOnly
)
$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$py = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    throw ".venv не найден ($py); создайте: python -m venv .venv; .venv\Scripts\pip install -r requirements.txt"
}
$prevCwd = Get-Location
$prevTitle = try { $Host.UI.RawUI.WindowTitle } catch { $null }
$prevConfig = $env:CLAUDE_CONFIG_DIR
try {
    if ($ConfigDir) { $env:CLAUDE_CONFIG_DIR = $ConfigDir }
    if ($WindowTitle) { try { $Host.UI.RawUI.WindowTitle = $WindowTitle } catch {} }
    Set-Location $Root
    # R1 (id4941/id4945): сервер управляется Scheduled Task 'Agentchattr Server'
    # (AI\Infra\launchers) и НИКОГДА не запускается отсюда — только bounded-
    # ожидание через единый wait-only помощник.
    & cmd.exe /c ('"' + (Join-Path $PSScriptRoot 'wait-for-server.bat') + '" ' + $ServerPort)
    if ($LASTEXITCODE -ne 0) {
        throw "Сервер agentchattr не слушает :$ServerPort (wait-only; таск: AI\Infra\launchers\Install-AgentchattrServerTask.ps1)"
    }
    $wrapperArgs = @('wrapper.py', $Agent)
    if ($AgentArgs) {
        $wrapperArgs += '--'
        $wrapperArgs += $AgentArgs
    } elseif (-not $Safe -and $Agent -like 'claude-*') {
        # паттерн start_claude*-батников: full-access по умолчанию, -Safe отключает
        $wrapperArgs += '--dangerously-skip-permissions'
    }
    if ($ValidateOnly) {
        Write-Host "OK: $py $($wrapperArgs -join ' ')  (root=$Root, порт=$ServerPort)"
        return
    }
    & $py @wrapperArgs
} finally {
    Set-Location $prevCwd
    if ($null -ne $prevConfig) { $env:CLAUDE_CONFIG_DIR = $prevConfig }
    elseif ($ConfigDir) { Remove-Item Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue }
    if ($null -ne $prevTitle) { try { $Host.UI.RawUI.WindowTitle = $prevTitle } catch {} }
}
