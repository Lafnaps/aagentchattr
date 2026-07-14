# Thin foreground launcher for the trusted local night supervisor (MVP).
# Changes to the repository root, invokes the Python module with -B, waits,
# and returns the supervisor's exit code. No service, no scheduled task.

param(
    [Parameter(Mandatory = $true)][string]$Root,
    [int]$DurationSeconds,
    [double]$PollSeconds,
    [string]$Profiles,
    [string]$Claude,
    [string]$QuotaCache
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$argv = @('-B', '-m', 'autonomy.local_supervisor', '--root', $Root)
if ($PSBoundParameters.ContainsKey('DurationSeconds')) {
    $argv += @('--duration-seconds', $DurationSeconds.ToString([System.Globalization.CultureInfo]::InvariantCulture))
}
if ($PSBoundParameters.ContainsKey('PollSeconds')) {
    $argv += @('--poll-seconds', $PollSeconds.ToString([System.Globalization.CultureInfo]::InvariantCulture))
}
if ($PSBoundParameters.ContainsKey('Profiles')) {
    $argv += @('--profiles', $Profiles)
}
if ($PSBoundParameters.ContainsKey('Claude')) {
    $argv += @('--claude', $Claude)
}
if ($PSBoundParameters.ContainsKey('QuotaCache')) {
    $argv += @('--quota-cache', $QuotaCache)
}

& python @argv
exit $LASTEXITCODE
