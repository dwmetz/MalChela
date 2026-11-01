# MalChela release build (Windows)
# PowerShell counterpart of release.sh / release-unattended.sh.
#
#   .\release.ps1                 prompts for parallel or throttled build
#   .\release.ps1 -Unattended     parallel build, no prompt
#   release.cmd [-Unattended]     same, from cmd or a restricted execution policy

param([switch]$Unattended)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$tools = @(
    'malchela', 'fileminer', 'mstrings', 'hashit', 'hashcheck', 'mzcount', 'mzhash', 'xmzhash',
    'combine_yara', 'strings_to_yara', 'nsrlquery', 'extract_samples', 'dpp_extract', 'unpack',
    'about', 'fileanalyzer', 'MITRE_lookup', 'tiquery', 'plist_analyzer', 'macho_info',
    'codesign_check', 'yara_scan'
)

$jobs = @()
if (-not $Unattended) {
    Write-Host 'Choose build mode:'
    Write-Host '1) Default parallel build (fast, uses all CPU cores)'
    Write-Host '2) Throttled build (-j 1, for low-powered systems)'
    $mode = Read-Host 'Enter 1 or 2 [1]'
    if ($mode -eq '2') { $jobs = @('-j', '1') }
} else {
    Write-Host 'Defaulting to parallel build. Run .\release.ps1 without -Unattended for throttled mode.'
}

$failed = @()
foreach ($tool in $tools) {
    Write-Host "Building release for $tool..."
    & cargo build @jobs --release -p $tool
    if ($LASTEXITCODE -ne 0) { $failed += $tool }
}

Write-Host ''
if ($failed.Count -eq 0) {
    Write-Host "All $($tools.Count) tools built: target\release\" -ForegroundColor Green
} else {
    Write-Host "Built $($tools.Count - $failed.Count) of $($tools.Count). Failed: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
