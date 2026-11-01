# MalChela Server Launcher (Windows)
# PowerShell counterpart of start_server.sh: creates the venv on first run,
# then starts the Flask server. Extra arguments are passed to the server.
#
#   .\server\start_server.ps1            (PowerShell)
#   server\start_server.cmd              (cmd, Explorer, or restricted execution policy)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv      = Join-Path $ScriptDir 'venv'
$VenvPy    = Join-Path $Venv 'Scripts\python.exe'

function Find-Python {
    # Prefer the py launcher; skip the Microsoft Store "python" alias stub,
    # which opens the Store instead of running Python.
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { return @{ Exe = $py.Source; Args = @('-3') } }
    foreach ($name in 'python3', 'python') {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -notlike '*\WindowsApps\*') { return @{ Exe = $cmd.Source; Args = @() } }
    }
    return $null
}

if (-not (Test-Path $VenvPy)) {
    $python = Find-Python
    if (-not $python) {
        Write-Host '[MalChela] Python 3 was not found.' -ForegroundColor Red
        Write-Host '           Install it from https://www.python.org (tick "Add python.exe to PATH")'
        Write-Host '           or run:  winget install Python.Python.3.12'
        exit 1
    }
    $venvArgs = @('-m', 'venv')
    if (Test-Path $Venv) {
        # A venv folder without Scripts\python.exe was made on macOS/Linux (bin/ layout).
        Write-Host '[MalChela] Existing venv is not a Windows venv; recreating it...'
        $venvArgs += '--clear'
    } else {
        Write-Host '[MalChela] Creating virtual environment...'
    }
    & $python.Exe @($python.Args + $venvArgs + $Venv)
    if ($LASTEXITCODE -ne 0) { Write-Host '[MalChela] venv creation failed.' -ForegroundColor Red; exit 1 }

    Write-Host '[MalChela] Installing dependencies...'
    & $VenvPy -m pip install --quiet flask flask-cors pyyaml
    if ($LASTEXITCODE -ne 0) { Write-Host '[MalChela] pip install failed.' -ForegroundColor Red; exit 1 }
    Write-Host '[MalChela] Dependencies installed.'
}

# Tool output is UTF-8 (box drawing, defanged indicators); make Python agree.
$env:PYTHONUTF8 = '1'

Write-Host '[MalChela] Starting server...'
& $VenvPy (Join-Path $ScriptDir 'malchela_server.py') @args
exit $LASTEXITCODE
