# Build the Windows .exe. Run on Windows (PowerShell) with the project venv set up.
#   powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$py = if ($env:PYTHON) { $env:PYTHON } else { ".venv\Scripts\python.exe" }
& $py -m PyInstaller --noconfirm --clean packaging\securitysight.spec
Write-Host ""
Write-Host "Built: dist\securitysight\securitysight.exe"
