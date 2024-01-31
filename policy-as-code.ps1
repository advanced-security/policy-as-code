# Policy as Code Powershell script.

$pw = Split-Path -Parent $MyInvocation.MyCommand.Definition

if (Get-Command python -ErrorAction SilentlyContinue) {
    $env:PYTHONPATH = $pw + "\vendor"
    python -m ghascompliance $args
} else {
    Write-Host "Python is not installed. Please install Python (+3.9) and try again."
    Write-Host "Make sure that Python is added to the PATH environment variable."
}

