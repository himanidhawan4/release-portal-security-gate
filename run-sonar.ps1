$projectPath = "C:\Projects\release-portal-security-gate"

Set-Location $projectPath

Write-Host "Stopping any running Java process..."
Get-Process java -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "Removing old SonarScanner working directory..."
if (Test-Path ".scannerwork") {
    Remove-Item ".scannerwork" -Recurse -Force
}

Write-Host "Starting SonarScanner..."
sonar-scanner