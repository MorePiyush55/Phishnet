# PowerShell helper to fix case-sensitive module resolution issues on Windows for the frontend
# Usage: Run from repo root in an elevated PowerShell if needed.
# This script will:  
# 1. Remove `frontend/node_modules` if it exists.  
# 2. Ensure the folder name casing for the frontend directory is `frontend` (lowercase) to avoid mixed-case paths.  
# 3. Reinstall node modules in `frontend` using npm.

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$frontendPath = Join-Path $repoRoot 'frontend'
$nodeModules = Join-Path $frontendPath 'node_modules'

Write-Host "Repo root: $repoRoot"
Write-Host "Frontend path: $frontendPath"

if (Test-Path $nodeModules) {
    Write-Host "Removing existing node_modules..."
    Remove-Item -Recurse -Force $nodeModules
} else {
    Write-Host "No node_modules found in frontend."
}

# Normalize directory casing: ensure a folder named exactly 'frontend' exists
$parent = Split-Path $frontendPath -Parent
$entries = Get-ChildItem -LiteralPath $parent
$found = $entries | Where-Object { $_.Name -ieq 'frontend' }
if (-not $found) {
    # Try to find a case-insensitive match and rename
    $match = $entries | Where-Object { $_.Name -like '*frontend*' -and $_.Name -ne 'frontend' }
    if ($match) {
        $old = Join-Path $parent $($match[0].Name)
        $new = Join-Path $parent 'frontend'
        Write-Host "Renaming $old -> $new to normalize casing..."
        Rename-Item -LiteralPath $old -NewName 'frontend'
    } else {
        Write-Host 'No frontend directory found to normalize. Aborting.'
        exit 1
    }
} else {
    Write-Host 'Frontend folder casing already normalized.'
}

# Run npm install in frontend
if (Test-Path $frontendPath) {
    Write-Host 'Running npm install in frontend (this may take a while)...'
    Push-Location $frontendPath
    npm install
    Pop-Location
    Write-Host 'npm install completed. Restart your editor/TS server if you use one.'
} else {
    Write-Host "Frontend path not found: $frontendPath"
    exit 1
}
