# PhishNet Frontend Setup Script for Windows

Write-Host "🛡️  PhishNet Frontend Setup" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

# Check if Node.js is installed
try {
    $nodeVersion = node --version
    Write-Host "✅ Node.js $nodeVersion detected" -ForegroundColor Green
    
    # Check Node.js version
    $majorVersion = [int]($nodeVersion -replace 'v(\d+)\..*', '$1')
    if ($majorVersion -lt 18) {
        Write-Host "❌ Node.js version 18+ is required. Current version: $nodeVersion" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Node.js is not installed. Please install Node.js 18+ first." -ForegroundColor Red
    exit 1
}

# Check if npm is installed
try {
    $npmVersion = npm --version
    Write-Host "✅ npm $npmVersion detected" -ForegroundColor Green
} catch {
    Write-Host "❌ npm is not installed." -ForegroundColor Red
    exit 1
}

# Navigate to frontend directory
Set-Location $PSScriptRoot

Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
npm install

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "❌ Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Create .env file if it doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "📝 Creating .env file..." -ForegroundColor Yellow
    @"
# PhishNet Frontend Environment Variables
REACT_APP_API_URL=http://localhost:8000
"@ | Out-File -FilePath ".env" -Encoding UTF8
    Write-Host "✅ .env file created" -ForegroundColor Green
} else {
    Write-Host "ℹ️  .env file already exists" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Make sure the backend server is running on port 8000" -ForegroundColor White
Write-Host "2. Start the development server: npm run dev" -ForegroundColor White
Write-Host "3. Open http://localhost:3000 in your browser" -ForegroundColor White
Write-Host ""
Write-Host "Demo credentials:" -ForegroundColor Cyan
Write-Host "  - Admin: admin/admin" -ForegroundColor White
Write-Host "  - Analyst: analyst/analyst" -ForegroundColor White
Write-Host ""
Write-Host "Happy coding! 🚀" -ForegroundColor Green

# Pause to show the output
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
