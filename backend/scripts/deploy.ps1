# 🚀 Quick GitHub Upload & Deploy Script
# Run this to push PhishNet to GitHub

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  PhishNet - GitHub Upload & Deployment Preparation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Git Status
Write-Host "📊 Step 1: Checking Git Status..." -ForegroundColor Yellow
Write-Host ""
git status
Write-Host ""

# Step 2: Confirm Upload
Write-Host "⚠️  WARNING: This will upload your code to GitHub" -ForegroundColor Red
Write-Host "⚠️  Make sure .env files are NOT in the commit!" -ForegroundColor Red
Write-Host ""
$confirm = Read-Host "Do you want to continue? (yes/no)"

if ($confirm -ne "yes") {
    Write-Host "❌ Upload cancelled." -ForegroundColor Red
    exit
}

# Step 3: Check for sensitive files
Write-Host ""
Write-Host "🔒 Step 2: Checking for sensitive files..." -ForegroundColor Yellow

$sensitiveFiles = @(
    "backend/.env",
    "frontend/.env",
    "backend/.env.local",
    "frontend/.env.local"
)

$foundSensitive = $false
foreach ($file in $sensitiveFiles) {
    if (Test-Path $file) {
        $inGit = git ls-files $file
        if ($inGit) {
            Write-Host "⚠️  WARNING: $file is tracked by git!" -ForegroundColor Red
            $foundSensitive = $true
        } else {
            Write-Host "✅ $file is properly ignored" -ForegroundColor Green
        }
    }
}

if ($foundSensitive) {
    Write-Host ""
    Write-Host "❌ ERROR: Sensitive files found in git!" -ForegroundColor Red
    Write-Host "Run 'git rm --cached backend/.env' to remove them" -ForegroundColor Yellow
    $override = Read-Host "Continue anyway? (yes/no)"
    if ($override -ne "yes") {
        exit
    }
}

# Step 4: Stage all changes
Write-Host ""
Write-Host "📦 Step 3: Staging all changes..." -ForegroundColor Yellow
git add .
Write-Host "✅ All changes staged" -ForegroundColor Green

# Step 5: Commit
Write-Host ""
Write-Host "💾 Step 4: Creating commit..." -ForegroundColor Yellow
$commitMessage = @"
Add IMAP email integration and deployment configuration

New Features:
- ThePhish-style IMAP email forwarding workflow
- QuickIMAPService for real email parsing
- 4 REST API endpoints for email analysis
- Integration with EnhancedPhishingAnalyzer (5 modules)
- Real email testing with propam5553@gmail.com

Documentation:
- DEPLOYMENT_GUIDE.md - Complete deployment instructions
- REAL_EMAIL_SETUP.md - Real email configuration
- IMAP_QUICK_START.md - Quick setup guide
- 2000+ lines of comprehensive docs

Deployment Ready:
- Render.yaml configured for backend
- Vercel.json configured for frontend
- MongoDB Atlas integration
- Environment variable templates
- Production-ready settings

Testing:
- test_imap_integration.py - Complete workflow test
- quick_test.bat - Windows testing utility
- All documentation updated for propam5553@gmail.com

This version is ready for deployment on Render (backend) and Vercel (frontend)
"@

git commit -m $commitMessage
Write-Host "✅ Commit created" -ForegroundColor Green

# Step 6: Check remote
Write-Host ""
Write-Host "🔗 Step 5: Checking GitHub remote..." -ForegroundColor Yellow
$remote = git remote -v

if ($remote -match "origin") {
    Write-Host "✅ Remote 'origin' already configured:" -ForegroundColor Green
    Write-Host $remote
    Write-Host ""
    $updateRemote = Read-Host "Update remote URL? (yes/no)"
    
    if ($updateRemote -eq "yes") {
        $repoUrl = Read-Host "Enter GitHub repository URL"
        git remote set-url origin $repoUrl
        Write-Host "✅ Remote URL updated" -ForegroundColor Green
    }
} else {
    Write-Host "⚠️  No remote configured" -ForegroundColor Yellow
    Write-Host "Your GitHub repository should be: https://github.com/MorePiyush55/Phishnet.git" -ForegroundColor Cyan
    Write-Host ""
    $repoUrl = Read-Host "Enter GitHub repository URL (or press Enter for default)"
    
    if ([string]::IsNullOrWhiteSpace($repoUrl)) {
        $repoUrl = "https://github.com/MorePiyush55/Phishnet.git"
    }
    
    git remote add origin $repoUrl
    Write-Host "✅ Remote 'origin' added: $repoUrl" -ForegroundColor Green
}

# Step 7: Push to GitHub
Write-Host ""
Write-Host "🚀 Step 6: Pushing to GitHub..." -ForegroundColor Yellow
Write-Host "This may take a few minutes for first push..." -ForegroundColor Cyan
Write-Host ""

try {
    git push -u origin main
    Write-Host ""
    Write-Host "✅ Successfully pushed to GitHub!" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "⚠️  Push failed. Trying with force (only if needed)..." -ForegroundColor Yellow
    Write-Host ""
    $force = Read-Host "Force push? This will overwrite remote. (yes/no)"
    
    if ($force -eq "yes") {
        git push -u origin main --force
        Write-Host "✅ Force pushed to GitHub" -ForegroundColor Green
    } else {
        Write-Host "❌ Push cancelled" -ForegroundColor Red
        exit
    }
}

# Step 8: Summary
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ✅ SUCCESS! Code Uploaded to GitHub" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📍 Your Repository: https://github.com/MorePiyush55/Phishnet" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎯 Next Steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Deploy Backend on Render:" -ForegroundColor White
Write-Host "   - Go to: https://render.com" -ForegroundColor Cyan
Write-Host "   - New Web Service → Connect GitHub → MorePiyush55/Phishnet" -ForegroundColor Cyan
Write-Host "   - Root Directory: backend" -ForegroundColor Cyan
Write-Host "   - See DEPLOYMENT_GUIDE.md for details" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Deploy Frontend on Vercel:" -ForegroundColor White
Write-Host "   - Go to: https://vercel.com" -ForegroundColor Cyan
Write-Host "   - New Project → Import MorePiyush55/Phishnet" -ForegroundColor Cyan
Write-Host "   - Root Directory: frontend" -ForegroundColor Cyan
Write-Host "   - See DEPLOYMENT_GUIDE.md for details" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Setup MongoDB Atlas:" -ForegroundColor White
Write-Host "   - Go to: https://cloud.mongodb.com" -ForegroundColor Cyan
Write-Host "   - Create free M0 cluster" -ForegroundColor Cyan
Write-Host "   - Get connection string" -ForegroundColor Cyan
Write-Host "   - Add to Render environment variables" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Configure Environment Variables:" -ForegroundColor White
Write-Host "   - IMAP credentials (propam5553@gmail.com)" -ForegroundColor Cyan
Write-Host "   - MongoDB connection string" -ForegroundColor Cyan
Write-Host "   - SECRET_KEY and JWT_SECRET_KEY" -ForegroundColor Cyan
Write-Host "   - CORS origins" -ForegroundColor Cyan
Write-Host ""
Write-Host "📚 Documentation:" -ForegroundColor Yellow
Write-Host "   - DEPLOYMENT_GUIDE.md - Complete deployment guide" -ForegroundColor Cyan
Write-Host "   - REAL_EMAIL_SETUP.md - Email configuration" -ForegroundColor Cyan
Write-Host "   - IMAP_QUICK_START.md - Quick setup" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎉 Your PhishNet is ready for deployment!" -ForegroundColor Green
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Open DEPLOYMENT_GUIDE.md
$openGuide = Read-Host "Open DEPLOYMENT_GUIDE.md now? (yes/no)"
if ($openGuide -eq "yes") {
    Start-Process "DEPLOYMENT_GUIDE.md"
}

Write-Host "Happy Deploying! 🚀" -ForegroundColor Green
