# PhishNet Google Cloud Setup - PowerShell Script
# Automates Google Cloud Console configuration for Gmail OAuth

param(
    [Parameter(Mandatory=$true)]
    [string]$ProjectId,
    
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [Parameter(Mandatory=$true)]
    [string]$BackendUrl,
    
    [string]$SupportEmail = "support@$Domain"
)

# Configuration
$FrontendUrl = "https://$Domain"
$RedirectUri = "$BackendUrl/api/v1/auth/gmail/callback"

Write-Host "🚀 PhishNet Google Cloud Setup" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "Project ID: $ProjectId"
Write-Host "Domain: $Domain"
Write-Host "Backend: $BackendUrl"
Write-Host "Frontend: $FrontendUrl"
Write-Host ""

# Check if gcloud is installed
try {
    gcloud version | Out-Null
    Write-Host "✅ gcloud CLI found" -ForegroundColor Green
} catch {
    Write-Host "❌ gcloud CLI not found. Please install:" -ForegroundColor Red
    Write-Host "   https://cloud.google.com/sdk/docs/install"
    exit 1
}

# Check authentication
$authList = gcloud auth list --format=json | ConvertFrom-Json
$activeAccount = $authList | Where-Object { $_.status -eq "ACTIVE" }

if (-not $activeAccount) {
    Write-Host "❌ No active gcloud account. Please run:" -ForegroundColor Red
    Write-Host "   gcloud auth login"
    exit 1
}

Write-Host "✅ Authenticated as: $($activeAccount.account)" -ForegroundColor Green

# Create project
Write-Host "🔄 Creating project: $ProjectId" -ForegroundColor Yellow

try {
    gcloud projects describe $ProjectId | Out-Null
    Write-Host "✅ Project $ProjectId already exists" -ForegroundColor Green
} catch {
    gcloud projects create $ProjectId --name="PhishNet Gmail Integration"
    Write-Host "✅ Created project: $ProjectId" -ForegroundColor Green
}

# Set active project
gcloud config set project $ProjectId

# Enable APIs
Write-Host "🔄 Enabling APIs..." -ForegroundColor Yellow

$apis = @(
    "gmail.googleapis.com",
    "people.googleapis.com", 
    "pubsub.googleapis.com",
    "cloudbuild.googleapis.com",
    "secretmanager.googleapis.com",
    "iap.googleapis.com"
)

foreach ($api in $apis) {
    Write-Host "  Enabling $api"
    gcloud services enable $api --project=$ProjectId
}

Write-Host "✅ All APIs enabled" -ForegroundColor Green

# Create Pub/Sub resources
Write-Host "🔄 Creating Pub/Sub resources..." -ForegroundColor Yellow

$topicName = "phishnet-gmail-notifications"
$subscriptionName = "phishnet-gmail-sub"

gcloud pubsub topics create $topicName --project=$ProjectId
gcloud pubsub subscriptions create $subscriptionName --topic=$topicName --project=$ProjectId

# Create service account
$serviceAccountName = "phishnet-gmail"
$serviceAccountEmail = "$serviceAccountName@$ProjectId.iam.gserviceaccount.com"

gcloud iam service-accounts create $serviceAccountName --display-name="PhishNet Gmail Integration" --project=$ProjectId

# Grant permissions
$permissions = @(
    "roles/pubsub.subscriber",
    "roles/pubsub.viewer"
)

foreach ($permission in $permissions) {
    gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:$serviceAccountEmail" --role=$permission
}

Write-Host "✅ Pub/Sub resources created" -ForegroundColor Green

# Create service account key
$keyFile = "phishnet-gmail-$ProjectId.json"
gcloud iam service-accounts keys create $keyFile --iam-account=$serviceAccountEmail --project=$ProjectId

Write-Host "✅ Service account key created: $keyFile" -ForegroundColor Green

# Generate OAuth configuration template
$oauthConfig = @{
    web = @{
        client_id = "REPLACE_WITH_ACTUAL_CLIENT_ID"
        client_secret = "REPLACE_WITH_ACTUAL_CLIENT_SECRET"  
        auth_uri = "https://accounts.google.com/o/oauth2/auth"
        token_uri = "https://oauth2.googleapis.com/token"
        auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
        redirect_uris = @($RedirectUri)
        javascript_origins = @($FrontendUrl)
    }
}

$oauthConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath "oauth_client_config.json" -Encoding UTF8

# Generate environment configuration
$envConfig = @"
# PhishNet Gmail OAuth Configuration
# Generated on $(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")

# Google Cloud Project
GOOGLE_CLOUD_PROJECT=$ProjectId

# OAuth 2.0 Credentials (from Google Cloud Console)
GMAIL_CLIENT_ID=REPLACE_WITH_CLIENT_ID
GMAIL_CLIENT_SECRET=REPLACE_WITH_CLIENT_SECRET

# OAuth Redirect URIs
GMAIL_REDIRECT_URI=$RedirectUri
FRONTEND_URL=$FrontendUrl

# Pub/Sub Configuration
PUBSUB_TOPIC=projects/$ProjectId/topics/$topicName
PUBSUB_SUBSCRIPTION=projects/$ProjectId/subscriptions/$subscriptionName
GOOGLE_APPLICATION_CREDENTIALS=./$keyFile

# Security Settings (generate these!)
ENCRYPTION_KEY=GENERATE_32_BYTE_KEY_HERE
SECRET_KEY=GENERATE_JWT_SECRET_HERE

# Additional URLs for OAuth consent
PRIVACY_POLICY_URL=https://$Domain/privacy
TERMS_OF_SERVICE_URL=https://$Domain/terms
SUPPORT_EMAIL=$SupportEmail

# Environment
ENVIRONMENT=production
DEBUG=false
"@

$envConfig | Out-File -FilePath ".env.production" -Encoding UTF8

# Generate key generation script
$keyGenScript = @"
import secrets
import base64

# Generate encryption key (32 bytes for Fernet)
encryption_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
print(f"ENCRYPTION_KEY={encryption_key}")

# Generate JWT secret (32 bytes)
jwt_secret = secrets.token_urlsafe(32)
print(f"SECRET_KEY={jwt_secret}")
"@

$keyGenScript | Out-File -FilePath "generate_keys.py" -Encoding UTF8

Write-Host "✅ Configuration files generated" -ForegroundColor Green

# Manual setup instructions
Write-Host ""
Write-Host "📋 MANUAL SETUP REQUIRED" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. OAuth Consent Screen Setup:" -ForegroundColor Yellow
Write-Host "   URL: https://console.cloud.google.com/apis/credentials/consent?project=$ProjectId"
Write-Host "   - Application name: PhishNet Email Security"
Write-Host "   - User support email: $SupportEmail" 
Write-Host "   - Authorized domains: $Domain"
Write-Host "   - Privacy Policy: https://$Domain/privacy"
Write-Host "   - Terms of Service: https://$Domain/terms"
Write-Host ""
Write-Host "   Required Scopes:"
Write-Host "   - https://www.googleapis.com/auth/gmail.readonly"
Write-Host "   - https://www.googleapis.com/auth/gmail.modify"
Write-Host "   - https://www.googleapis.com/auth/gmail.labels"
Write-Host "   - openid"
Write-Host "   - email"
Write-Host "   - profile"
Write-Host ""
Write-Host "2. Create OAuth Credentials:" -ForegroundColor Yellow
Write-Host "   URL: https://console.cloud.google.com/apis/credentials?project=$ProjectId"
Write-Host "   - Click 'Create Credentials' > 'OAuth client ID'"
Write-Host "   - Application type: Web application"
Write-Host "   - Name: PhishNet Web Client"
Write-Host "   - Authorized JavaScript origins: $FrontendUrl"
Write-Host "   - Authorized redirect URIs: $RedirectUri"
Write-Host ""
Write-Host "3. Generate Security Keys:" -ForegroundColor Yellow
Write-Host "   python generate_keys.py"
Write-Host ""
Write-Host "4. Update .env.production with:" -ForegroundColor Yellow
Write-Host "   - Actual OAuth client ID and secret"
Write-Host "   - Generated encryption and JWT keys"
Write-Host ""
Write-Host "✅ Files created:" -ForegroundColor Green
Write-Host "   - .env.production (environment config)"
Write-Host "   - oauth_client_config.json (OAuth template)" 
Write-Host "   - $keyFile (service account key)"
Write-Host "   - generate_keys.py (key generator)"
Write-Host ""
Write-Host "⚠️  SECURITY:" -ForegroundColor Red
Write-Host "   - Store client secret securely (use environment variables)"
Write-Host "   - Add $keyFile to .gitignore"
Write-Host "   - Deploy service account key to backend securely"
Write-Host "   - Create privacy policy and terms pages"

# Open relevant URLs
Write-Host ""
Write-Host "🔗 Opening Google Cloud Console..." -ForegroundColor Cyan
Start-Process "https://console.cloud.google.com/apis/credentials/consent?project=$ProjectId"
Start-Sleep 2
Start-Process "https://console.cloud.google.com/apis/credentials?project=$ProjectId"

Write-Host ""
Write-Host "🎉 Setup complete! Follow the manual steps above." -ForegroundColor Green
