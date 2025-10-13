@echo off
REM PhishNet IMAP Testing - Quick Commands
REM For testing with real emails from propam5553@gmail.com

echo ============================================================
echo PhishNet IMAP Email Integration - Quick Test Commands
echo Using REAL emails from: propam5553@gmail.com
echo ============================================================
echo.

:menu
echo.
echo Select an option:
echo.
echo 1. Run IMAP Integration Test
echo 2. Start FastAPI Server
echo 3. Test IMAP Connection (API)
echo 4. List Pending Emails (API)
echo 5. Get Statistics (API)
echo 6. Open Gmail (propam5553@gmail.com)
echo 7. Open App Password Page
echo 8. View Configuration Guide
echo 9. Exit
echo.

set /p choice="Enter your choice (1-9): "

if "%choice%"=="1" goto test_imap
if "%choice%"=="2" goto start_server
if "%choice%"=="3" goto test_connection
if "%choice%"=="4" goto list_emails
if "%choice%"=="5" goto get_stats
if "%choice%"=="6" goto open_gmail
if "%choice%"=="7" goto open_apppass
if "%choice%"=="8" goto view_docs
if "%choice%"=="9" goto end

echo Invalid choice. Please try again.
goto menu

:test_imap
echo.
echo Running IMAP Integration Test...
echo ============================================================
cd backend
python test_imap_integration.py
cd ..
echo.
echo Test complete! Check results above.
pause
goto menu

:start_server
echo.
echo Starting FastAPI Server...
echo ============================================================
echo Server will start at: http://localhost:8000
echo API Docs at: http://localhost:8000/docs
echo Press Ctrl+C to stop server
echo.
cd backend
uvicorn app.main:app --reload
cd ..
goto menu

:test_connection
echo.
echo Testing IMAP Connection via API...
echo ============================================================
curl http://localhost:8000/api/v1/imap-emails/test-connection
echo.
echo.
pause
goto menu

:list_emails
echo.
echo Listing Pending Emails via API...
echo ============================================================
curl http://localhost:8000/api/v1/imap-emails/pending
echo.
echo.
pause
goto menu

:get_stats
echo.
echo Getting Analysis Statistics...
echo ============================================================
curl http://localhost:8000/api/v1/imap-emails/stats
echo.
echo.
pause
goto menu

:open_gmail
echo.
echo Opening Gmail for propam5553@gmail.com...
echo ============================================================
start https://mail.google.com/mail/u/propam5553@gmail.com
echo.
echo Gmail opened in browser.
pause
goto menu

:open_apppass
echo.
echo Opening App Password Page...
echo ============================================================
start https://myaccount.google.com/apppasswords
echo.
echo App Password page opened in browser.
echo Remember to:
echo 1. Enable 2FA first
echo 2. Select App: Mail
echo 3. Select Device: Other (PhishNet)
echo 4. Copy 16-character password
echo.
pause
goto menu

:view_docs
echo.
echo Opening Configuration Guides...
echo ============================================================
echo.
echo Available guides:
echo 1. REAL_EMAIL_SETUP.md - Complete setup guide
echo 2. IMAP_QUICK_START.md - Quick start guide
echo 3. IMAP_REFERENCE.md - Quick reference
echo 4. CONFIGURATION_UPDATE.md - Recent changes
echo.
echo Opening in default editor...
start backend\REAL_EMAIL_SETUP.md
echo.
pause
goto menu

:end
echo.
echo ============================================================
echo Thank you for using PhishNet IMAP Testing!
echo Remember: Use REAL emails from propam5553@gmail.com
echo ============================================================
echo.
exit
