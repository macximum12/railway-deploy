Write-Host ""
Write-Host "========================================"
Write-Host " AUDIT TRACKING SYSTEM - LOGIN DEMO"
Write-Host "========================================"
Write-Host ""
Write-Host "Starting Flask application with login system..." -ForegroundColor Green
Write-Host ""
Write-Host "Login Credentials:" -ForegroundColor Yellow
Write-Host "  Username: admin" -ForegroundColor Cyan
Write-Host "  Password: admin" -ForegroundColor Cyan
Write-Host ""
Write-Host "The application will open at:" -ForegroundColor Yellow
Write-Host "  http://127.0.0.1:5000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Red
Write-Host ""
Write-Host "========================================" 
Write-Host ""

# Start the Flask application
python app.py

Write-Host ""
Write-Host "Server stopped." -ForegroundColor Yellow
Read-Host "Press Enter to exit"
