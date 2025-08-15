# Internal Audit Tracker - Restore Script
# PowerShell version for better Windows compatibility

Write-Host "====================================" -ForegroundColor Green
Write-Host "Internal Audit Tracker - Restore" -ForegroundColor Green  
Write-Host "====================================" -ForegroundColor Green
Write-Host ""

# Check Python installation
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python not found. Please install Python first." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Installing required packages..." -ForegroundColor Yellow
pip install flask

if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Some packages might already be installed." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Starting Internal Audit Tracker..." -ForegroundColor Green
Write-Host ""
Write-Host "Dashboard will be available at: http://127.0.0.1:5000" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Start the Flask application
python app.py
