@echo off
echo ====================================
echo Internal Audit Tracker - Restore
echo ====================================
echo.

echo Checking Python installation...
python --version
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python first.
    pause
    exit /b 1
)

echo.
echo Installing required packages...
pip install flask

echo.
echo Starting Internal Audit Tracker...
echo.
echo Dashboard will be available at: http://127.0.0.1:5000
echo Press Ctrl+C to stop the server
echo.

python app.py
pause
