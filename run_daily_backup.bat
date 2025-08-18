@echo off
REM Daily Backup Script for Windows
REM Schedule this to run daily using Windows Task Scheduler

echo.
echo ================================
echo   DAILY BACKUP SYSTEM
echo ================================
echo.
echo Starting backup at %DATE% %TIME%
echo.

REM Change to the application directory
cd /d "%~dp0"

REM Run the Python backup script
python daily_backup.py

REM Check if backup was successful
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Backup completed successfully!
    echo.
) else (
    echo.
    echo ❌ Backup failed with error code %ERRORLEVEL%
    echo Check backup.log for details
    echo.
)

REM Log the backup attempt
echo Backup attempt completed at %DATE% %TIME% >> backup_schedule.log

echo.
echo Press any key to exit...
pause >nul
