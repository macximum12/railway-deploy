# Daily Backup PowerShell Script
# Advanced backup script with better error handling and notifications

param(
    [switch]$Silent = $false
)

# Set script location and change to app directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    if (-not $Silent) {
        Write-Host $Message -ForegroundColor $Color
    }
}

# Function to log messages
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path "backup_schedule.log" -Value $logMessage
    if (-not $Silent) {
        Write-Host $logMessage
    }
}

try {
    Write-ColorOutput "" 
    Write-ColorOutput "================================" "Cyan"
    Write-ColorOutput "   DAILY BACKUP SYSTEM" "Cyan"
    Write-ColorOutput "================================" "Cyan"
    Write-ColorOutput ""
    
    $startTime = Get-Date
    Write-Log "Starting backup process"
    Write-ColorOutput "Starting backup at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Yellow"
    Write-ColorOutput ""
    
    # Check if Python is available
    try {
        $pythonVersion = python --version 2>&1
        Write-ColorOutput "✅ Python found: $pythonVersion" "Green"
    }
    catch {
        Write-ColorOutput "❌ Python not found in PATH" "Red"
        Write-Log "ERROR: Python not found in PATH"
        exit 1
    }
    
    # Check if backup script exists
    if (-not (Test-Path "daily_backup.py")) {
        Write-ColorOutput "❌ daily_backup.py not found" "Red"
        Write-Log "ERROR: daily_backup.py not found"
        exit 1
    }
    
    # Run the backup script
    Write-ColorOutput "🔄 Running backup script..." "Yellow"
    $process = Start-Process -FilePath "python" -ArgumentList "daily_backup.py" -Wait -PassThru -NoNewWindow
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    if ($process.ExitCode -eq 0) {
        Write-ColorOutput "" 
        Write-ColorOutput "✅ Backup completed successfully!" "Green"
        Write-ColorOutput "⏱️  Duration: $($duration.ToString('hh\:mm\:ss'))" "Green"
        Write-Log "Backup completed successfully in $($duration.ToString('hh\:mm\:ss'))"
        
        # Check backup directory size
        if (Test-Path "backups") {
            $backupSize = (Get-ChildItem -Path "backups" -Recurse | Measure-Object -Property Length -Sum).Sum
            $backupSizeGB = [math]::Round($backupSize / 1GB, 2)
            Write-ColorOutput "💾 Total backup size: $backupSizeGB GB" "Cyan"
        }
        
    } else {
        Write-ColorOutput ""
        Write-ColorOutput "❌ Backup failed with exit code $($process.ExitCode)" "Red"
        Write-ColorOutput "📋 Check backup.log for details" "Yellow"
        Write-Log "ERROR: Backup failed with exit code $($process.ExitCode)"
        
        # Try to show last few lines of backup.log if it exists
        if (Test-Path "backup.log") {
            Write-ColorOutput ""
            Write-ColorOutput "📋 Last few lines from backup.log:" "Yellow"
            Get-Content "backup.log" -Tail 5 | ForEach-Object {
                Write-ColorOutput "   $_" "Gray"
            }
        }
        
        exit $process.ExitCode
    }
    
} catch {
    Write-ColorOutput ""
    Write-ColorOutput "❌ Script execution failed: $($_.Exception.Message)" "Red"
    Write-Log "ERROR: Script execution failed: $($_.Exception.Message)"
    exit 1
}

Write-ColorOutput ""
if (-not $Silent) {
    Write-ColorOutput "Press Enter to exit..."
    Read-Host
}
