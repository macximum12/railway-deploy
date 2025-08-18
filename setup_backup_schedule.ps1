# Setup Daily Backup Task Scheduler
# Run this script as Administrator to create a scheduled task

param(
    [string]$BackupTime = "02:00",
    [switch]$Force = $false
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

$TaskName = "AuditTracker-DailyBackup"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackupScript = Join-Path $ScriptDir "run_daily_backup.ps1"

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "  BACKUP SCHEDULER SETUP" -ForegroundColor Cyan  
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if backup script exists
if (-not (Test-Path $BackupScript)) {
    Write-Host "❌ Backup script not found: $BackupScript" -ForegroundColor Red
    exit 1
}

try {
    # Check if task already exists
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    
    if ($existingTask -and -not $Force) {
        Write-Host "⚠️  Scheduled task '$TaskName' already exists!" -ForegroundColor Yellow
        $response = Read-Host "Do you want to replace it? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            exit 0
        }
    }
    
    # Remove existing task if it exists
    if ($existingTask) {
        Write-Host "🗑️  Removing existing task..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    
    Write-Host "📅 Creating scheduled task..." -ForegroundColor Yellow
    Write-Host "   Task Name: $TaskName" -ForegroundColor Cyan
    Write-Host "   Backup Time: $BackupTime daily" -ForegroundColor Cyan
    Write-Host "   Script: $BackupScript" -ForegroundColor Cyan
    Write-Host ""
    
    # Create the scheduled task action
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$BackupScript`" -Silent" -WorkingDirectory $ScriptDir
    
    # Create the scheduled task trigger (daily at specified time)
    $Trigger = New-ScheduledTaskTrigger -Daily -At $BackupTime
    
    # Create task settings
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
    
    # Create the principal (run as SYSTEM with highest privileges)
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Register the scheduled task
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Daily backup of Audit Tracker application and database with 365-day retention"
    
    Write-Host "✅ Scheduled task created successfully!" -ForegroundColor Green
    Write-Host ""
    
    # Show task information
    $task = Get-ScheduledTask -TaskName $TaskName
    Write-Host "📋 Task Details:" -ForegroundColor Cyan
    Write-Host "   Name: $($task.TaskName)" -ForegroundColor White
    Write-Host "   State: $($task.State)" -ForegroundColor White
    Write-Host "   Next Run: $($(Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo).NextRunTime)" -ForegroundColor White
    Write-Host ""
    
    # Test the backup immediately (optional)
    Write-Host "🧪 Would you like to test the backup now? (y/N): " -NoNewline -ForegroundColor Yellow
    $testResponse = Read-Host
    
    if ($testResponse -eq 'y' -or $testResponse -eq 'Y') {
        Write-Host ""
        Write-Host "🔄 Running test backup..." -ForegroundColor Yellow
        Start-ScheduledTask -TaskName $TaskName
        
        # Wait a moment and check status
        Start-Sleep -Seconds 3
        $taskInfo = Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo
        Write-Host "Task Status: $($taskInfo.LastTaskResult)" -ForegroundColor Cyan
        
        if ($taskInfo.LastTaskResult -eq 0) {
            Write-Host "✅ Test backup appears to be running successfully!" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Check the task history in Task Scheduler for details" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "📝 Configuration Summary:" -ForegroundColor Green
    Write-Host "   • Daily backup at $BackupTime" -ForegroundColor White
    Write-Host "   • 365-day retention policy" -ForegroundColor White
    Write-Host "   • Backs up entire application + database" -ForegroundColor White
    Write-Host "   • Compressed archives to save space" -ForegroundColor White
    Write-Host "   • Automatic cleanup of old backups" -ForegroundColor White
    Write-Host "   • Detailed logging in backup.log" -ForegroundColor White
    Write-Host ""
    Write-Host "🎉 Daily backup system is now active!" -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 Tips:" -ForegroundColor Cyan
    Write-Host "   • Check 'backups/' folder for backup files" -ForegroundColor White
    Write-Host "   • Monitor 'backup.log' for backup status" -ForegroundColor White
    Write-Host "   • Use Task Scheduler to modify schedule if needed" -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Host "❌ Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "Press Enter to exit..."
Read-Host
