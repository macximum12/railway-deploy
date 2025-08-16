#!/usr/bin/env python3
"""
Backup System Demo - Show what's been created
"""
import os
import zipfile
import datetime
import glob

def demo_backup_system():
    print("💾 DAILY BACKUP SYSTEM DEMONSTRATION")
    print("=" * 60)
    
    backup_dir = "backups"
    
    # Check if backups exist
    if not os.path.exists(backup_dir):
        print("❌ No backup directory found. Run 'python daily_backup.py' first.")
        return
    
    # List backup files
    backup_files = glob.glob(os.path.join(backup_dir, "backup_*.zip"))
    
    if not backup_files:
        print("❌ No backup files found. Run 'python daily_backup.py' first.")
        return
    
    print(f"✅ Found {len(backup_files)} backup file(s):")
    print()
    
    for i, backup_file in enumerate(sorted(backup_files), 1):
        filename = os.path.basename(backup_file)
        size = os.path.getsize(backup_file)
        size_mb = size / (1024 * 1024)
        
        # Extract date from filename
        try:
            date_str = filename.split('_')[1]
            time_str = filename.split('_')[2].replace('.zip', '')
            backup_date = datetime.datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
            date_formatted = backup_date.strftime("%Y-%m-%d %H:%M:%S")
        except:
            date_formatted = "Unknown"
        
        print(f"📦 Backup #{i}: {filename}")
        print(f"   📅 Created: {date_formatted}")
        print(f"   💾 Size: {size_mb:.2f} MB ({size:,} bytes)")
        
        # Show contents of the backup
        try:
            with zipfile.ZipFile(backup_file, 'r') as zf:
                files = zf.namelist()
                print(f"   📁 Contains {len(files)} files:")
                
                # Show key files
                key_files = [f for f in files if any(key in f for key in 
                           ['database_', 'app.py', 'requirements.txt', 'templates/', 'static/'])]
                
                for file in sorted(key_files)[:10]:  # Show first 10 important files
                    print(f"      📄 {file}")
                
                if len(files) > 10:
                    print(f"      ... and {len(files) - 10} more files")
                    
        except Exception as e:
            print(f"   ⚠️  Could not read backup contents: {e}")
        
        print()
    
    # Show backup report if it exists
    report_file = os.path.join(backup_dir, "backup_report.txt")
    if os.path.exists(report_file):
        print("📋 BACKUP SYSTEM REPORT:")
        print("-" * 40)
        with open(report_file, 'r') as f:
            for line in f:
                print(f"   {line.rstrip()}")
        print()
    
    # Show features
    print("🎯 BACKUP SYSTEM FEATURES:")
    print("-" * 40)
    print("   ✅ Daily automatic backups")
    print("   ✅ 365-day retention policy")  
    print("   ✅ Complete application + database backup")
    print("   ✅ Compressed archives to save space")
    print("   ✅ Database integrity checking")
    print("   ✅ Automatic cleanup of old backups")
    print("   ✅ Interactive restoration system")
    print("   ✅ Windows Task Scheduler integration")
    print("   ✅ Detailed logging and reporting")
    print()
    
    # Show how to use
    print("🚀 HOW TO USE:")
    print("-" * 40)
    print("   📅 Setup automatic daily backups:")
    print("      PowerShell (as Admin): .\\setup_backup_schedule.ps1")
    print()
    print("   🔄 Manual backup:")
    print("      python daily_backup.py")
    print()
    print("   📤 Restore from backup:")
    print("      python restore_backup.py")
    print()
    print("   📋 View detailed guide:")
    print("      type BACKUP_SYSTEM_GUIDE.md")
    print()
    
    print("🎉 Your backup system is ready for production use!")

if __name__ == "__main__":
    demo_backup_system()
