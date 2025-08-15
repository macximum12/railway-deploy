import sqlite3

# Connect to database
conn = sqlite3.connect('audit_findings.db')
cursor = conn.cursor()

print("=== Removing blank entries ===")

# Remove entries that are missing both audit_reference AND audit_report
# (These are essentially unusable)
cursor.execute("""
    DELETE FROM audit_findings 
    WHERE (audit_reference IS NULL OR audit_reference = '') 
    AND (audit_report IS NULL OR audit_report = '')
""")
deleted_both = cursor.rowcount
print(f"Removed {deleted_both} entries with blank audit reference AND audit report")

# Remove entries with blank audit_reference (if any remain)
cursor.execute("""
    DELETE FROM audit_findings 
    WHERE audit_reference IS NULL OR audit_reference = ''
""")
deleted_ref = cursor.rowcount
print(f"Removed {deleted_ref} additional entries with blank audit reference")

# Remove entries with blank audit_report but only if observations are also blank
cursor.execute("""
    DELETE FROM audit_findings 
    WHERE (audit_report IS NULL OR audit_report = '') 
    AND (observations IS NULL OR observations = '')
""")
deleted_report_obs = cursor.rowcount
print(f"Removed {deleted_report_obs} entries with blank audit report AND observations")

# Commit changes
conn.commit()

# Check final count
final_count = cursor.execute("SELECT COUNT(*) FROM audit_findings").fetchone()[0]
print(f"\nFinal count of audit findings: {final_count}")

# Show remaining entries with any blank fields (for review)
remaining_blanks = cursor.execute("""
    SELECT id, audit_reference, audit_report, observations 
    FROM audit_findings 
    WHERE (audit_reference IS NULL OR audit_reference = '') 
    OR (audit_report IS NULL OR audit_report = '') 
    OR (observations IS NULL OR observations = '')
    LIMIT 5
""").fetchall()

if remaining_blanks:
    print(f"\nRemaining entries with some blank fields: {len(remaining_blanks)}")
    for entry in remaining_blanks:
        print(f"  ID: {entry[0]}, Ref: '{entry[1]}', Report: '{entry[2]}', Obs: '{entry[3][:30] if entry[3] else ''}...'")
else:
    print("\nNo remaining entries with blank key fields!")

conn.close()
print("\nCleanup completed!")
