import sqlite3

# Connect to database
conn = sqlite3.connect('audit_findings.db')
cursor = conn.cursor()

# Check for completely blank entries (all key fields empty)
print("=== Checking for blank entries ===")

# Check entries with blank audit reference
blank_ref = cursor.execute("SELECT COUNT(*) FROM audit_findings WHERE audit_reference IS NULL OR audit_reference = ''").fetchone()[0]
print(f"Entries with blank audit reference: {blank_ref}")

# Check entries with blank audit report
blank_report = cursor.execute("SELECT COUNT(*) FROM audit_findings WHERE audit_report IS NULL OR audit_report = ''").fetchone()[0]
print(f"Entries with blank audit report: {blank_report}")

# Check entries with blank observations
blank_obs = cursor.execute("SELECT COUNT(*) FROM audit_findings WHERE observations IS NULL OR observations = ''").fetchone()[0]
print(f"Entries with blank observations: {blank_obs}")

# Check completely blank entries (missing all three key fields)
completely_blank = cursor.execute("""
    SELECT id, audit_reference, audit_report, observations 
    FROM audit_findings 
    WHERE (audit_reference IS NULL OR audit_reference = '') 
    AND (audit_report IS NULL OR audit_report = '') 
    AND (observations IS NULL OR observations = '')
""").fetchall()

print(f"\nCompletely blank entries: {len(completely_blank)}")
for entry in completely_blank[:10]:  # Show first 10
    print(f"  ID: {entry[0]}")

# Check entries that are mostly blank (missing 2 out of 3 key fields)
mostly_blank = cursor.execute("""
    SELECT id, audit_reference, audit_report, observations 
    FROM audit_findings 
    WHERE ((audit_reference IS NULL OR audit_reference = '') 
           + (audit_report IS NULL OR audit_report = '') 
           + (observations IS NULL OR observations = '')) >= 2
""").fetchall()

print(f"\nMostly blank entries (2+ key fields missing): {len(mostly_blank)}")
for entry in mostly_blank[:10]:  # Show first 10
    print(f"  ID: {entry[0]}, Ref: '{entry[1]}', Report: '{entry[2]}', Obs: '{entry[3][:30] if entry[3] else ''}...'")

conn.close()
