import sqlite3

# Connect to database
conn = sqlite3.connect('audit_findings.db')
cursor = conn.cursor()

# Clean person_responsible field
results = cursor.execute('SELECT id, person_responsible FROM audit_findings WHERE person_responsible IS NOT NULL').fetchall()
updated = 0

for row in results:
    old_name = row[1]
    if old_name:
        # Take only the first part before comma or newline
        if ',' in old_name:
            new_name = old_name.split(',')[0].strip()
        elif '\n' in old_name:
            new_name = old_name.split('\n')[0].strip()
        else:
            new_name = old_name.strip()
        
        if new_name != old_name:
            cursor.execute('UPDATE audit_findings SET person_responsible = ? WHERE id = ?', (new_name, row[0]))
            updated += 1

conn.commit()
conn.close()
print(f'Cleaned {updated} person_responsible records')
