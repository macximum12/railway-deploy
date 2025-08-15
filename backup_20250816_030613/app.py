from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
import sqlite3
from datetime import datetime
import csv
import io

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('audit_findings.db')
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_reference TEXT,
        audit_report TEXT,
        observations TEXT,
        observation_details TEXT,
        report_date TEXT,
        priority TEXT,
        recommendation TEXT,
        management_response TEXT,
        target_date TEXT,
        revised_target_date TEXT,
        completion_date TEXT,
        person_responsible TEXT,
        department TEXT,
        status TEXT,
        validated TEXT,
        testing_procedures TEXT,
        comments TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('audit_findings.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    findings = conn.execute('''
        SELECT id, audit_reference, audit_report, status, priority, 
               target_date, person_responsible, created_at 
        FROM audit_findings 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('index.html', findings=findings)

@app.route('/findings')
def findings():
    conn = get_db_connection()
    findings = conn.execute('''
        SELECT id, audit_reference, audit_report, status, priority, 
               target_date, person_responsible 
        FROM audit_findings 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('findings.html', findings=findings)

@app.route('/add', methods=['GET', 'POST'])
def add_finding():
    if request.method == 'POST':
        conn = get_db_connection()
        now = datetime.now().isoformat()
        
        # Handle conditional audit report field
        audit_reference = request.form.get('audit_reference', '').strip()
        if audit_reference in ['24-07', '25-05']:
            audit_report = request.form.get('audit_report_custom', '').strip()
        else:
            audit_report = request.form.get('audit_report', '').strip()
        
        # Get other required fields
        observations = request.form.get('observations', '').strip()
        
        # Validate required fields
        error_message = None
        if not audit_reference:
            error_message = "Audit Reference is required"
        elif not audit_report:
            error_message = "Audit Report is required"
        elif not observations:
            error_message = "Observations are required"
        
        if error_message:
            conn.close()
            return render_template('add_finding.html', error=error_message)
        
        # Get target_date and clear it if status is Completed
        target_date = request.form.get('target_date', '').strip()
        status = request.form.get('status', '').strip()
        if status == 'Completed':
            target_date = None  # Clear target date for completed findings
        
        conn.execute('''
            INSERT INTO audit_findings (
                audit_reference, audit_report, observations, observation_details,
                report_date, priority, recommendation, management_response,
                target_date, revised_target_date, completion_date,
                person_responsible, department, status, validated,
                testing_procedures, comments, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            audit_reference,
            audit_report,
            observations,
            request.form.get('observation_details', ''),
            request.form.get('report_date', ''),
            request.form.get('priority', ''),
            request.form.get('recommendation', ''),
            request.form.get('management_response', ''),
            target_date,
            request.form.get('revised_target_date', ''),
            request.form.get('completion_date', ''),
            request.form.get('person_responsible', ''),
            request.form.get('department', ''),
            status,
            request.form.get('validated', ''),
            request.form.get('testing_procedures', ''),
            request.form.get('comments', ''),
            now
        ))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    return render_template('add_finding.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_finding(id):
    conn = get_db_connection()
    
    if request.method == 'POST':
        now = datetime.now().isoformat()
        
        # Handle conditional audit report field
        audit_reference = request.form.get('audit_reference', '')
        if audit_reference in ['24-07', '25-05']:
            audit_report = request.form.get('audit_report_custom', '')
        else:
            audit_report = request.form.get('audit_report', '')
        
        # Process status and target date - clear target date if status is Completed
        status = request.form.get('status', '')
        target_date = request.form.get('target_date', '')
        if status == 'Completed':
            target_date = ''
        
        conn.execute('''
            UPDATE audit_findings SET
                audit_reference=?, audit_report=?, observations=?, observation_details=?,
                report_date=?, priority=?, recommendation=?, management_response=?,
                target_date=?, revised_target_date=?, completion_date=?,
                person_responsible=?, department=?, status=?, validated=?,
                testing_procedures=?, comments=?, updated_at=?
            WHERE id=?
        ''', (
            audit_reference,
            audit_report,
            request.form.get('observations', ''),
            request.form.get('observation_details', ''),
            request.form.get('report_date', ''),
            request.form.get('priority', ''),
            request.form.get('recommendation', ''),
            request.form.get('management_response', ''),
            target_date,
            request.form.get('revised_target_date', ''),
            request.form.get('completion_date', ''),
            request.form.get('person_responsible', ''),
            request.form.get('department', ''),
            status,
            request.form.get('validated', ''),
            request.form.get('testing_procedures', ''),
            request.form.get('comments', ''),
            now,
            id
        ))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    finding = conn.execute('SELECT * FROM audit_findings WHERE id = ?', (id,)).fetchone()
    conn.close()
    return render_template('edit_finding.html', finding=finding)

@app.route('/delete/<int:id>')
def delete_finding(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM audit_findings WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/export')
def export_csv():
    conn = get_db_connection()
    findings = conn.execute('SELECT * FROM audit_findings').fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Audit Reference', 'Audit Report', 'Observations', 'Observation Details',
        'Report Date', 'Priority', 'Recommendation', 'Management Response',
        'Target Date', 'Revised Target Date', 'Completion Date',
        'Person Responsible', 'Department', 'Status', 'Validated',
        'Testing Procedures', 'Comments', 'Created At', 'Updated At'
    ])
    
    # Write data
    for finding in findings:
        writer.writerow(finding)
    
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=audit_findings_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/import', methods=['GET', 'POST'])
def import_findings():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        
        if file and file.filename.endswith('.csv'):
            # Process the CSV file
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)
            
            # Skip header row
            next(csv_input)
            
            conn = get_db_connection()
            imported_count = 0
            errors = []
            
            for row_num, row in enumerate(csv_input, start=2):
                if len(row) < 14:  # Ensure minimum required columns
                    errors.append(f"Row {row_num}: Insufficient columns")
                    continue
                
                try:
                    # Map CSV columns to database columns
                    # Your CSV: Audit Reference Number,Audit Report,Observations,Observation Details,Report Date,Priority,Recommendation,Management Response,Target Date,Revised Target Date,Completion Date,Person Responsible,Department of Person Responsible,Status,Validated,Testing Procedures,Comments
                    audit_reference = row[0].strip() if row[0] else ''
                    audit_report = row[1].strip() if row[1] else ''
                    observations = row[2].strip() if row[2] else ''
                    observation_details = row[3].strip() if row[3] else ''
                    report_date = row[4].strip() if row[4] else ''
                    priority = row[5].strip() if row[5] else ''
                    recommendation = row[6].strip() if row[6] else ''
                    management_response = row[7].strip() if row[7] else ''
                    target_date = row[8].strip() if row[8] else ''
                    revised_target_date = row[9].strip() if row[9] else ''
                    completion_date = row[10].strip() if row[10] else ''
                    person_responsible = row[11].strip() if row[11] else ''
                    department = row[12].strip() if row[12] else ''
                    status = row[13].strip() if row[13] else 'In-Progress'
                    validated = row[14].strip() if len(row) > 14 and row[14] else 'No'
                    testing_procedures = row[15].strip() if len(row) > 15 and row[15] else ''
                    comments = row[16].strip() if len(row) > 16 and row[16] else ''
                    
                    # Validate date fields - reject words, only accept proper dates or empty values
                    def validate_date(date_str, field_name):
                        if not date_str:
                            return ''
                        # Reject common non-date words
                        invalid_words = ['complete', 'na', 'n/a', 'pending', 'tbd', 'unknown']
                        if date_str.lower().strip() in invalid_words:
                            return ''  # Convert invalid words to empty string
                        # Check if it contains only date-like characters
                        if not all(c in '0123456789-/' for c in date_str):
                            raise ValueError(f"Invalid {field_name}: '{date_str}' contains non-date characters")
                        # Try parsing common date formats
                        try:
                            if '/' in date_str:
                                datetime.strptime(date_str, '%m/%d/%Y')
                            elif '-' in date_str:
                                if len(date_str.split('-')[0]) == 4:
                                    datetime.strptime(date_str, '%Y-%m-%d')
                                else:
                                    datetime.strptime(date_str, '%d-%b-%y')
                            return date_str
                        except ValueError:
                            raise ValueError(f"Invalid {field_name} format: '{date_str}'")
                    
                    # Clean person responsible field
                    def clean_person_responsible(person_str):
                        if not person_str:
                            return ''
                        # Take only the first line and first name/title
                        lines = person_str.split('\n')
                        first_line = lines[0].strip()
                        # If there's a comma, take only the part before the first comma
                        if ',' in first_line:
                            return first_line.split(',')[0].strip()
                        return first_line
                    
                    # Validate dates
                    target_date = validate_date(target_date, 'target date')
                    revised_target_date = validate_date(revised_target_date, 'revised target date')
                    completion_date = validate_date(completion_date, 'completion date')
                    report_date = validate_date(report_date, 'report date')
                    
                    # Clean person responsible field
                    person_responsible = clean_person_responsible(person_responsible)
                    
                    # Validate required fields
                    if not audit_reference.strip():
                        errors.append(f"Row {row_num}: Audit Reference is required")
                        continue
                    if not audit_report.strip():
                        errors.append(f"Row {row_num}: Audit Report is required")
                        continue
                    if not observations.strip():
                        errors.append(f"Row {row_num}: Observations are required")
                        continue
                    
                    # If status is Completed, target date is optional; otherwise it should be provided
                    if status.lower() != 'completed' and not target_date:
                        errors.append(f"Row {row_num}: Target date is required for non-completed findings")
                        continue
                    
                    # Insert into database
                    conn.execute('''
                        INSERT INTO audit_findings (
                            audit_reference, audit_report, observations, observation_details,
                            report_date, priority, recommendation, management_response,
                            target_date, revised_target_date, completion_date,
                            person_responsible, department, status, validated,
                            testing_procedures, comments, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        audit_reference, audit_report, observations, observation_details,
                        report_date, priority, recommendation, management_response,
                        target_date, revised_target_date, completion_date,
                        person_responsible, department, status, validated,
                        testing_procedures, comments, datetime.now().isoformat()
                    ))
                    imported_count += 1
                    
                except Exception as e:
                    errors.append(f"Row {row_num}: {str(e)}")
            
            conn.commit()
            conn.close()
            
            if errors:
                error_msg = f"Imported {imported_count} records with {len(errors)} errors: " + "; ".join(errors[:5])
                if len(errors) > 5:
                    error_msg += f" and {len(errors) - 5} more errors..."
                return render_template('import.html', message=error_msg, message_type='warning')
            else:
                return render_template('import.html', message=f"Successfully imported {imported_count} records!", message_type='success')
    
    return render_template('import.html')

@app.route('/api/chart-data/<int:year>')
def get_chart_data(year):
    """API endpoint to get chart data for a specific year"""
    conn = get_db_connection()
    
    # Get all findings and filter by year in Python since date formats are inconsistent
    findings = conn.execute('''
        SELECT status, report_date, created_at
        FROM audit_findings 
    ''').fetchall()
    
    conn.close()
    
    # Initialize data structure
    data = {
        'Completed': 0,
        'In-Progress': 0,
        'Delayed': 0,
        'Closed': 0
    }
    
    from datetime import datetime
    import re
    
    # Function to extract year from various date formats
    def extract_year(date_str):
        if not date_str or date_str.strip() == '':
            return None
        
        # Handle formats like "17-Oct-24", "14-Jul-25", "8-May-24"
        date_patterns = [
            r'(\d{1,2})-(\w{3})-(\d{2})',  # 17-Oct-24
            r'(\d{1,2})/(\d{1,2})/(\d{2,4})',  # 17/10/24 or 17/10/2024
            r'(\d{4})-(\d{2})-(\d{2})',  # 2024-10-17
        ]
        
        for pattern in date_patterns:
            match = re.match(pattern, date_str)
            if match:
                if pattern == date_patterns[0]:  # DD-MMM-YY format
                    year_str = match.group(3)
                    # Convert 2-digit year to 4-digit
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:  # 20-99 -> 2020-2099
                            return 2000 + year_int
                        else:  # 00-19 -> 2000-2019
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[1]:  # MM/DD/YY or MM/DD/YYYY
                    year_str = match.group(3)
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:
                            return 2000 + year_int
                        else:
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[2]:  # YYYY-MM-DD
                    return int(match.group(1))
        
        return None
    
    # Filter findings by year
    for finding in findings:
        # Try to get year from report_date first
        finding_year = extract_year(finding['report_date'])
        
        # If report_date doesn't give us a year, use created_at
        if finding_year is None:
            try:
                # Extract year from created_at (ISO format)
                if finding['created_at']:
                    finding_year = int(finding['created_at'][:4])
            except:
                finding_year = None
        
        # If this finding belongs to the requested year, count it
        if finding_year == year and finding['status'] in data:
            data[finding['status']] += 1
    
    return jsonify(data)

@app.route('/api/findings-by-status/<status>/<int:year>')
def get_findings_by_status(status, year):
    """API endpoint to get findings by status and year"""
    conn = get_db_connection()
    
    # Get all findings with the specified status
    findings = conn.execute('''
        SELECT id, audit_reference, audit_report, status, priority, 
               target_date, person_responsible, created_at, report_date
        FROM audit_findings 
        WHERE status = ?
        ORDER BY created_at DESC
    ''', (status,)).fetchall()
    
    conn.close()
    
    from datetime import datetime
    import re
    
    # Function to extract year from various date formats
    def extract_year(date_str):
        if not date_str or date_str.strip() == '':
            return None
        
        # Handle formats like "17-Oct-24", "14-Jul-25", "8-May-24"
        date_patterns = [
            r'(\d{1,2})-(\w{3})-(\d{2})',  # 17-Oct-24
            r'(\d{1,2})/(\d{1,2})/(\d{2,4})',  # 17/10/24 or 17/10/2024
            r'(\d{4})-(\d{2})-(\d{2})',  # 2024-10-17
        ]
        
        for pattern in date_patterns:
            match = re.match(pattern, date_str)
            if match:
                if pattern == date_patterns[0]:  # DD-MMM-YY format
                    year_str = match.group(3)
                    # Convert 2-digit year to 4-digit
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:  # 20-99 -> 2020-2099
                            return 2000 + year_int
                        else:  # 00-19 -> 2000-2019
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[1]:  # MM/DD/YY or MM/DD/YYYY
                    year_str = match.group(3)
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:
                            return 2000 + year_int
                        else:
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[2]:  # YYYY-MM-DD
                    return int(match.group(1))
        
        return None
    
    # Filter findings by year and convert to list of dictionaries
    findings_list = []
    for finding in findings:
        # Try to get year from report_date first
        finding_year = extract_year(finding['report_date'])
        
        # If report_date doesn't give us a year, use created_at
        if finding_year is None:
            try:
                # Extract year from created_at (ISO format)
                if finding['created_at']:
                    finding_year = int(finding['created_at'][:4])
            except:
                finding_year = None
        
        # If this finding belongs to the requested year, include it
        if finding_year == year:
            findings_list.append({
                'id': finding['id'],
                'audit_reference': finding['audit_reference'],
                'audit_report': finding['audit_report'],
                'status': finding['status'],
                'priority': finding['priority'],
                'target_date': finding['target_date'],
                'person_responsible': finding['person_responsible'],
                'created_at': finding['created_at']
            })
    
    return jsonify(findings_list)

@app.route('/api/finding/<int:finding_id>')
def get_finding_details(finding_id):
    conn = get_db_connection()
    finding = conn.execute('''
        SELECT * FROM audit_findings WHERE id = ?
    ''', (finding_id,)).fetchone()
    conn.close()
    
    if finding:
        finding_dict = {
            'id': finding['id'],
            'audit_reference': finding['audit_reference'],
            'audit_report': finding['audit_report'],
            'observations': finding['observations'],
            'observation_details': finding['observation_details'],
            'report_date': finding['report_date'],
            'priority': finding['priority'],
            'recommendation': finding['recommendation'],
            'management_response': finding['management_response'],
            'target_date': finding['target_date'],
            'revised_target_date': finding['revised_target_date'],
            'completion_date': finding['completion_date'],
            'person_responsible': finding['person_responsible'],
            'department': finding['department'],
            'status': finding['status'],
            'validated': finding['validated'],
            'testing_procedures': finding['testing_procedures'],
            'comments': finding['comments'],
            'created_at': finding['created_at'],
            'updated_at': finding['updated_at']
        }
        return jsonify(finding_dict)
    else:
        return jsonify({'error': 'Finding not found'}), 404

if __name__ == '__main__':
    init_db()
    print("🚀 Starting Internal Audit Tracker...")
    print("📊 Database initialized successfully!")
    print("🌐 Server running at: http://127.0.0.1:5000")
    print("Press CTRL+C to stop the server")
    app.run(debug=True, host='127.0.0.1', port=5000)
