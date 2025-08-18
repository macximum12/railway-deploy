# Internal Audit Tracker

A comprehensive web-based application for managing internal audit findings, tracking remediation progress, and maintaining audit documentation.

## Features

### 🔐 Role-Based Access Control
- **Administrator**: Full access to everything - user management, system settings, all features
- **Content Manager**: Add/edit/delete findings, access to activity logs, content management
- **Contributor**: Add and edit findings, limited content creation permissions
- **Viewer**: View-only access, cannot add/edit findings or access management features

### 📋 Finding Management
- Create, edit, and track audit findings
- Import findings from Excel files
- Comprehensive finding details including risk levels, recommendations, and implementation status
- Progress tracking with target dates and completion monitoring
- Status management (In Progress, Completed, Delayed, Closed)

### 👥 User Management
- Secure user authentication and session management
- Password policy enforcement with complexity requirements
- Account lockout protection after failed login attempts
- First-login password change requirement (with admin exception)
- User activity tracking and audit logs

### 📊 Reporting & Analytics
- Activity logs for audit trail
- Finding status dashboard
- Progress tracking and reporting
- Export capabilities for audit documentation

### 🔒 Security Features
- Session timeout (30 minutes of inactivity)
- Password expiry (90 days)
- Strong password requirements
- CSRF protection
- Secure session management
- Admin exception handling for deployment safety

## Installation

### Prerequisites
- Python 3.8 or higher
- Flask framework
- SQLite database (included)

### Setup
1. Clone the repository:
```bash
git clone https://github.com/macximum12/audit-logger.git
cd audit-logger
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install flask flask-session werkzeug pandas openpyxl
```

4. Run the application:
```bash
python main.py
```

5. Access the application at `http://localhost:5000`

### Default Login
- **Username**: admin
- **Password**: admin123
- **Note**: Change the default password immediately after first login

## Project Structure

```
audit-logger/
├── main.py                 # Main Flask application
├── templates/              # HTML templates
│   ├── base.html          # Base template with navigation
│   ├── index.html         # Dashboard/home page
│   ├── login.html         # Login page
│   ├── add_finding.html   # Add new finding form
│   ├── edit_finding.html  # Edit finding form
│   ├── findings.html      # Findings list view
│   ├── import.html        # Excel import interface
│   ├── activity_logs.html # Activity logs view
│   ├── manage_users.html  # User management (admin only)
│   ├── add_user.html     # Add user form (admin only)
│   ├── edit_user.html    # Edit user form (admin only)
│   ├── first_login.html  # First login password change
│   └── admin/            # Admin-specific templates
├── audit_findings.db      # SQLite database (auto-created)
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Configuration

### Environment Variables
Set these environment variables for production deployment:
- `SECRET_KEY`: Flask secret key for session security
- `DATABASE_URL`: Database connection string (optional, defaults to SQLite)

### Security Settings
The application includes several security configurations:
- Session timeout: 30 minutes
- Password expiry: 90 days
- Account lockout: 5 failed attempts
- Password requirements: 12+ characters, mixed case, numbers, symbols

## Access Levels

### Administrator
- Full system access
- User management and creation
- System settings and configuration
- All finding management capabilities
- Access to all reports and logs

### Content Manager
- Add, edit, and delete findings
- Access to activity logs
- Content management features
- Import/export capabilities

### Contributor
- Add and edit findings
- Limited content creation
- View findings and basic reports

### Viewer
- View-only access to findings
- Basic reporting access
- No editing or management capabilities

## Security Notes

1. **Admin Exception**: The 'admin' user is exempt from first-login password changes to prevent deployment lockouts
2. **Password Policy**: Enforced strong password requirements for all users
3. **Session Security**: Automatic session timeout and secure session handling
4. **Audit Trail**: All user activities are logged for security auditing

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is proprietary software for internal audit tracking purposes.

## Support

For support and questions, please contact the development team or create an issue in the repository.

---

**Version**: 1.0.0  
**Last Updated**: August 2025  
**Status**: Production Ready
