# 🔍 Internal Audit Tracker

> **Open Source Template** - A complete, production-ready internal audit management system

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![Deploy to Railway](https://img.shields.io/badge/deploy-railway-purple.svg)](https://railway.app)
[![Deploy to Heroku](https://img.shields.io/badge/deploy-heroku-orange.svg)](https://heroku.com)

A comprehensive, secure web-based application for tracking internal audit findings. Perfect for organizations needing a professional audit management system with enterprise-grade features, built with Flask and designed for easy deployment.

![Dashboard Preview](https://via.placeholder.com/800x400/4f46e5/ffffff?text=Internal+Audit+Tracker+Dashboard)

## ✨ Key Features

### 🔐 **Security-First Design**
- **4-Tier Role System**: Administrator → Content Manager → Contributor → Viewer
- **Session Management**: Secure sessions with configurable timeout (5-30 minutes)
- **Rate Limiting**: Built-in brute force protection with Flask-Limiter
- **Password Policies**: Industry-standard requirements (NIST/OWASP compliant)
- **Activity Logging**: Complete audit trail of all user actions
- **Account Protection**: Auto-lockout after 5 failed login attempts

### 📊 **Comprehensive Audit Management**
- **Finding Lifecycle**: Create, edit, track, and close audit findings
- **Excel Integration**: Bulk import from Excel files with template support
- **Status Tracking**: Monitor finding progression and due dates
- **Advanced Search**: Filter by status, risk level, assignee, dates
- **Dashboard Analytics**: Quick overview of findings and progress
- **Export Capabilities**: Generate reports and documentation

### 👥 **Multi-User Collaboration**
- **Unlimited Users**: Support for teams of any size
- **Role-Based Permissions**: Granular access control
- **First-Login Security**: Mandatory password change for new accounts
- **Admin Override**: Emergency access to prevent lockouts
- **User Activity**: Track who did what and when

### 📱 **Modern, Responsive Interface**
- **Mobile-Friendly**: Works seamlessly on all devices
- **Clean Design**: Professional, intuitive user interface
- **Bootstrap Integration**: Modern UI components and styling
- **Dark/Light Modes**: User preference support
- **Print-Friendly**: Optimized for documentation printing

## 🚀 Quick Start

### Option 1: One-Click Cloud Deploy

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template/your-template)

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/macximum12/audit-logger)

### Option 2: Local Development

```bash
# 1. Clone the repository
git clone https://github.com/macximum12/audit-logger.git
cd audit-logger

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python main.py

# 5. Open your browser to http://localhost:5000
```

**Default Login**: `admin` / `admin123` (⚠️ **Change immediately!**)

### Option 3: Docker Deployment

```bash
# Pull and run the container
docker run -p 5000:5000 -e SECRET_KEY=your-secret-key audit-tracker:latest
```

## 📋 User Roles & Permissions

| Feature | Administrator | Content Manager | Contributor | Viewer |
|---------|:-------------:|:---------------:|:-----------:|:------:|
| View Findings | ✅ | ✅ | ✅ | ✅ |
| Add/Edit Findings | ✅ | ✅ | ✅ | ❌ |
| Delete Findings | ✅ | ✅ | ❌ | ❌ |
| Import Excel | ✅ | ✅ | ❌ | ❌ |
| Activity Logs | ✅ | ✅ | ❌ | ❌ |
| User Management | ✅ | ❌ | ❌ | ❌ |
| System Settings | ✅ | ❌ | ❌ | ❌ |

## 🏗️ Architecture

### Tech Stack
- **Backend**: Flask (Python)
- **Database**: SQLite (configurable to PostgreSQL/MySQL)
- **Frontend**: HTML5, Bootstrap 5, JavaScript
- **Security**: Flask-Limiter, Werkzeug, Session Management
- **Import/Export**: Pandas, OpenPyXL

### Project Structure
```
audit-logger/
├── 📄 main.py              # Flask application core
├── 📁 templates/           # HTML templates
│   ├── base.html          # Base layout
│   ├── login.html         # Authentication
│   ├── findings.html      # Main findings interface
│   └── admin/             # Admin panel templates
├── 📁 static/             # CSS, JS, images
│   ├── css/style.css      # Custom styling
│   └── js/app.js          # Client-side functionality
├── 📄 requirements.txt    # Python dependencies
├── 📄 Procfile           # Deployment configuration
├── 📄 railway.json       # Railway-specific config
├── 📄 DEPLOYMENT.md      # Detailed deployment guide
└── 🗃️ audit_findings.db  # Database (auto-created)
```

## ⚙️ Configuration

### Environment Variables

```bash
# Required for production
SECRET_KEY=your-super-secret-key-minimum-32-characters
FLASK_ENV=production

# Optional database configuration
DATABASE_URL=sqlite:///audit_findings.db

# Optional host/port configuration
HOST=0.0.0.0
PORT=5000
```

### Security Configuration

The application includes enterprise-grade security features:

```python
# Session Configuration
SESSION_TIMEOUT = 30 minutes (configurable)
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

# Password Requirements
MIN_LENGTH = 12 characters
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_NUMBERS = True
REQUIRE_SPECIAL = False (configurable by role)

# Account Protection
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 15 minutes
RATE_LIMITING = 1000 requests/hour
```

## 📊 Features Deep Dive

### Finding Management
- **Rich Editor**: Detailed finding descriptions with formatting
- **Risk Assessment**: High/Medium/Low risk categorization
- **Due Date Tracking**: Automatic status updates and notifications
- **File Attachments**: Support for evidence and documentation
- **Custom Fields**: Configurable additional data fields

### Excel Import/Export
- **Template Support**: Pre-formatted Excel templates
- **Bulk Operations**: Import hundreds of findings at once
- **Data Validation**: Automatic format and content checking
- **Export Options**: Multiple formats (Excel, CSV, PDF)

### Reporting & Analytics
- **Dashboard Metrics**: Key performance indicators
- **Trend Analysis**: Finding patterns over time
- **Status Reports**: Progress tracking and summaries
- **Custom Reports**: Configurable report generation

## 🔧 Customization

### Branding
```css
/* Customize colors in static/css/style.css */
:root {
    --primary-color: #4f46e5;
    --secondary-color: #64748b;
    --success-color: #10b981;
    --danger-color: #ef4444;
}
```

### Adding Custom Fields
```python
# Extend database schema in main.py
def add_custom_field(field_name, field_type):
    # Implementation details in customization guide
```

### Role Customization
```python
# Modify role permissions in main.py
ROLE_PERMISSIONS = {
    'custom_role': {
        'can_view': True,
        'can_edit': False,
        # ... additional permissions
    }
}
```

## 📖 Documentation

- 📋 **[Deployment Guide](DEPLOYMENT.md)** - Complete setup instructions
- 🔧 **[Configuration Guide](docs/CONFIGURATION.md)** - Advanced settings
- 🎨 **[Customization Guide](docs/CUSTOMIZATION.md)** - Theming and branding
- 🔒 **[Security Guide](docs/SECURITY.md)** - Security best practices
- 🐛 **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest

# Format code
black .
flake8 .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 🛟 Support & Community

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/macximum12/audit-logger/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/macximum12/audit-logger/discussions)
- 📧 **Email Support**: support@audit-tracker.com
- 💬 **Discord Community**: [Join our Discord](https://discord.gg/audit-tracker)

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License - Feel free to use in commercial and personal projects!
```

## 🌟 Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/) - The Python web framework
- UI powered by [Bootstrap](https://getbootstrap.com/) - Responsive CSS framework
- Icons from [Heroicons](https://heroicons.com/) - Beautiful SVG icons
- Deployed on [Railway](https://railway.app/) - Modern app deployment

---

<div align="center">

**⭐ Star this repository if it helped you!**

Made with ❤️ by developers, for organizations who need professional audit tracking.

[🚀 Get Started](https://github.com/macximum12/audit-logger) • [📖 Documentation](DEPLOYMENT.md) • [💬 Community](https://github.com/macximum12/audit-logger/discussions)

</div>
