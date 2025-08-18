# Changelog

All notable changes to the Internal Audit Tracker will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive open-source documentation
- MIT License for open-source distribution
- Contributing guidelines for community development
- Security guide with best practices
- Troubleshooting guide for common issues

## [1.0.0] - 2025-08-18

### Added
- Complete Internal Audit Tracker application
- Role-based access control system (Administrator, Content Manager, Contributor, Viewer)
- User authentication and session management
- Finding management (create, read, update, delete)
- Excel import/export functionality
- Activity logging and audit trail
- Responsive web interface with Bootstrap
- Security features (rate limiting, password policies, session timeout)
- Database management with SQLite
- Cloud deployment support (Railway, Heroku)
- Docker support
- Comprehensive deployment documentation

### Security
- Flask-Limiter integration for rate limiting
- Secure session management with timeout
- Password complexity requirements
- Account lockout protection
- CSRF protection
- Admin override functionality
- Secure cookie configuration

### Changed
- Updated Flask app configuration for cloud deployments
- Enhanced PORT and HOST configuration for Railway
- Improved error handling and user feedback

### Fixed
- Railway deployment "Application failed to respond" issue
- Missing static files in deployment
- Flask-Limiter dependency issues
- Session timeout and security configurations

## Previous Development

### [0.9.0] - 2025-08-17
- Initial implementation of core features
- Basic user management and authentication
- Finding management system
- Excel import functionality
- Role-based permissions

### [0.8.0] - 2025-08-16  
- Security enhancements
- Password policies implementation
- Session management improvements
- Activity logging system

### [0.7.0] - 2025-08-15
- User interface improvements
- Responsive design implementation
- Bootstrap integration
- Mobile-friendly interface

### [0.6.0] - 2025-08-14
- Database schema finalization
- SQLite integration
- Data validation and sanitization

### [0.5.0] - 2025-08-13
- Core Flask application structure
- Basic routing and templates
- Initial authentication system

---

## Types of Changes

- `Added` for new features
- `Changed` for changes in existing functionality  
- `Deprecated` for soon-to-be removed features
- `Removed` for now removed features
- `Fixed` for any bug fixes
- `Security` for vulnerability fixes
