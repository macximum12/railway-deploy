# Audit Tracker Flask Application

A comprehensive Flask web application for tracking internal audit findings with secure user management and activity logging.

## Features

- **User Authentication & Authorization**
  - Role-based access control (Admin, Editor, Viewer)
  - Industry-standard password requirements (NIST/OWASP compliant)
  - Session management with concurrent login prevention
  - Activity logging and audit trails

- **Audit Finding Management**
  - Add, edit, delete audit findings
  - Import/export CSV functionality
  - Status tracking and reporting
  - Interactive dashboard with charts

- **Security Features**
  - Password complexity validation by role
  - Force password change for new users
  - Session timeout and management
  - Comprehensive activity logging

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python app.py`
4. Access at `http://127.0.0.1:5000`

## Default Login

- Username: `admin`
- Password: `admin`

**Important:** Change the default credentials in production!

## Deployment

This application is configured for Railway deployment with the included `Procfile`.
