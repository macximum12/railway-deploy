# Contributing to Internal Audit Tracker

Thank you for your interest in contributing! This document provides guidelines for contributing to the Internal Audit Tracker open-source project.

## 🤝 How to Contribute

### Types of Contributions We Welcome

- 🐛 **Bug fixes**
- ✨ **New features** 
- 📚 **Documentation improvements**
- 🎨 **UI/UX enhancements**
- 🔒 **Security improvements**
- 🌐 **Internationalization/Localization**
- ⚡ **Performance optimizations**

## 🚀 Getting Started

### 1. Set Up Development Environment

```bash
# Fork the repository and clone your fork
git clone https://github.com/YOUR_USERNAME/audit-logger.git
cd audit-logger

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests to ensure everything works
python -m pytest
```

### 2. Development Workflow

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes
# ... code, test, repeat ...

# Run tests and linting
python -m pytest
black .
flake8 .

# Commit your changes
git add .
git commit -m "feat: add amazing new feature"

# Push to your fork
git push origin feature/your-feature-name

# Create a pull request on GitHub
```

## 📋 Development Guidelines

### Code Style
- Follow **PEP 8** Python style guidelines
- Use **Black** for code formatting (`black .`)
- Use **flake8** for linting (`flake8 .`)
- Maximum line length: **88 characters**
- Use **type hints** where appropriate

### Commit Messages
Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
feat: add user role management
fix: resolve session timeout issue  
docs: update deployment guide
style: format code with black
refactor: simplify user authentication
test: add unit tests for finding creation
```

### Testing
- Write tests for all new features
- Maintain test coverage above **80%**
- Run tests before submitting: `python -m pytest`
- Test on multiple Python versions if possible

### Documentation
- Update documentation for new features
- Include docstrings for all functions/classes
- Update README.md if adding major features
- Add examples for complex functionality

## 🏗️ Project Structure

```
audit-logger/
├── main.py                 # Flask application core
├── tests/                  # Test suite
│   ├── test_auth.py       # Authentication tests
│   ├── test_findings.py   # Finding management tests
│   └── test_users.py      # User management tests
├── templates/              # Jinja2 templates
├── static/                # CSS, JS, images
├── docs/                  # Documentation
├── requirements.txt       # Production dependencies
├── requirements-dev.txt   # Development dependencies
└── .github/               # GitHub workflows
    └── workflows/
        └── ci.yml         # Continuous integration
```

## 🎯 Priority Areas

We're especially looking for contributions in these areas:

### 🔒 Security
- Security vulnerability fixes
- Authentication improvements
- Session management enhancements
- Input validation and sanitization

### 📊 Features
- Advanced reporting capabilities
- Dashboard improvements
- Excel import/export enhancements
- Mobile responsiveness improvements

### 🌐 Internationalization
- Translation support
- Multi-language interfaces
- Date/time localization
- Currency/number formatting

### ⚡ Performance
- Database query optimization
- Frontend performance improvements
- Caching mechanisms
- Load testing and optimization

## 🐛 Bug Reports

When reporting bugs, please include:

### Bug Report Template
```markdown
**Description**
A clear description of the bug.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '...'
3. See error

**Expected Behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment**
- OS: [e.g. Windows 10, Ubuntu 20.04]
- Python version: [e.g. 3.9.5]
- Browser: [e.g. Chrome 91.0]

**Additional Context**
Any other context about the problem.
```

## 💡 Feature Requests

For feature requests, please include:

### Feature Request Template
```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Alternative solutions or features you've considered.

**Additional context**
Screenshots, mockups, or examples.
```

## 📝 Pull Request Process

### Before Submitting
1. ✅ Ensure tests pass
2. ✅ Update documentation
3. ✅ Follow coding standards
4. ✅ Add/update tests for new features
5. ✅ Update CHANGELOG.md

### Pull Request Template
```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No merge conflicts
```

## 🔍 Code Review Process

### What We Look For
- **Functionality**: Does it work as intended?
- **Code Quality**: Is it readable and maintainable?
- **Security**: Are there any security concerns?
- **Performance**: Does it impact performance?
- **Testing**: Are there adequate tests?
- **Documentation**: Is it properly documented?

### Review Timeline
- Initial review: **2-3 business days**
- Follow-up reviews: **1-2 business days**
- Complex changes may take longer

## 🏷️ Issue Labels

We use these labels to categorize issues:

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Documentation improvements
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `security` - Security-related issues
- `question` - Further information requested

## 👥 Community Guidelines

### Code of Conduct
- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Respect different viewpoints and experiences

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community chat
- **Pull Requests**: Code review and technical discussion

## 🎉 Recognition

Contributors will be:
- Added to the CONTRIBUTORS.md file
- Mentioned in release notes for significant contributions
- Given credit in documentation for major features

## 📞 Getting Help

Need help contributing? Reach out:

- 💬 **GitHub Discussions**: Ask questions
- 📧 **Email**: maintainers@audit-tracker.com
- 🐛 **Issues**: Create an issue with the `question` label

---

**Thank you for contributing to Internal Audit Tracker! 🎉**

Every contribution, no matter how small, makes a difference.
