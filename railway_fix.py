#!/usr/bin/env python3
"""
Comprehensive fix script for Railway deployment issues
This script identifies and fixes issues with the admin/users page
"""

import sys
import os
import traceback

def main():
    """Main function to run all fixes"""
    print("🔧 Railway Deployment Fix Script")
    print("=" * 50)
    
    try:
        # Fix 1: Test local functionality
        print("\n1. Testing local functionality...")
        test_local_app()
        
        # Fix 2: Create Railway-specific fixes
        print("\n2. Creating Railway deployment fixes...")
        create_railway_fixes()
        
        # Fix 3: Create production error handling
        print("\n3. Adding production error handling...")
        add_production_error_handling()
        
        print("\n✅ All fixes completed successfully!")
        print("\nNext steps:")
        print("1. Commit and push changes to your repository")
        print("2. Railway will automatically redeploy")
        print("3. Check the Railway logs for any remaining issues")
        
    except Exception as e:
        print(f"\n❌ Error during fix process: {e}")
        print(f"Traceback: {traceback.format_exc()}")

def test_local_app():
    """Test the local app functionality"""
    try:
        # Import after changing directory
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from app import app, get_all_users, ROLES
        
        # Test getting users
        users = get_all_users()
        print(f"   ✅ Database connection successful - found {len(users)} users")
        
        # Test password requirements structure
        template_password_requirements = {}
        for role, data in ROLES.items():
            key = role.lower().replace(' ', '_')
            template_password_requirements[key] = data['password_requirements']
        
        print(f"   ✅ Password requirements structure valid - {len(template_password_requirements)} roles")
        
        # Test Flask app context
        with app.app_context():
            print("   ✅ Flask application context working")
            
    except Exception as e:
        print(f"   ❌ Local test failed: {e}")
        raise

def create_railway_fixes():
    """Create Railway-specific fixes"""
    
    # Create a requirements check
    requirements_content = """Flask==3.0.3
gunicorn==22.0.0
Werkzeug==3.0.3
"""
    
    # Check current requirements
    try:
        with open('requirements.txt', 'r') as f:
            current_req = f.read()
            
        if 'gunicorn' not in current_req:
            with open('requirements.txt', 'a') as f:
                f.write('\ngunicorn==22.0.0\n')
            print("   ✅ Added gunicorn to requirements.txt")
        else:
            print("   ✅ Requirements.txt already contains gunicorn")
            
    except FileNotFoundError:
        with open('requirements.txt', 'w') as f:
            f.write(requirements_content)
        print("   ✅ Created requirements.txt")
    
    # Create/update Procfile for Railway
    procfile_content = "web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 30"
    
    try:
        with open('Procfile', 'w') as f:
            f.write(procfile_content)
        print("   ✅ Created/updated Procfile")
    except Exception as e:
        print(f"   ⚠️  Could not create Procfile: {e}")

def add_production_error_handling():
    """Add better error handling for production"""
    
    # Read the current app.py to see if we need to add error handlers
    try:
        with open('app.py', 'r') as f:
            content = f.read()
            
        # Check if error handlers already exist
        if '@app.errorhandler(500)' not in content:
            error_handlers = '''

# Production error handlers
@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    import traceback
    error_trace = traceback.format_exc()
    print(f"❌ Internal Server Error: {error_trace}")
    
    # Log to a file if possible
    try:
        with open('error.log', 'a') as f:
            f.write(f"{datetime.now()}: {error_trace}\\n")
    except:
        pass
    
    return render_template('error.html', 
                         error_message="Internal server error occurred. Please try again."), 500

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('error.html', 
                         error_message="Page not found."), 404

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    return render_template('error.html', 
                         error_message="Access forbidden."), 403
'''
            
            # Insert before the final if __name__ == '__main__': block
            content = content.replace("if __name__ == '__main__':", 
                                    error_handlers + "\nif __name__ == '__main__':")
            
            with open('app.py', 'w') as f:
                f.write(content)
            
            print("   ✅ Added production error handlers")
        else:
            print("   ✅ Error handlers already exist")
            
    except Exception as e:
        print(f"   ⚠️  Could not add error handlers: {e}")

if __name__ == "__main__":
    main()
