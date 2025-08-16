#!/usr/bin/env python3
"""
Debug script to test the manage_users route and identify issues
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, get_all_users, ROLES

def test_manage_users():
    """Test the manage_users functionality"""
    print("🔍 Testing manage_users functionality...")
    
    try:
        # Test getting users
        print("1. Testing get_all_users()...")
        users = get_all_users()
        print(f"   ✅ Found {len(users)} users")
        if users:
            print(f"   First user: {users[0]}")
        
        # Test password requirements structure
        print("\n2. Testing password requirements structure...")
        template_password_requirements = {}
        for role, data in ROLES.items():
            key = role.lower().replace(' ', '_')
            template_password_requirements[key] = data['password_requirements']
            print(f"   {role} -> {key}: {data['password_requirements']['description']}")
        
        # Test template rendering
        print("\n3. Testing template access...")
        with app.test_client() as client:
            with app.app_context():
                # Create a minimal context for template testing
                from flask import render_template_string
                
                test_template = """
                Password Requirements Test:
                {% for key, req in password_requirements.items() %}
                - {{ key }}: {{ req.description }}
                {% endfor %}
                """
                
                result = render_template_string(test_template, 
                                              password_requirements=template_password_requirements)
                print("   ✅ Template rendering successful")
                print(f"   Result:\n{result}")
                
        print("\n✅ All tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        print(f"Full traceback:\n{traceback.format_exc()}")
        return False

if __name__ == "__main__":
    test_manage_users()
