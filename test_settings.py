#!/usr/bin/env python3
"""
Quick test script to identify the settings page error
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

def test_settings():
    """Test the settings route"""
    with app.test_client() as client:
        with app.app_context():
            # Simulate a logged-in user session
            with client.session_transaction() as sess:
                sess['logged_in'] = True
                sess['username'] = 'admin'
                sess['session_id'] = 'test-session-id'
                sess['user_role'] = 'admin'
                sess['last_activity'] = '2025-08-16T09:00:00'
                
            try:
                # Test GET request to settings
                response = client.get('/settings')
                print(f"Settings GET response status: {response.status_code}")
                
                if response.status_code == 500:
                    print("❌ Settings page has 500 Internal Server Error")
                    return False
                else:
                    print("✅ Settings page loads successfully")
                    return True
                    
            except Exception as e:
                print(f"❌ Error testing settings: {e}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                return False

if __name__ == "__main__":
    test_settings()
