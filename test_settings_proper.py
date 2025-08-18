#!/usr/bin/env python3
"""
Comprehensive test for settings page with proper session
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, ACTIVE_SESSIONS
from datetime import datetime

def test_settings_with_proper_session():
    """Test settings with a properly configured session"""
    with app.test_client() as client:
        with app.app_context():
            # Create a proper session ID and add it to active sessions
            session_id = 'test-session-123'
            ACTIVE_SESSIONS[session_id] = {
                'username': 'admin',
                'login_time': datetime.now().isoformat(),
                'user_agent': 'Test Agent',
                'ip_address': '127.0.0.1'
            }
            
            # Simulate a properly logged-in user session
            with client.session_transaction() as sess:
                sess['logged_in'] = True
                sess['username'] = 'admin'
                sess['session_id'] = session_id
                sess['user_role'] = 'Administrator'
                sess['last_activity'] = datetime.now().isoformat()
                
            try:
                # Test GET request to settings
                print("Testing settings page...")
                response = client.get('/settings')
                print(f"Settings response status: {response.status_code}")
                
                if response.status_code == 200:
                    print("✅ Settings page loads successfully!")
                    return True
                elif response.status_code == 302:
                    print("⚠️  Settings page redirecting (likely to login)")
                    return False
                elif response.status_code == 500:
                    print("❌ Settings page has 500 Internal Server Error")
                    print(f"Response data: {response.data.decode('utf-8')[:500]}...")
                    return False
                else:
                    print(f"⚠️  Unexpected status code: {response.status_code}")
                    return False
                    
            except Exception as e:
                print(f"❌ Error testing settings: {e}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                return False
            finally:
                # Clean up
                if session_id in ACTIVE_SESSIONS:
                    del ACTIVE_SESSIONS[session_id]

if __name__ == "__main__":
    test_settings_with_proper_session()
