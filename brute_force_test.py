#!/usr/bin/env python3
"""
Focused Brute Force Security Test
"""

import requests
import time
from datetime import datetime

def test_brute_force_detailed():
    """Detailed brute force testing"""
    base_url = "http://127.0.0.1:5000"
    session = requests.Session()
    
    print("🔒 DETAILED BRUTE FORCE ATTACK TEST")
    print("=" * 50)
    
    # Test 1: Sequential failed attempts
    print("Testing sequential failed login attempts...")
    for i in range(10):
        try:
            start_time = time.time()
            response = session.post(f"{base_url}/login", 
                                   data={'username': 'admin', 'password': f'wrong{i}'}, 
                                   timeout=15)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            print(f"Attempt {i+1}: Status {response.status_code}, Response time: {response_time:.2f}s")
            
            # Check response content for security measures
            if "locked" in response.text.lower():
                print(f"✅ ACCOUNT LOCKOUT detected after {i+1} attempts")
                break
            elif "too many" in response.text.lower():
                print(f"✅ RATE LIMITING detected after {i+1} attempts")
                break
            elif response_time > 5:
                print(f"✅ PROGRESSIVE DELAY detected (response time: {response_time:.2f}s)")
            elif "invalid" in response.text.lower():
                print(f"⚠️  Attempt {i+1} failed normally")
            
            time.sleep(1)  # Wait between attempts
            
        except requests.exceptions.Timeout:
            print(f"✅ REQUEST TIMEOUT after {i+1} attempts (security measure)")
            break
        except Exception as e:
            print(f"❌ Error on attempt {i+1}: {str(e)}")
            break
    
    # Test 2: Check if server is still responsive
    print("\nTesting server responsiveness after attacks...")
    try:
        response = session.get(f"{base_url}/login", timeout=10)
        if response.status_code == 200:
            print("✅ Server still responsive")
        else:
            print(f"⚠️  Server response code: {response.status_code}")
    except Exception as e:
        print(f"❌ Server unresponsive: {str(e)}")
    
    # Test 3: Check security headers
    print("\nChecking security headers...")
    try:
        response = session.get(f"{base_url}/login")
        headers = response.headers
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content security policy'
        }
        
        for header, description in security_headers.items():
            if header in headers:
                print(f"✅ {header}: {description}")
            else:
                print(f"❌ Missing {header}: {description}")
                
    except Exception as e:
        print(f"❌ Error checking headers: {str(e)}")

if __name__ == "__main__":
    test_brute_force_detailed()
