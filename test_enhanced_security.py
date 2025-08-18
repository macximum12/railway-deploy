#!/usr/bin/env python3
"""
🔒 BRUTE FORCE PROTECTION TESTING
Test the enhanced security features implementation
"""

import requests
import time
import json
from datetime import datetime

class BruteForceTest:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_rate_limiting(self):
        """Test rate limiting on login endpoint"""
        print("\n🔨 TESTING RATE LIMITING")
        print("=" * 40)
        
        login_url = f"{self.base_url}/login"
        
        # Rapid fire attempts to test rate limiting
        for i in range(15):  # Try 15 rapid attempts
            start_time = time.time()
            
            try:
                response = self.session.post(login_url, data={
                    'username': 'testuser',
                    'password': f'wrongpass{i}'
                }, timeout=5)
                
                end_time = time.time()
                response_time = end_time - start_time
                
                print(f"Attempt {i+1:2d}: HTTP {response.status_code} - {response_time:.2f}s", end="")
                
                if response.status_code == 429:
                    print(" ✅ RATE LIMITED!")
                    return True
                elif response_time > 3:
                    print(" ✅ DELAYED!")
                    return True
                else:
                    print("")
                    
                # Small delay to avoid overwhelming
                time.sleep(0.1)
                
            except requests.exceptions.Timeout:
                print(f"Attempt {i+1:2d}: TIMEOUT ✅ PROTECTION ACTIVE!")
                return True
            except Exception as e:
                print(f"Attempt {i+1:2d}: ERROR - {str(e)}")
        
        print("⚠️ No rate limiting detected")
        return False
    
    def test_progressive_delays(self):
        """Test progressive delay system"""
        print("\n⏱️ TESTING PROGRESSIVE DELAYS")
        print("=" * 40)
        
        login_url = f"{self.base_url}/login"
        delays_detected = []
        
        # Test with same IP but spaced out attempts
        for i in range(6):
            start_time = time.time()
            
            try:
                response = self.session.post(login_url, data={
                    'username': 'admin',
                    'password': 'wrongpassword'
                }, timeout=15)
                
                end_time = time.time()
                response_time = end_time - start_time
                delays_detected.append(response_time)
                
                print(f"Attempt {i+1}: {response_time:.2f}s delay", end="")
                
                if response_time > 1:
                    print(" ✅ DELAY APPLIED!")
                else:
                    print("")
                
                # Wait between attempts
                time.sleep(1)
                
            except requests.exceptions.Timeout:
                print(f"Attempt {i+1}: TIMEOUT - Very long delay applied!")
                delays_detected.append(15.0)
                
        # Analyze delay progression
        print(f"\nDelay progression: {[f'{d:.1f}s' for d in delays_detected]}")
        
        # Check if delays are increasing
        increasing_delays = all(delays_detected[i] <= delays_detected[i+1] for i in range(len(delays_detected)-1))
        if increasing_delays and max(delays_detected) > 3:
            print("✅ Progressive delay system working!")
            return True
        else:
            print("⚠️ Progressive delays may not be fully implemented")
            return False
    
    def test_account_lockout(self):
        """Test account lockout after multiple failures"""
        print("\n🔒 TESTING ACCOUNT LOCKOUT")
        print("=" * 40)
        
        login_url = f"{self.base_url}/login"
        
        print("Making multiple failed attempts for account lockout test...")
        
        # Make several failed attempts
        for i in range(7):
            try:
                response = self.session.post(login_url, data={
                    'username': 'admin',
                    'password': 'definitelywrong'
                }, timeout=10)
                
                print(f"Attempt {i+1}: HTTP {response.status_code}", end="")
                
                if "locked" in response.text.lower() or "blocked" in response.text.lower():
                    print(" ✅ ACCOUNT LOCKED!")
                    return True
                else:
                    print("")
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"Attempt {i+1}: ERROR - {str(e)}")
        
        print("⚠️ Account lockout not detected")
        return False
    
    def test_security_headers(self):
        """Test security headers implementation"""
        print("\n🛡️ TESTING SECURITY HEADERS")
        print("=" * 40)
        
        try:
            response = self.session.get(f"{self.base_url}/login")
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Content-Security-Policy': True  # Just check if present
            }
            
            headers_found = 0
            for header, expected_value in security_headers.items():
                if header in headers:
                    if expected_value is True or headers[header] == expected_value:
                        print(f"✅ {header}: {headers[header]}")
                        headers_found += 1
                    else:
                        print(f"⚠️ {header}: {headers[header]} (expected: {expected_value})")
                else:
                    print(f"❌ {header}: Missing")
            
            print(f"\nSecurity headers implemented: {headers_found}/{len(security_headers)}")
            return headers_found >= len(security_headers) - 1  # Allow one missing
            
        except Exception as e:
            print(f"❌ Error testing security headers: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all brute force protection tests"""
        print("🔒 TESTING ENHANCED SECURITY FEATURES")
        print("=" * 50)
        print(f"Target: {self.base_url}")
        print(f"Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        tests = [
            ("Rate Limiting", self.test_rate_limiting),
            ("Progressive Delays", self.test_progressive_delays),
            ("Account Lockout", self.test_account_lockout),
            ("Security Headers", self.test_security_headers)
        ]
        
        results = {}
        for test_name, test_func in tests:
            try:
                result = test_func()
                results[test_name] = result
            except Exception as e:
                print(f"❌ {test_name} test failed with error: {str(e)}")
                results[test_name] = False
        
        # Summary
        print("\n" + "=" * 50)
        print("🎯 SECURITY ENHANCEMENT TEST RESULTS")
        print("=" * 50)
        
        passed = sum(results.values())
        total = len(results)
        
        for test_name, result in results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{status} - {test_name}")
        
        print(f"\n📊 Overall: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
        
        if passed >= total * 0.75:
            print("🟢 SECURITY ENHANCEMENTS: GOOD")
        elif passed >= total * 0.5:
            print("🟡 SECURITY ENHANCEMENTS: PARTIAL")
        else:
            print("🔴 SECURITY ENHANCEMENTS: NEEDS WORK")
        
        return results

if __name__ == "__main__":
    tester = BruteForceTest()
    tester.run_all_tests()
