#!/usr/bin/env python3

import requests
import json
import time
from urllib.parse import urljoin
import uuid
import base64
import hmac
import hashlib

class MobileAPITester:
    def __init__(self):
        self.base_url = "https://api-7.whoop.com"  # Mobile API endpoint
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WHOOP/5.0.0 (iPhone; iOS 17.0; Scale/3.00)',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'x-whoop-device-id': str(uuid.uuid4()),
            'x-whoop-client-os': 'iOS',
            'x-whoop-client-version': '5.0.0'
        })

    def test_api_auth_bypass(self):
        """Test for authentication bypass in mobile API endpoints"""
        endpoints = [
            '/user/profile',
            '/user/metrics',
            '/user/activities',
            '/user/sleep',
            '/user/recovery'
        ]

        auth_tests = [
            {
                'description': 'Missing auth token',
                'headers': {}
            },
            {
                'description': 'Empty auth token',
                'headers': {'Authorization': ''}
            },
            {
                'description': 'Invalid JWT format',
                'headers': {'Authorization': 'Bearer invalid.token.here'}
            },
            {
                'description': 'Expired token reuse',
                'headers': {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.4Adcj3UFYzPUVaVF43FmMze3kqdaNXL7_y9U-3JR0hw'}
            }
        ]

        for endpoint in endpoints:
            for test in auth_tests:
                try:
                    resp = self.session.get(
                        urljoin(self.base_url, endpoint),
                        headers=test['headers'],
                        allow_redirects=False
                    )
                    
                    if resp.status_code == 200 and self._contains_sensitive_data(resp.text):
                        self.results.append({
                            'type': 'mobile_auth_bypass',
                            'endpoint': endpoint,
                            'test_case': test['description'],
                            'severity': 'Critical',
                            'details': 'Potential authentication bypass in mobile API',
                            'proof': self._sanitize_response(resp.text)
                        })
                except Exception as e:
                    print(f"Error in {test['description']} for {endpoint}: {str(e)}")

    def test_device_auth_bypass(self):
        """Test for device authentication bypass scenarios"""
        test_cases = [
            {
                'description': 'Missing device headers',
                'headers': {
                    'Authorization': 'Bearer dummy-token'
                }
            },
            {
                'description': 'Invalid device ID format',
                'headers': {
                    'x-whoop-device-id': 'invalid-device-id',
                    'x-whoop-client-os': 'iOS',
                    'x-whoop-client-version': '5.0.0'
                }
            },
            {
                'description': 'Mismatched client version',
                'headers': {
                    'x-whoop-device-id': str(uuid.uuid4()),
                    'x-whoop-client-os': 'iOS',
                    'x-whoop-client-version': '1.0.0'
                }
            }
        ]

        endpoints = [
            '/device/register',
            '/device/sync',
            '/device/metrics'
        ]

        for endpoint in endpoints:
            for test in test_cases:
                try:
                    resp = self.session.post(
                        urljoin(self.base_url, endpoint),
                        headers=test['headers'],
                        json={'deviceToken': str(uuid.uuid4())},
                        allow_redirects=False
                    )
                    
                    if resp.status_code == 200 and self._indicates_success(resp.text):
                        self.results.append({
                            'type': 'device_auth_bypass',
                            'endpoint': endpoint,
                            'test_case': test['description'],
                            'severity': 'High',
                            'details': 'Potential device authentication bypass',
                            'proof': self._sanitize_response(resp.text)
                        })
                except Exception as e:
                    print(f"Error in {test['description']} for {endpoint}: {str(e)}")

    def test_data_manipulation(self):
        """Test for data manipulation vulnerabilities in mobile API"""
        test_cases = [
            {
                'description': 'Metrics data manipulation',
                'endpoint': '/metrics/sync',
                'data': {
                    'heartRate': 999,
                    'steps': 999999,
                    'calories': 99999,
                    'timestamp': int(time.time())
                }
            },
            {
                'description': 'Activity data manipulation',
                'endpoint': '/activity/record',
                'data': {
                    'type': 'workout',
                    'duration': 3600,
                    'calories': 9999,
                    'strain': 21.0,  # Maximum strain score is 20.0
                    'timestamp': int(time.time())
                }
            },
            {
                'description': 'Sleep data manipulation',
                'endpoint': '/sleep/record',
                'data': {
                    'duration': 86400,  # 24 hours
                    'quality': 100,
                    'stages': {
                        'deep': 86400  # Impossible value
                    }
                }
            }
        ]

        for test in test_cases:
            try:
                resp = self.session.post(
                    urljoin(self.base_url, test['endpoint']),
                    json=test['data'],
                    allow_redirects=False
                )
                
                if resp.status_code == 200 and self._indicates_success(resp.text):
                    self.results.append({
                        'type': 'data_manipulation',
                        'endpoint': test['endpoint'],
                        'test_case': test['description'],
                        'severity': 'High',
                        'details': 'Potential data manipulation vulnerability',
                        'proof': self._sanitize_response(resp.text)
                    })
            except Exception as e:
                print(f"Error in {test['description']}: {str(e)}")

    def _contains_sensitive_data(self, response):
        """Check if response contains actual sensitive data"""
        indicators = [
            '"email":', 
            '"phoneNumber":',
            '"address":',
            '"paymentMethods":',
            '"healthData":',
            '"location":',
            '"metrics":'
        ]
        return any(indicator in response.lower() for indicator in indicators)

    def _indicates_success(self, response):
        """Check if response indicates successful operation"""
        try:
            data = json.loads(response)
            return ('success' in data and data['success']) or \
                   ('status' in data and data['status'] == 'success') or \
                   ('data' in data and data['data'])
        except:
            return False

    def _sanitize_response(self, response):
        """Remove sensitive data from response before logging"""
        try:
            data = json.loads(response)
            # Remove sensitive fields but keep structure
            for key in data.keys():
                if isinstance(data[key], str) and len(data[key]) > 20:
                    data[key] = f"{data[key][:10]}..."
            return json.dumps(data)
        except:
            return response[:100] + "..."

    def run_tests(self):
        """Run all mobile API security tests"""
        print("Testing for API authentication bypass...")
        self.test_api_auth_bypass()
        
        print("Testing for device authentication bypass...")
        self.test_device_auth_bypass()
        
        print("Testing for data manipulation...")
        self.test_data_manipulation()
        
        return self.results

def main():
    tester = MobileAPITester()
    results = tester.run_tests()
    
    with open('vulnerabilities/mobile_api_findings.json', 'w') as f:
        json.dump(results, f, indent=4)
    
    print("\nTesting completed. Results saved to mobile_api_findings.json")
    if results:
        print(f"\nFound {len(results)} potential issues:")
        for result in results:
            print(f"- {result['type']} ({result['severity']}): {result['details']}")

if __name__ == '__main__':
    main() 