#!/usr/bin/env python3

import requests
import dns.resolver
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import sys
import argparse
from datetime import datetime

class WhoopRecon:
    def __init__(self):
        self.base_domains = [
            'whoop.com',
            'api.whoop.com',
            'app.whoop.com'
        ]
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.results = {
            'domains': [],
            'endpoints': [],
            'technologies': [],
            'findings': []
        }

    def check_domain(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                self.results['domains'].append({
                    'domain': domain,
                    'ip': str(rdata),
                    'timestamp': datetime.now().isoformat()
                })
        except Exception as e:
            pass

    def probe_endpoint(self, url):
        try:
            headers = {'User-Agent': self.user_agent}
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            self.results['endpoints'].append({
                'url': url,
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'timestamp': datetime.now().isoformat()
            })
            
            # Check for interesting security headers
            security_headers = [
                'X-Frame-Options',
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]
            
            missing_headers = [h for h in security_headers if h not in resp.headers]
            if missing_headers:
                self.results['findings'].append({
                    'type': 'missing_security_headers',
                    'url': url,
                    'missing': missing_headers
                })
                
        except Exception as e:
            pass

    def scan(self):
        # Domain enumeration
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.check_domain, self.base_domains)

        # Common endpoint probing
        common_paths = [
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/docs',
            '/swagger',
            '/graphql',
            '/health',
            '/status'
        ]

        endpoints = []
        for domain in self.base_domains:
            for path in common_paths:
                endpoints.append(f'https://{domain}{path}')

        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.probe_endpoint, endpoints)

        return self.results

def main():
    parser = argparse.ArgumentParser(description='WHOOP Reconnaissance Tool')
    parser.add_argument('-o', '--output', help='Output file for results', default='recon_results.json')
    args = parser.parse_args()

    recon = WhoopRecon()
    results = recon.scan()

    with open(args.output, 'w') as f:
        json.dump(results, f, indent=4)

if __name__ == '__main__':
    main() 