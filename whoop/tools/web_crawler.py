#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import json
import re
import argparse
from urllib.parse import urljoin, urlparse
import time

class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited = set()
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc.endswith('whoop.com')

    def find_sensitive_info(self, url, content):
        patterns = {
            'api_key': r'(?i)(api[_-]key|apikey|api[_-]secret|apisecret)["\']?\s*[:=]\s*["\']([^"\']+)',
            'jwt': r'(?i)(eyJ[A-Za-z0-9-_]*\.eyJ[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*)',
            'aws_key': r'(?i)(AKIA[0-9A-Z]{16})',
            'email': r'[a-zA-Z0-9._%+-]+@whoop\.com',
            'internal_ip': r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
            'debug_info': r'(?i)(debug|stack trace|error:)',
            'version_info': r'(?i)(version["\']?\s*[:=]\s*["\']([^"\']+))'
        }

        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                self.findings.append({
                    'type': 'information_disclosure',
                    'subtype': pattern_name,
                    'url': url,
                    'severity': 'Medium',
                    'details': f'Found potential {pattern_name}: {match.group(0)[:50]}...'
                })

    def check_security_headers(self, url, headers):
        security_headers = {
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        }

        missing = security_headers - set(headers.keys())
        if missing:
            self.findings.append({
                'type': 'missing_security_headers',
                'url': url,
                'severity': 'Low',
                'details': f'Missing security headers: {", ".join(missing)}'
            })

    def check_for_debug_endpoints(self, url):
        debug_paths = [
            '/debug',
            '/status',
            '/health',
            '/metrics',
            '/admin',
            '/console',
            '/swagger',
            '/api-docs'
        ]

        for path in debug_paths:
            test_url = urljoin(url, path)
            try:
                resp = self.session.get(test_url, timeout=5)
                if resp.status_code == 200:
                    self.findings.append({
                        'type': 'exposed_debug_endpoint',
                        'url': test_url,
                        'severity': 'Medium',
                        'details': f'Potentially exposed debug endpoint: {path}'
                    })
            except Exception:
                continue

    def crawl(self, url, depth=2):
        if depth <= 0 or url in self.visited or not self.is_valid_url(url):
            return

        self.visited.add(url)
        print(f"Crawling: {url}")

        try:
            resp = self.session.get(url, timeout=10)
            self.check_security_headers(url, resp.headers)
            
            # Check for sensitive information in response
            self.find_sensitive_info(url, resp.text)
            
            # Check for debug endpoints
            self.check_for_debug_endpoints(url)

            # Parse links and continue crawling
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    next_url = urljoin(url, href)
                    if self.is_valid_url(next_url):
                        self.crawl(next_url, depth - 1)

            # Check JavaScript files
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    js_url = urljoin(url, src)
                    if self.is_valid_url(js_url) and js_url not in self.visited:
                        try:
                            js_resp = self.session.get(js_url, timeout=5)
                            self.find_sensitive_info(js_url, js_resp.text)
                        except Exception:
                            continue

            time.sleep(1)  # Be nice to the server

        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Web Security Crawler')
    parser.add_argument('-u', '--url', required=True, help='Base URL to crawl')
    parser.add_argument('-o', '--output', help='Output file for results', default='web_findings.json')
    args = parser.parse_args()

    crawler = WebCrawler(args.url)
    crawler.crawl(args.url)

    with open(args.output, 'w') as f:
        json.dump(crawler.findings, f, indent=4)

if __name__ == '__main__':
    main() 