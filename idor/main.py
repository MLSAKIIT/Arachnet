import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import argparse
from tqdm import tqdm
import sys
import json
import os
import time
import socket
import zipfile

class Scanner:
    def __init__(self, url, session, http_methods, test_values):
        self.url = url
        self.session = session
        self.visited_urls = set()
        self.http_methods = http_methods
        self.test_values = test_values
        self.results = []

    def check_connection(self):
        try:
            socket.create_connection(("www.google.com", 80))
            return True
        except OSError:
            pass
        return False

    def crawl(self, url=None):
        if url is None:
            url = self.url
        self.visited_urls.add(url)
        response = self.session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.startswith(self.url) and href not in self.visited_urls:
                self.crawl(href)

    def test_request(self, url, method):
        try:
            response = self.session.request(method, url)
            return response.status_code, response.text
        except requests.exceptions.RequestException as e:
            return None, str(e)

    def analyze_response(self, url, method, status_code, response_text):
        if status_code == 200 and "access denied" not in response_text.lower():
            result = {'url': url, 'method': method, 'vulnerability': 'Potential IDOR'}
            self.results.append(result)
        else:
            result = {'url': url, 'method': method, 'vulnerability': 'No IDOR'}
            self.results.append(result)

    def run(self):
        if not self.check_connection():
            print("No internet connection.")
            sys.exit(1)

        self.crawl()

        for visited_url in tqdm(self.visited_urls, desc="Scanning URLs", unit="URL"):
            for method in self.http_methods:
                for value in self.test_values:
                    test_url = urljoin(visited_url, '?id={}'.format(value))
                    status_code, response_text = self.test_request(test_url, method)
                    self.analyze_response(test_url, method, status_code, response_text)

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        results_file = f'scan_results_{timestamp}.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f)

        with zipfile.ZipFile(f'{results_file}.zip', 'w') as zipf:
            zipf.write(results_file)

        os.remove(results_file)

def main():
    parser = argparse.ArgumentParser(description="Web Scanner")
    parser.add_argument("url", help="The URL to scan")
    parser.add_argument("--methods", nargs='+', default=['GET', 'POST', 'PUT', 'DELETE'], help="HTTP methods to use")
    parser.add_argument("--values", nargs='+', default=['1', '2', '3', '4'], help="Test values to use")
    args = parser.parse_args()

    session = requests.Session()
    scanner = Scanner(args.url, session, args.methods, args.values)
    scanner.run()

if __name__ == "__main__":
    main()