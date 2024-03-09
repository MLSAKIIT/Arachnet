import re
import ast
import argparse
import requests
import subprocess
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init

init(autoreset=True)

class IDORTarget:
    def __init__(self, url, depth, **kwargs):
        self.url = url
        self.depth = depth
        self.headers = kwargs.get('headers', {})
        self.proxies = kwargs.get('proxies', {})
        self.cookies = kwargs.get('cookies', None)
        self.post_data = kwargs.get('post_data', "")
        
    def parse_headers(headers_str):
        try:
            headers = ast.literal_eval(headers_str)
            if isinstance(headers, dict):
                return headers
            else:
                print(f"{Fore.RED}[ERROR] Invalid headers format: {headers_str}{Style.RESET_ALL}")
                return {}
        except (ValueError, SyntaxError):
            print(f"{Fore.RED}[ERROR] Invalid headers format: {headers_str}{Style.RESET_ALL}")
            return {}

    def check_idor(self):
        try:
            response = requests.get(self.url, headers=self.headers, proxies=self.proxies, cookies=self.cookies)
            response.raise_for_status()
            content = response.text
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
            return False

        patterns = [
            r'\b(id|user_id|customer_id|order_id|product_id)\b=\d+',
            r'\b(id|user_id|customer_id|order_id|product_id)\b=[a-zA-Z0-9]+',
            r'\b(id|user_id|customer_id|order_id|product_id)\b=.*',
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                param, value = match.group().split('=')
                test_content = self.test_idor(param, 'test')
                if test_content and value in test_content:
                    print(f"{Fore.GREEN}[+] Confirmed IDOR vulnerability: {self.url}")
                    # print(f"Parameter: {param}, Original Value: {value}, Test Value: test{Style.RESET_ALL}")
                    return True

        return False

    def test_idor(self, param, value):
        modified_url = re.sub(f"{param}=[^&]*", f"{param}={value}", self.url)
        try:
            response = requests.get(modified_url, headers=self.headers, proxies=self.proxies, cookies=self.cookies)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
            return None

    def explore(self):
        url_name = urlparse(self.url).netloc
        katana_output_file = f"{url_name}_katana"
        katana_cmd = f"katana -u {self.url} -output {katana_output_file} -depth {self.depth}"
        subprocess.run(katana_cmd, shell=True, check=True)

        with open(katana_output_file, 'r') as f:
            links = [line.strip() for line in f.readlines()]

        vulnerable_urls = []
        for link in links:
            target = IDORTarget(link, self.depth, headers=self.headers, proxies=self.proxies, cookies=self.cookies)
            if target.check_idor():
                vulnerable_urls.append(link)

        if vulnerable_urls:
            print(f"{Fore.GREEN}\n[+] Vulnerable URLs:{Style.RESET_ALL}")
            for url in vulnerable_urls:
                print(url)
        else:
            print(f"{Fore.RED}[-] No IDOR vulnerabilities found.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='IDOR Scanner')
    parser.add_argument('-u', '--url', dest="url", required=True, help='Target URL')
    parser.add_argument('-d', '--depth', dest="depth", required=True, help='Depth of search')
    parser.add_argument('-H', '--headers', dest="headers", default={}, help='Additional headers (e.g., \'{"User-Agent": "Mozilla/5.0"}\')')
    parser.add_argument('-P', '--proxy', dest="proxy", default=None, help='Proxy (e.g., "127.0.0.1:8080")')
    parser.add_argument('-c', '--cookies', dest="cookies", default=None, help='Cookies (e.g., "session=abc123")')
    parser.add_argument('-p', '--post-data', dest="post_data", default=None, help='POST data (e.g., "{\"id\": \"IDOR\"}")')
    args = parser.parse_args()
    
    args = parser.parse_args()

    headers = IDORTarget.parse_headers(args.headers)

    target = IDORTarget(
        url=args.url,
        depth=args.depth,
        headers=headers,
        proxy=args.proxy,
        cookies=args.cookies,
        post_data=args.post_data
    )
    target.explore()

if __name__ == '__main__':
    main()