import re
import argparse
import requests
import subprocess
from urllib.parse import urlparse, urljoin

def test_idor(url, param, value):
    """
    Test for IDOR vulnerabilities by sending a request with modified data.
    """
    modified_url = re.sub(f"{param}=[^&]*", f"{param}={value}", url)
    try:
        response = requests.get(modified_url)
        response.raise_for_status()
        print(response.text)
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def check_idor(url):
    """
    Check for potential IDOR vulnerabilities in the webpage content.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return

    patterns = [
        r'\b(id|user_id|customer_id|order_id|product_id)\b=\d+',
        r'\b(id|user_id|customer_id|order_id|product_id)\b=[a-zA-Z0-9]+',
        r'\b(id|user_id|customer_id|order_id|product_id)\b=.*',
    ]

    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            param, value = match.group().split('=')
            test_content = test_idor(url, param, 'test')
            if test_content and value in test_content:
                print(f"[+] Confirmed IDOR vulnerability: {url}")
                print(f"Parameter: {param}, Original Value: {value}, Test Value: test")
                return True

    return False

def main():
    parser = argparse.ArgumentParser(description='IDOR Scanner')
    parser.add_argument('-u', '--url', dest="url", required=True, help='Target URL')
    parser.add_argument('-d', '--depth', dest="depth", required=True, help='Depth of search')
    args = parser.parse_args()

    target_url = args.url
    target_depth = args.depth
    url_name = urlparse(target_url).netloc

    # Use Katana to extract links
    katana_output_file = f"{url_name}_katana"
    katana_cmd = f"katana -u {target_url} -output {katana_output_file} -depth {target_depth}"
    subprocess.run(katana_cmd, shell=True, check=True)

    with open(katana_output_file, 'r') as f:
        links = [line.strip() for line in f.readlines()]

    vulnerable_urls = []
    for link in links:
        if check_idor(link):
            vulnerable_urls.append(link)

    if vulnerable_urls:
        print("\n[+] Vulnerable URLs:")
        for url in vulnerable_urls:
            print(url)
    else:
        print("[-] No IDOR vulnerabilities found.")

if __name__ == '__main__':
    main()
