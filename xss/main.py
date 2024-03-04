import requests
from Header import Parser
import re
from adder import Adder
from colorama import Fore
import json
from Waf import Waf_Detect
from optparse import OptionParser
import subprocess
import sys
from urllib.parse import urlparse,parse_qsl,urlencode
from concurrent.futures import ThreadPoolExecutor



"""
This script parses command-line arguments for a vulnerability scanning application.

**Options:**

- `-f`, `--filename`: Specify a file containing URLs to scan (e.g., `urls.txt`).
- `-u`, `--url`: Scan a single URL (e.g., `http://example.com/?id=2`).
- `-o`, `--output`: Specify the filename to store scan results (e.g., `result.txt`).
- `-t`, `--threads`: Number of threads to use for concurrent requests (maximum 10).
- `-H`, `--headers`: Specify custom headers to send with requests.
- `--waf`: Enable web application firewall (WAF) detection and subsequent payload testing.
- `-w`, `--custom_waf`: Use specific payloads related to the detected WAF.
- `--crawl`: Enable crawling a website to find potential XSS vulnerabilities.
- `--pipe`: Pipe the output of another process as input to this script.

"""

parser = OptionParser()

parser.add_option("-f", "--filename", dest="filename", help="Specify a file containing URLs to scan (e.g., 'urls.txt').", metavar="FILE")
parser.add_option("-u", "--url", dest="url", help="Scan a single URL (e.g., 'http://example.com/?id=2').")
parser.add_option("-o", "--output", dest="output", help="Specify the filename to store scan results (e.g., 'result.txt').")
parser.add_option("-t", "--threads", dest="threads", help="Number of threads to use for concurrent requests (maximum 10).")
parser.add_option("-H", "--headers", dest="headers", help="Specify custom headers to send with requests.")
parser.add_option("--waf", action="store_true", dest="waf", help="Enable web application firewall (WAF) detection and subsequent payload testing.")
parser.add_option("-w", "--custom_waf", dest="custom_waf", help="Use specific payloads related to the detected WAF.")
parser.add_option("--crawl", action="store_true", dest="crawl", help="Enable crawling a website to find potential XSS vulnerabilities.")
parser.add_option("--pipe", action="store_true", dest="pipe", help="Pipe the output of another process as input to this script.")

val,args = parser.parse_args()
filename = val.filename
threads = val.threads
output = val.output
url = val.url
crawl = val.crawl
waf = val.waf
pipe = val.pipe
custom_waf = val.custom_waf
headers = val.headers

try:
    if headers:
        print(Fore.WHITE + "[+] HEADERS: {}".format(headers))
        headers = Parser.headerParser(headers.split(','))
except AttributeError:
    headers = Parser.headerParser(headers.split())

try:
    threads = int(threads)
except TypeError:
    threads = 1
if threads > 10:
    threads = 7 

if crawl:
    filename = f"{url.split('://')[1]}_katana"


class Main:

    def __init__(self,url=None, filename=None, output=None,headers=None):
        self.filename = filename
        self.url = url
        self.output = output
        self.headers = headers
        #print(headers)
        self.result = []

    def read(self,filename):
        '''
        Read & sort GET  urls from given filename
        '''
        print(Fore.WHITE + "READING URLS")
        urls = subprocess.check_output(f"cat {filename} | grep '=' | sort -u",shell=True).decode('utf-8')
        if not urls:
            print(Fore.GREEN + f"[+] NO URLS WITH GET PARAMETER FOUND")
        return urls.split()

    def write(self, output, value):
        '''
        Writes the output back to the given filename.
        '''
        if not output:
            return None
        subprocess.call(f"echo '{value}' >> {output}",shell=True)

    def replace(self,url,param_name,value):
        return re.sub(f"{param_name}=([^&]+)",f"{param_name}={value}",url)

    def bubble_sort(self, arr):
        """
        Sorts the given array of payloads in ascending order based on specific keys.

        Args:
            arr (list): The list of payloads to be sorted.

        Returns:
            list: The sorted list of payloads.

        Notes:
            - This implementation assumes that each payload in the list is a dictionary,
              and the sorting is based on the values of specific keys within the dictionaries.
            - You may need to modify this function if the structure of your payloads is different.
        """
        n = len(arr)
        for i in range(n - 1):
            for j in range(0, n - i - 1):
                if arr[j]["count"] < arr[j + 1]["count"]:
                    arr[j], arr[j + 1] = arr[j + 1], arr[j]
        return arr

    def crawl(self):
        """
        Initiates a crawling process using Katana and saves the results.

        Args:
            self: Reference to the current object (likely a class instance).

        Returns:
            None

        Raises:
            subprocess.CalledProcessError: If the Katana command fails.
        """
        try:
            subprocess.check_output(f"katana -u {self.url} -o {self.filename}", shell=True)
        except subprocess.CalledProcessError as e:
            print(f"Katana crawling failed: {e}")

    def parameters(self, url):
        """
        Extracts parameter names from the given URL's query string.

        Args:
            self: Reference to the current object.
            url: The URL to extract parameters from.

        Returns:
            list: A list of parameter names found in the URL.
        """
        query_string = urlparse(url).query
        parameters = re.findall(r"[?&](\w+)=", query_string)
        return parameters

    def parser(self, url, param_name, value):
        """
        Replaces a parameter's value in the URL and returns a dictionary of modified parameters.

        Args:
            self: Reference to the current object.
            url: The URL to modify.
            param_name: The name of the parameter to replace.
            value: The new value to assign to the parameter.

        Returns:
            dict: A dictionary containing the parsed URL components, including the modified parameter.
        """
        parsed_url = urlparse(url)
        query_params = dict(parse_qsl(parsed_url.query))
        query_params[param_name] = value
        new_query_string = urlencode(query_params, doseq=True)
        new_url = parsed_url._replace(query=new_query_string).geturl()
        return {
            "url": new_url,
            "params": query_params,
        }

    def validator(self, arr, param_name, url):
        """
        Analyzes a list of potential parameter values for potential reflection vulnerabilities.

        Args:
            url (str): The base URL to be tested with different parameters.
            param_name (str): The name of the parameter to be tested.
            arr (list): A list of potential parameter values to be tested.
            headers (dict, optional): Custom headers to be included in the HTTP request. Defaults to None.

        Returns:
            dict: A dictionary containing potential vulnerable parameters found, where the key is the parameter name
                  and the value is a list of potentially vulnerable values.

        Raises:
            Exception: Any exceptions that occur during the execution.
        """
        vulnerable_params = {}
        for value in arr:
            payload_url = self.parser(url, param_name, value)["url"]
            try:
                response = requests.get(payload_url, headers=self.headers, timeout=5)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"Request error for {payload_url}: {e}")
                continue
            except requests.exceptions.HTTPError as e:
                if "404 Not Found" in str(e):
                    continue
                print(f"HTTP error for {payload_url}: {e}")
                continue

            if value in response.text:
                if param_name not in vulnerable_params:
                    vulnerable_params[param_name] = []
                vulnerable_params[param_name].append(value)

        return vulnerable_params

    def fuzzer(self, url):
        """
        Performs fuzz testing on parameters extracted from a given URL.

        Args:
            url (str): The URL to fuzz.
            dangerous_characters (list, optional): A list of characters considered
                                 unsafe for fuzzing. Defaults to None.

        Returns:
            list: The results of applying the fuzzing logic to each parameter.

        Raises:
            ValueError: If no parameters are identified in the URL.
        """
        if not url:
            raise ValueError("URL is missing")

        if not dangerous_characters:
            dangerous_characters = [
                "<",
                ">",
                '"',
                "'",
                "&",
                ";",
                "javascript",
                "script",
            ]

        parameters = self.parameters(url)
        if not parameters:
            raise ValueError("No parameters found in the URL")

        fuzz_results = []

        for param in parameters:
            for char in dangerous_characters:
                fuzzed_param_value = f"{param}={urlencode(char)}"
                fuzz_results.append(self.parser(url, param, fuzzed_param_value))

        return fuzz_results

def filter_and_rank_payloads(arr, payload_file="payloads.json", firewall=None, threads=1):
    """
    Filters and ranks payloads based on firewall compatibility and occurrence within the target string.

    Args:
        arr (str): The target string against which payloads are compared.
        payload_file (str, optional): The file path containing payloads in JSON format. Defaults to "payloads.json".
        firewall (str, optional): The specific firewall to filter payloads for. If None, payloads not specific to a firewall are used. Defaults to None.
        threads (int, optional): The number of threads to use for parallel processing (not implemented in this function). Defaults to 1.

    Returns:
        list: A list of ranked payloads, with potential perfect payloads at the beginning and others ranked by occurrence.

    Raises:
        FileNotFoundError: If the specified payload file is not found.
        JSONDecodeError: If the payload file contents are invalid JSON.
    """
    try:
        with open(payload_file, "r") as f:
            payloads = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Payload file '{payload_file}' not found")
    except json.JSONDecodeError:
        raise json.JSONDecodeError("Invalid JSON in payload file")

    filtered_payloads = payloads
    if firewall:
        filtered_payloads = [
            payload
            for payload in payloads
            if any(
                firewall.lower() in waf.lower() for waf in payload["wafs"]
            )
        ]

    for payload in filtered_payloads:
        payload["count"] = arr.count(payload["payload"])

    ranked_payloads = sorted(filtered_payloads, key=lambda payload: (payload["count"], not payload["is_perfect_match"]), reverse=True)

    return ranked_payloads

if __name__ == "__main__":
    urls = ["https://kiit.ac.in"]
    Scanner = Main(filename, output, headers=headers)
    try:
        if url and not filename:
            Scanner = Main(url,output,headers=headers)
            Scanner.scanner(url)
            if Scanner.result:
                Scanner.write(output,Scanner.result[0])
            exit()
        elif filename and crawl:
            Scanner.crawl()
            urls = Scanner.read(filename)
        elif pipe:
            out = sys.stdin
            for url in out:
                urls.append(url)
        else:
            urls = Scanner.read(filename)
        print(Fore.GREEN + "CURRENT THREADS: {}".format(threads))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(Scanner.scanner,urls)
        for i in Scanner.result:
            Scanner.write(output,i)
        print(Fore.WHITE + "COMPLETED")
    except Exception as e:
        print(e)