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
from urllib.parse import urlparse
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
        - This  implementation assumes that each payload in the list is a dictionary,
          and the sorting is based on the values of specific keys within the dictionaries.
        - You may need to modify this function if the structure of your payloads is different.
    """

    
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



    def parameters(self, url):
      """
    Extracts parameter names from the given URL's query string.

    Args:
        self: Reference to the current object.
        url: The URL to extract parameters from.

    Returns:
        list: A list of parameter names found in the URL.
    """


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

    This function assumes the existence of methods `parameters(url)` and
    `validator(dangerous_characters, parameter, url)`, but their specific
    implementations are not included in this code snippet.

    **Important Notes:**

    - Using threads for fuzzing is generally discouraged due to potential
      instability and increased complexity.
    - The `dangerous_characters` list and the custom sorting implemented
      using `bubble_sort` might require adjustments based on your specific
      fuzzing context and application.
    """
       return data



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
        # Load payloads from JSON file

    # Filter payloads based on firewall (if specified)
    
            # Exit if no payloads match the firewall
        # Use generic payloads (no firewall specified)
       

    # Count payload occurrences in the target string

                # Handle potential absence of "Attribute" key
                
                # Handle potential absence of "count" key
                

    # Sort payloads by count (descending) and potential perfect match



    def ranking_function(payload):

    # Extract and rank identified payloads
    
            # Prepend perfect payloads
        # Include payloads with non-zero count

        return payload_list


    def scanner(self,url):
       # Print testing message
       # Check for WAF detection

       # Use custom WAF if defined


       # No WAF detected
 

            # Get potential vulnerabilities from fuzzer

            # Iterate through each potential vulnerability

                 # Filter payloads based on WAF information

                 # Try each filtered payload

                      # Construct new URL with payload

                      # Modify data with the parser (if needed)

                      # Send GET request with the payload

                      # Check for payload presence in the response

     return None

if __name__ == "__main__":
    urls = []
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
