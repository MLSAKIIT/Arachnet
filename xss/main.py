import requests
from Header import Parser
import re
from adder import Adder
from colorama import Fore
import json
from Waf import Waf_Detect
from argparse import ArgumentParser
import subprocess
from urllib.parse import urlparse, parse_qs
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
# Define the parser object to parse command-line arguments
parser = ArgumentParser(description="Vulnerability scanning application")

parser.add_argument("-f", "--filename", dest="filename", help="Specify a file containing URLs to scan (e.g., urls.txt)")
parser.add_argument("-u", "--url", dest="url", help="Scan a single URL (e.g., http://example.com/?id=2)")
parser.add_argument("-o", "--output", dest="output", help="Specify the filename to store scan results (e.g., result.txt)")
parser.add_argument("-t", "--threads", dest="threads", help="Number of threads to use for concurrent requests (maximum 10)")
parser.add_argument("-H", "--headers", dest="headers", help="Specify custom headers to send with requests")
parser.add_argument("--waf", action="store_true", dest="waf", help="Enable web application firewall (WAF) detection and subsequent payload testing")
parser.add_argument("-w", "--custom_waf", dest="custom_waf", help="Use specific payloads related to the detected WAF")
parser.add_argument("--crawl", action="store_true", dest="crawl", help="Enable crawling a website to find potential XSS vulnerabilities")
parser.add_argument("--pipe", dest="pipe", help="Pipe the output of another process as input to this script")

args = parser.parse_args()
filename = args.filename
threads = args.threads
output = args.output
url = args.url
crawl = args.crawl
waf = args.waf
pipe = args.pipe
custom_waf = args.custom_waf
headers = args.headers

# Sanitize and validate URL
def validate_and_sanitize_url(url):
    if not url:
        raise ValueError("URL cannot be empty")
    # Validate URL format
    if not re.match(r'^https?://\S+', url):
        raise ValueError("Invalid URL format")
    # Sanitize URL to prevent injection attacks
    parsed_url = urlparse(url)
    sanitized_url = parsed_url.geturl()  # Reconstruct sanitized URL
    return sanitized_url

# Sanitize and validate filename
def validate_and_sanitize_filename(filename):
    if not filename:
        raise ValueError("Filename cannot be empty")
    # Sanitize filename to prevent injection attacks
    sanitized_filename = subprocess.check_output(["basename", filename]).decode().strip()
    return sanitized_filename

# Validate and sanitize headers
def validate_and_sanitize_headers(headers):
    if headers:
        header_list = headers.split(',')
        return header_list
    return None

# Validate and sanitize threads
def validate_and_sanitize_threads(threads):
    try:
        if threads:
            threads = int(threads)
            if threads > 10:
                threads = 10
        else:
            # Default to 1 thread if threads is empty
            threads = 1
        return threads
    except ValueError:
        return 1
        
class Main:
    def __init__(self, url=None, filename=None, output=None, headers=None):
        self.filename = filename
        self.url = url
        self.output = output
        self.headers = headers
        self.result = []
        
    def read(self, filename):
        '''
        Read & sort GET  urls from given filename
        '''
        print(Fore.WHITE + "READING URLS")
        try:
            urls = subprocess.check_output(f"cat {filename} | grep '=' | sort -u", shell=True).decode('utf-8')
            if not urls:
                print(Fore.GREEN + f"[+] NO URLS WITH GET PARAMETER FOUND")
            return urls.split()
        except subprocess.CalledProcessError as e:
            print(f"Error reading URLs: {e}")
            return []

    def write(self, output, value):
        '''
        Writes the output back to the given filename.
        '''
        if not output:
            return None
        with open(output, 'a') as file:
            file.write(value + '\n')
        
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

    
    def crawl(self):
        """
        Initiates a crawling process using Katana and saves the results.
        """
        # Function to check if Katana is installed
        def check_katana_installed():
            try:
                # Check if Katana is installed
                subprocess.run(["katana", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                return True
            except subprocess.CalledProcessError:
                return False
        
        # Function to install Katana
        def install_katana():
            try:
                # Install Katana 
                subprocess.run(["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"], check=True)
               
                # Copy katana to /bin/ directory
                subprocess.run(["sudo", "cp", "~/go/bin/katana", "/bin/"], check=True)
                
                print("Katana installed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Error installing Katana: {e}")
                sys.exit(1)
        
        try:
            # Check if Katana is installed
            if not check_katana_installed():
                print(Fore.RED + "[-] Katana is not installed. Installing Katana...")
                install_katana()

            # Define the command to execute Katana for crawling
            command = f"katana --url {self.url} --output {self.filename}"

            # Execute the command using subprocess
            subprocess.run(command, shell=True, check=True)

            print(Fore.GREEN + "[+] Crawling completed successfully.")
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] Error occurred while crawling: {e}")

# Validate and sanitize inputs
try:
    url = validate_and_sanitize_url(url)
    filename = validate_and_sanitize_filename(filename)
    headers = validate_and_sanitize_headers(headers)
    threads = validate_and_sanitize_threads(threads)
except ValueError as e:
    print(f"Error: {e}")
    exit(1)

# Initialize Main class object
main = Main(url=url, filename=filename, output=output, headers=headers)

# Call appropriate methods based on command-line arguments
if crawl:
    main.crawl()
    
    def parameters(self, url):
      """
    Extracts parameter names from the given URL's query string.

    Args:
        self: Reference to the current object.
        url: The URL to extract parameters from.

    Returns:
        list: A list of parameter names found in the URL.
    """
    # Parse the URL to extract the query string
        parsed_url = urlparse(url)
        query_string = parsed_url.query
        
        # Parse the query string to extract parameter names
        parameters = parse_qs(query_string)
        parameter_names = list(parameters.keys())

        # Ask the user for the filename
        output_file = input("Enter the filename to save the parameter names (e.g., parameters.txt): ")

        # Write the parameter names to the output file
        with open(output_file, 'w') as file:
            for parameter in parameter_names:
                file.write(parameter + '\n')

        return parameter_names

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
       pass

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
