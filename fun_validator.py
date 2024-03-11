#ENCODING PROBLEM

from colorama import Fore
import requests
from urllib.parse import urlparse , parse_qs
from optparse import OptionParser

parser = OptionParser()

parser.add_option('-f', dest='filename', help="specify Filename to scan. Eg: urls.txt etc")
parser.add_option("-u", dest="url", help="scan a single URL. Eg: http://example.com/?id=2")
parser.add_option('-o', dest='output', help="filename to store output. Eg: result.txt")
parser.add_option('-t', dest='threads', help="no of threads to send concurrent requests(Max: 10)")
parser.add_option('-H', dest='headers', help="specify Custom Headers")
parser.add_option('--waf', dest='waf',action='store_true', help="detect web application firewall and then test payloads")
parser.add_option('-w', dest='custom_waf',help='use specific payloads related to W.A.F')
parser.add_option('--crawl',dest='crawl',help='crawl then find xss',action="store_true")
parser.add_option('--pipe',dest="pipe",action="store_true",help="pipe output of a process as an input")

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


def parser( url, param_name, value):
      parameter_dict = {}
      url_parsed = urlparse(url)
      parameter_query = url_parsed.query
      seperate_parameter = parameter_query.split("&")
      for parameter in seperate_parameter:
        parameter = parameter.split("=")
        parameter_dict[parameter[0]] = parameter[1]
      parameter_dict[param_name] = value.encode('-utf-8')
      return parameter_dict



def validator(arr, param_name, url):
    result = {param_name: []}
    try:
        for data in arr:
            final_parameters = parser(url, param_name, data + "randomstring")
            new_url = urlparse(url).scheme + "://" + urlparse(url).hostname + "/" + urlparse(url).path
            if headers:
                response = requests.get(new_url, params=final_parameters, headers=headers, verify=False).text
            else:
                response = requests.get(new_url, params=final_parameters, verify=False).text
            if data + "randomstring" in response:
                if not threads or threads == 1:
                    print(Fore.GREEN + f"[+] {data} is reflecting in the response")
                result[param_name].append(data)
    except Exception as e:
        print(e)
    return result       

print(validator(['abc','xyz','pqr'],'param1',"https://example.com/path/to/page?param1=value1&param2=value2&param3=value3",))