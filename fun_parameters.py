from urllib.parse import urlparse , parse_qs
def parameters(url):
      url_parsed = urlparse(url)
      parameter_value = parse_qs(url_parsed.query)
      parameter = list(parameter_value)
      return parameter
print(parameters("https://example.com/path/to/page?param1=value1&param2=value2&param3=value3"))