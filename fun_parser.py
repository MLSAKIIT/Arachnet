from urllib.parse import urlparse
def parser( url, param_name, value):
      parameter_dict = {}
      url_parsed = urlparse(url)
      parameter_query = url_parsed.query
      seperate_parameter = parameter_query.split("&")
      for parameter in seperate_parameter:
        parameter = parameter.split("=")
        parameter_dict[parameter[0]] = parameter[1]
      parameter_dict[param_name] = value
      return parameter_dict
print(parser("https://example.com/path/to/page?param1=value1&param2=value2&param3=value3","param1","rgksj"))