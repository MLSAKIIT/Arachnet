import aiohttp
import asyncio
import re
from bs4 import BeautifulSoup
class DnsDumpsterClient:
    def __init__(self, domain):
        self.url = 'https://dnsdumpster.com/'
        self.headers = {
            'Host': 'dnsdumpster.com',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://dnsdumpster.com',
            'Connection': 'keep-alive',
            'Referer': 'https://dnsdumpster.com/',
            'Cookie': 'csrftoken=XbJN0LsEuuQ35oHysX8Znr9TPoFFvikBCoVMVHFVarjCZZR0DB1fWKEZuOoi09Ya; _ga_FPGN9YXFNE=GS1.1.1708695947.1.1.1708696276.0.0.0; _ga=GA1.1.1800228015.1708695948',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'TE': 'trailers'
        }
        self.payload = {
            'csrfmiddlewaretoken': 'ddkJgoD5P0AXO8HP9Cp0ixynoXyF972KSqwIbkQmvX3wIJRhkgigRQ3t3nhiEYGj',
            'targetip': domain,
            'user': 'free'
        }

    async def fetch_data(self):
        async with aiohttp.ClientSession() as session:
            async with session.post(self.url, headers=self.headers, data=self.payload) as response:
                print(response.status)
                html = await response.text()
                #await self.parse_data(html)
                return html
    
    async def parse_data(self, html):
        anchors = ['dnsanchor', 'mxanchor', 'txtanchor', 'hostanchor']
        for anchor in anchors:
            an = 'DNS' if anchor == 'dnsanchor' else ('MX' if anchor == 'mxanchor' else 'host' if anchor == 'hostanchor' else 'TXT')
            soup = BeautifulSoup(html, 'html.parser')
            try:
                dns_servers_section = soup.find('a', attrs={'name': anchor}).find_next('div', class_='table-responsive')
                dns_servers = dns_servers_section.find_all('tr')
                if anchor == 'txtanchor':
                    try:
                        txt_table = dns_servers_section.find('table')
                        print('TXT Records:\n')
                        for i, txt_record in enumerate(txt_table.find_all('tr'), start=1):
                            print(f'\t{i}. {txt_record.td.text.strip()}')
                    except AttributeError:
                        print("No TXT records found.\n")
                else:
                    print(f'\n{an} Records:\n')
                    for dns_server in dns_servers:
                        try:
                            server_name = dns_server.find('td', class_='col-md-4').text.strip()
                            server_name = re.sub(r'HTTP:\s*(.*)', '', server_name)
                            server_name = re.sub(r'FTP:\s*(.*)', '', server_name)
                            server_name = re.sub(r'SSH:\s*(.*)', '', server_name)
                            server_name = re.sub(r'HTTP\s+TECH:\s*(.*)', '', server_name)
                            ip_address = dns_server.find('td', class_='col-md-3').text.strip()
                            location = dns_server.find_all("td", class_="col-md-3")[1].text.strip()
                            print(f"\tServer Name: {server_name.strip()}, IP Address: {ip_address}, Location: {location}\n")
                        except AttributeError:
                            print("Attribute Error occurred while processing DNS server data.\n")
            except AttributeError:
                print("Attribute Error occurred while processing DNS servers section.\n")
