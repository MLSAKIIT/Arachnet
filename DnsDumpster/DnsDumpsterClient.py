import aiohttp
import asyncio

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
