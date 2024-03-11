import asyncio
import aiohttp
import argparse
import json
from DnsDumpsterClient import *

async def main(url):
    client = DnsDumpsterClient(url)
    html = await client.fetch_data()
    json_data = await client.parse_data(html)
    json_str = json.dumps(json_data, indent=4)
    print(json_str)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNS Dumpster Client')
    parser.add_argument('-u', '--url', type=str, help='URL/IP to enumerate', required=True)
    args = parser.parse_args()
    asyncio.run(main(args.url))
