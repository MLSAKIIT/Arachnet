import requests
from bs4 import BeautifulSoup

def scan_for_idor(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    ids = []
    for tag in soup.find_all('input'):
        if tag.get('type') == 'hidden':
            ids.append(tag.get('id'))
    return ids
