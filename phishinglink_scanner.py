import requests
url=input("Enter url:")
response=requests.get(url)
print("Page title:",response.text.split('<title>')[1].split('</title>')[0])

# Test the function
from bs4 import BeautifulSoup

soup=BeautifulSoup(response.text,'html.parser')
for link in soup.find_all('a'):
    print(link.get('href'))

# Test the function
def is_suspicious(url):
    suspicious_tlds=['.xyz','.top','.club']
    return any(url.endswith(tld)for tld in suspicious_tlds) or len(url)>75

# Test the function
def analyze_url(url):
    if is_suspicious(url):
        return "Suspicious URL!"
    response=requests.get(url)
    soup=BeautifulSoup(response.text,'html.parser')
    return "URL seems safe."

# Test the scanner
def check_with_virustotal(url,api_key):
    headers={'x_apikey':api_key}
    response=requests.get(f'https://www.virustotal.com/api/v3/urls/{url}',headers=headers)
    return response.json()

def main():
    url=input("Enter a URL to check:")
    print(analyze_url(url))

