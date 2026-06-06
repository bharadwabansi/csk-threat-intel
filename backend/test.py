import requests
from bs4 import BeautifulSoup
 
url = "https://www.csk.gov.in/alerts/Osiris-Ransomware.html"
headers = {"User-Agent": "Mozilla/5.0"}
resp = requests.get(url, headers=headers, timeout=15)
soup = BeautifulSoup(resp.text, "lxml")
 
# Remove noise
for tag in soup(["script", "style", "nav", "header", "footer", "aside"]):
    tag.decompose()
 
# Print all div class names to understand structure
for div in soup.find_all("div", class_=True):
    print(div.get("class"), "->", div.get_text(strip=True)[:80])