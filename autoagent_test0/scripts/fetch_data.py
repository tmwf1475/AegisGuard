import requests
from bs4 import BeautifulSoup
import json
import re

# Target URLs
urls = {
    "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2017-0143",
    "Microsoft": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
}

# Set User-Agent to simulate a normal browser request
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

data = {}

# Filter out irrelevant HTML blocks (avoid fetching navigation, privacy policy, etc.)
exclude_keywords = [
    "navigation", "privacy policy", "terms of use", "acknowledgments",
    "Visualizations", "Legal Disclaimer", "Vulnerability Search", 
    "CPE Search", "Expand or Collapse", "Upgrade to Microsoft Edge"
]

def clean_text(text):
    """ Clean text by removing special characters and formatting errors """
    text = re.sub(r'\s+', ' ', text)  # Remove extra spaces and line breaks
    text = text.replace("â", "’")  # Fix encoding errors
    return text.strip()

def is_relevant(text):
    """ Filter out irrelevant content """
    return not any(keyword.lower() in text.lower() for keyword in exclude_keywords)

for source, url in urls.items():
    print(f"Fetching: {url}")
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an error if the request fails
        
        soup = BeautifulSoup(response.text, 'html.parser')

        # Attempt to extract main content
        elements = soup.find_all(['p', 'li', 'span', 'div'])

        # Filter out useless content and clean the text
        text_content = "\n".join([
            clean_text(element.get_text()) for element in elements if is_relevant(element.get_text())
        ])
        
        data[source] = text_content
        print(f"Successfully fetched {source} data!")

    except requests.RequestException as e:
        print(f"Failed to fetch {source}: {e}")
        data[source] = "Error: Failed to fetch data."

# Save as JSON
with open("data/ms17-010_data.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4, ensure_ascii=False)

print("MS17-010 information download complete!")