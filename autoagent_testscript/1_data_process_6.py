import json
import time
import random
import os
import re
import requests
import asyncio
import faiss
import httpx
import logging
from bs4 import BeautifulSoup
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings

# 設定日誌
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 儲存路徑
DATA_PATH = "data/vulnerability_data_6.json"
CHUNKS_PATH = "data/vulnerability_chunks_6.json"
VECTOR_DB_PATH = "data/vulnerability_knowledge_base_6"


# Define URLs
urls = {
    "MS12-020 (RDP DoS & RCE)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2012-0002",
        "Microsoft": "https://support.microsoft.com/en-us/topic/ms12-020-vulnerabilities-in-remote-desktop-could-allow-remote-code-execution-march-13-2012-a81e282a-dd05-a8af-6716-1eb7e96a34f8",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002"
    },
    "Windows Remote Desktop Protocol Heap Overflow": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-35367",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35367",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35367",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Hyper-V Denial of Service": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-38564",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38564",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38564",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows TCP/IP Stack Denial of Service": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-44487",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487"
    }
}

# 建立資料夾
os.makedirs("data", exist_ok=True)

# 設定 Headers (模仿真實瀏覽器)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1"
}

# 當前的 Session 用來重用 Cookies
session = requests.Session()
session.headers.update(HEADERS)

# 當網站要求 403 時，試試使用 session
async def fetch_text(url, retries=5, timeout=15):
    async with httpx.AsyncClient(headers=HEADERS, timeout=timeout, follow_redirects=True) as client:
        for attempt in range(retries):
            try:
                response = await client.get(url)
                response.raise_for_status()
                
                logging.info(f"✅ 成功訪問 {url}")

                soup = BeautifulSoup(response.text, 'html.parser')
                return "\n".join(p.get_text(strip=True) for p in soup.find_all(['p', 'li', 'div']) if p.get_text(strip=True))
            except httpx.HTTPStatusError as e:
                logging.warning(f"[{e.response.status_code}] 無法訪問 {url} (Retry {attempt+1}/{retries})")
                if e.response.status_code == 403:
                    logging.error("❌ 403 Forbidden, 請使用代理或降低訪問頻率")
                    return fetch_text_with_requests(url)
                await asyncio.sleep(3 + random.random() * 2)
    return ""

# 若無法訪問，使用 requests 進行尚一步檢查
def fetch_text_with_requests(url, retries=3, timeout=15):
    for attempt in range(retries):
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            
            logging.info(f"[requests] Successfully fetched redirected URL: {response.url}")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            return "\n".join(p.get_text(strip=True) for p in soup.find_all(['p', 'li', 'div']) if p.get_text(strip=True))
        except requests.RequestException as e:
            logging.warning(f"[requests] Failed to fetch {url} (Retry {attempt+1}/{retries}): {e}")
            time.sleep(2 + random.random() * 3)
    return ""

# 當網站訪問被拒絕時，試試使用 proxy
def fetch_with_proxy(url, proxy, retries=3, timeout=15):
    proxies = {
        "http": proxy,
        "https": proxy
    }
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=HEADERS, proxies=proxies, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            logging.info(f"[Proxy] Successfully fetched {url}")
            return response.text
        except requests.RequestException as e:
            logging.warning(f"[Proxy] Failed to fetch {url} (Retry {attempt+1}/{retries}): {e}")
            time.sleep(2 + random.random() * 3)
    return ""

# 使用 asyncio 啟動一次性網站爬取
async def fetch_all(urls):
    tasks = [fetch_text(url) for url in urls]
    results = await asyncio.gather(*tasks)
    return results

# 執行爬取
def run_crawl(url_list):
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(fetch_all(url_list))
    return results


# 載入資料
with open(DATA_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

# 清理與過濾
def clean_text(text):
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'[^\x00-\x7F]+', ' ', text)  # 移除非 ASCII 字元
    text = re.sub(r'[“”’]', "'", text)  # 正規化引號
    return text.strip()

# 關鍵字篩選
include_keywords = [
    r'\bCVE-\d{4}-\d{4,7}\b', r'vulnerability', r'security update', r'exploit',
    r'remote code execution', r'privilege escalation', r'memory corruption', r'buffer overflow'
]

exclude_keywords = [r'privacy policy', r'terms of use', r'legal disclaimer']

def is_relevant(text):
    return any(re.search(k, text, re.IGNORECASE) for k in include_keywords) and \
           not any(re.search(k, text, re.IGNORECASE) for k in exclude_keywords)

# 清理並篩選文本
filtered_texts = []
for vuln_name, sources in data.items():
    combined_text = "\n".join(sources.values())
    sentences = combined_text.split("\n")
    relevant_sentences = [clean_text(sentence) for sentence in sentences if is_relevant(sentence)]
    filtered_texts.append("\n".join(relevant_sentences))

# 文本切割
splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=100)
split_texts = [chunk for text in filtered_texts for chunk in splitter.split_text(text)]

with open(CHUNKS_PATH, "w", encoding="utf-8") as f:
    json.dump(split_texts, f, indent=4, ensure_ascii=False)
logging.info(f"Processed {len(split_texts)} refined text segments!")

# FAISS 向量化並存儲
if not split_texts:
    raise ValueError("Processed text data is empty.")

embeddings = OllamaEmbeddings(model="llama3")

batch_size = 500
num_batches = len(split_texts) // batch_size + (1 if len(split_texts) % batch_size else 0)

# 初始化 FAISS
vectorstore = None

for i in range(num_batches):
    batch = split_texts[i * batch_size : (i + 1) * batch_size]
    logging.info(f"Processing batch {i+1}/{num_batches}...")

    batch_embeddings = embeddings.embed_documents(batch)

    if vectorstore is None:
        # **正確初始化 FAISS**
        vectorstore = FAISS.from_texts(batch, embeddings)
    else:
        # **正確添加新數據**
        vectorstore.add_texts(batch)

# 儲存 FAISS 向量資料庫
vectorstore.save_local(VECTOR_DB_PATH)
logging.info("FAISS vector database saved successfully!")
