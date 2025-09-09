import json
import time
import random
import os
import re
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
DATA_PATH = "data/vulnerability_data_7.json"
CHUNKS_PATH = "data/vulnerability_chunks_7.json"
VECTOR_DB_PATH = "data/vulnerability_knowledge_base_7"

# 建立資料夾
os.makedirs("data", exist_ok=True)

# Define URLs
urls = {
    "Azure AD Pass-Through Auth Bypass": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2022-23272",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-23272",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23272",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows BitLocker Bypass via TPM": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-24950",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24950",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24950",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Microsoft SQL Server Buffer Overflow": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-24955",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24955",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24955",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Active Directory LDAP Relay Attack": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-24958",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24958",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24958",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows IPv6 Stack Heap Overflow": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-32029",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32029",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32029",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Group Policy Spoofing": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-32036",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32036",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32036",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Kernel Pool Corruption": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-32032",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32032",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32032",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Defender SmartScreen Bypass": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-35364",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35364",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35364",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows WiFi Stack Buffer Overflow": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2024-30078",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30078",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-30078",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Server File Server Exploit": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36101",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36101",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36101",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Hyper-V Arbitrary Code Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36100",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36100",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36100",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows UAC Bypass via Device Drivers": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36103",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36103",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36103",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows DirectComposition Arbitrary Code Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36701",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36701",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36701",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Graphics Subsystem Arbitrary Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36701",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36701",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36701",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Microsoft Office VBA Macro Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36804",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36804",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36804",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows PowerShell Script Execution Bypass": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36807",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36807",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36807",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows PowerShell Code Execution Bypass": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36807",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36807",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36807",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows UAC Bypass via Kernel Driver": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36802",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36802",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36802",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows TDX Arbitrary Code Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-38146",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38146",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38146",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    }
}

# 異步爬取函數
async def fetch_text(url, retries=5, timeout=15):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(retries):
            try:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                return "\n".join(p.get_text(strip=True) for p in soup.find_all(['p', 'li', 'div']) if p.get_text(strip=True))
            except httpx.RequestError as e:
                logging.warning(f"Failed to fetch {url} (Attempt {attempt+1}/{retries}): {e}")
                await asyncio.sleep(2 + random.random() * 3)
    return ""

# 異步爬取所有漏洞資料
async def fetch_all():
    tasks = []
    for vuln, sources in urls.items():
        for source, url in sources.items():
            tasks.append((vuln, source, fetch_text(url)))
    
    results = await asyncio.gather(*(t[2] for t in tasks))
    data = {}
    for i, (vuln, source, _) in enumerate(tasks):
        data.setdefault(vuln, {})[source] = results[i]

    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    logging.info("Successfully crawled vulnerability information!")

asyncio.run(fetch_all())

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

# 初始化 Ollama embeddings
embedding_model = OllamaEmbeddings(model="llama3")

batch_size = 500
num_batches = len(split_texts) // batch_size + (1 if len(split_texts) % batch_size else 0)

# 初始化 FAISS
vectorstore = None

for i in range(num_batches):
    batch = split_texts[i * batch_size : (i + 1) * batch_size]
    logging.info(f"Processing batch {i+1}/{num_batches}...")

    # 生成嵌入
    batch_embeddings = embedding_model.embed_documents(batch)

    # 確保 batch_embeddings 格式正確 (N x D)
    batch_embeddings = [list(embedding) for embedding in batch_embeddings]

    if vectorstore is None:
        vectorstore = FAISS.from_texts(batch, embedding=embedding_model)
    else:
        vectorstore.add_texts(batch, embedding=embedding_model)

vectorstore.save_local(VECTOR_DB_PATH)
logging.info("FAISS vector database saved successfully!")

