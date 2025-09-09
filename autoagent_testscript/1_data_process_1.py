import requests  # ← 必須導入 requests
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
DATA_PATH = "data/vulnerability_data_1.json"
CHUNKS_PATH = "data/vulnerability_chunks_1.json"
VECTOR_DB_PATH = "data/vulnerability_knowledge_base_1"

# 建立資料夾
os.makedirs("data", exist_ok=True)

# Define URLs
urls = {
    "MS08-067 (NetAPI RCE)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2008-4250",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250"
    },
    "Print Spooler RCE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2010-2729",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-061",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2729",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/TA10-238A"
    },
    "MS12-020 (RDP DoS & RCE)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2012-0002",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-020",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002"
    },
    "EternalBlue SMBv1 RCE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/TA17-132A"
    },
    "Office Equation Editor RCE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2017-11882",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/TA18-201A"
    },
    "BlueKeep (RDP RCE)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/AA19-168A"
    },
    "Internet Explorer Memory Corruption": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2020-0674",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200001",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0674",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/AA20-073A"
    },
    "SIGRed DNS Server RCE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2020-1350",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1350",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1350"
    },
    "SMBGhost (SMBv3 RCE)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/AA20-073A"
    },
    "Microsoft Defender Remote Code Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2021-1647",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-1647",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1647",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/AA21-008A"
    },
    "Microsoft Exchange ProxyLogon": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855"
    },
    "Microsoft SharePoint RCE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2021-27076",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27076",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27076"
    },
    "HTTP.sys RCE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2022-21907",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21907",
        "CISA": "https://www.cisa.gov/news-events/alerts/2022/01/11/microsoft-releases-january-2022-security-updates"
    },
    "Exchange SSRF": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2022-41040",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41040"
    },
    "Exchange RCE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2022-41082",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41082"
    },
    "Windows Hyper-V Remote Code Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-28476",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28476",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28476",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/03/14/microsoft-releases-march-2023-security-updates"
    },
    "Windows Defender RCE via Signature Bypass": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-32031",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32031",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32031",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/06/13/microsoft-releases-june-2023-security-updates"
    },
    "Microsoft Edge Chromium-Based RCE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-35361",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35361",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35361",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/07/11/microsoft-releases-july-2023-security-updates"
    },
    "Windows DCOM Server Remote Code Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-34723",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-34723",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34723",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/08/08/microsoft-releases-august-2023-security-updates"
    },
    "Windows MSHTML Remote Code Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-35235",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35235",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35235"
    },
    "Windows Hyper-V Arbitrary Code Execution": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36100",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36100",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36100",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Remote Desktop Protocol Logic Flaw": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-42917",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-42917",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-42917",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "IIS Buffer Overflow Vulnerability": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-40001",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-40001",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-40001",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    }
}

# 異步爬取函數
async def fetch_text(url, retries=5, timeout=15):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://www.google.com/",
    }
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for attempt in range(retries):
            try:
                response = await client.get(url, headers=headers)
                if response.status_code == 403:
                    logging.warning(f"403 Forbidden for {url} (Attempt {attempt+1}/{retries}), retrying...")
                    await asyncio.sleep(3 + random.random() * 3)
                    continue  # 嘗試重新請求
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                return "\n".join(p.get_text(strip=True) for p in soup.find_all(['p', 'li', 'div']) if p.get_text(strip=True))
            except httpx.RequestError as e:
                logging.warning(f"Failed to fetch {url} (Attempt {attempt+1}/{retries}): {e}")
                await asyncio.sleep(3 + random.random() * 3)
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