import json
import time
import random
import os
import re
import random
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
DATA_PATH = "data/vulnerability_data_2.json"
CHUNKS_PATH = "data/vulnerability_chunks_2.json"
VECTOR_DB_PATH = "data/vulnerability_knowledge_base_2"

# 建立資料夾
os.makedirs("data", exist_ok=True)

# Define URLs
urls = {
    "Stuxnet (Windows Kernel LPE)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2010-2568",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-046",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2568"
    },
    "MS13-053 (Kernel Mode Drivers LPE)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2013-3660",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-053",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-3660",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/TA13-190A"
    },
    "MS14-068 (Kerberos PrivEsc)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2014-6324",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6324"
    },
    "MS15-051 (Kernel PrivEsc)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2015-1701",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-051",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1701"
    },
    "MS16-032 (Secondary Logon PrivEsc)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2016-0999",
        "Microsoft": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0999"
    },
    "Windows Task Scheduler LPE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2019-1069",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1069",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1069"
    },
    "PrintDemon (Print Spooler LPE)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2020-1048",
        "Microsoft": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1048",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1048"
    },
    "PrintNightmare LPE": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527"
    },
    "Named Pipe Hijacking": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2021-1727",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1727",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1727",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/aa21-008a"
    },
    "Windows COM Elevation of Privilege": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2021-1648",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1648",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1648",
        "CISA": "https://www.cisa.gov/uscert/ncas/alerts/aa21-008a"
    },
    "HiveNightmare (SAM File Exposure)": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2021-36934",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36934"
    },
    "Windows Installer Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2021-41379",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-41379",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41379"
    },
    "Windows Common Log File System PrivEsc": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-24957",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24957",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24957",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/02/14/microsoft-releases-february-2023-security-updates"
    },
    "Windows CLFS Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-28252",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28252",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/04/11/microsoft-releases-april-2023-security-updates"
    },
    "Outlook Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-23397",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23397",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/03/14/microsoft-releases-march-2023-security-updates"
    },
    "Windows Task Scheduler Zero-Day": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-29339",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29339",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29339",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/05/09/microsoft-releases-may-2023-security-updates"
    },
    "Windows ALPC Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-29338",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29338",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29338",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/05/09/microsoft-releases-may-2023-security-updates"
    },
    "Windows UAC Elevation of Privilege": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-24933",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24933",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24933",
        "CISA": "https://www.cisa.gov/news-events/alerts/2023/02/14/microsoft-releases-february-2023-security-updates"
    },
    "Windows User Profile Service Elevation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36903",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36903",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36903"
    },
    "Windows NTFS Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-32030",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32030",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32030",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows NTFS Compression Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-32035",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32035",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32035",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Kernel Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-32028",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32028",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32028",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Kernel GDI Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-36104",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36104",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36104",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Hyper-V Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-32037",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32037",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32037",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Print Spooler Arbitrary File Write": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-31502",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-31502",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31502",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows Defender Privilege Escalation": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-42811",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-42811",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-42811",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    },
    "Windows COM Server Security Feature Bypass": {
        "CVE": "https://nvd.nist.gov/vuln/detail/CVE-2023-37565",
        "Microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-37565",
        "Mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-37565",
        "CISA": "https://www.cisa.gov/news-events/cybersecurity-advisories"
    }
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:110.0) Gecko/20100101 Firefox/110.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:110.0) Gecko/20100101 Firefox/110.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
]

async def fetch_text(url, session, retries=5, timeout=15):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Referer": "https://www.google.com/",
        "Accept-Language": "en-US,en;q=0.5",
    }
    
    for attempt in range(retries):
        try:
            response = await session.get(url, headers=headers)
            if response.status_code == 403:
                logging.warning(f"403 Forbidden for {url} (Attempt {attempt+1}/{retries}), retrying...")
                await asyncio.sleep(5 + random.random() * 10)
                continue  # 重新嘗試請求
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            return "\n".join(p.get_text(strip=True) for p in soup.find_all(['p', 'li', 'div']) if p.get_text(strip=True))
        except httpx.RequestError as e:
            logging.warning(f"Failed to fetch {url} (Attempt {attempt+1}/{retries}): {e}")
            await asyncio.sleep(5 + random.random() * 10)
    return ""

async def fetch_all():
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as session:
        tasks = []
        for vuln, sources in urls.items():
            for source, url in sources.items():
                tasks.append((vuln, source, fetch_text(url, session)))
        
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