import json
import os
import re
import logging
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from concurrent.futures import ThreadPoolExecutor
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings
import warnings


# 儲存路徑
DATA_PATHS = [
    "/home/st335/CTIAgent/autoagent_final/data/vulnerability_data_U1.json",
    "/home/st335/CTIAgent/autoagent_final/data/vulnerability_data_U2.json",
]

DATA_COMBINED_PATH = "/home/st335/CTIAgent/autoagent_final/data/vulnerability_data_Ubuntu.json"
CHUNKS_PATH = "/home/st335/CTIAgent/autoagent_final/data/vulnerability_chunks_Ubuntu.json"
VECTOR_DB_PATH = "/home/st335/CTIAgent/autoagent_final/data/base/vulnerability_knowledge_base_Ubuntu"

# 讀取並合併 JSON 檔案
combined_data = {}

for json_file in DATA_PATHS:
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data, dict):
            combined_data.update(data)  # 使用 update() 合併字典

# 儲存合併後的 JSON
with open(DATA_COMBINED_PATH, "w", encoding="utf-8") as f:
    json.dump(combined_data, f, indent=4, ensure_ascii=False)

print(f"Merged JSON data saved to: {DATA_COMBINED_PATH}")

## 建立資料夾
os.makedirs("data", exist_ok=True)

# 設定日誌
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", force=True)

# 載入資料
def load_data(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error loading JSON data: {e}")
        return {}

data = load_data(DATA_COMBINED_PATH)

# 清理與過濾
def clean_text(text):
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'[^\x00-\x7F]+', ' ', text)  # 移除非 ASCII 字元
    text = re.sub(r'[“”’]', "'", text)  # 正規化引號
    text = text.lower().strip()  # 統一小寫，提高檢索準確度
    return text

# 關鍵字篩選
INCLUDE_KEYWORDS = [
    r'\bCVE-\d{4}-\d{4,7}\b', r'vulnerability', r'security update', r'exploit',
    r'remote code execution', r'privilege escalation', r'memory corruption', r'buffer overflow'
]
EXCLUDE_KEYWORDS = [r'privacy policy', r'terms of use', r'legal disclaimer']

def is_relevant(text):
    return any(re.search(k, text, re.IGNORECASE) for k in INCLUDE_KEYWORDS) and \
           not any(re.search(k, text, re.IGNORECASE) for k in EXCLUDE_KEYWORDS)

# 清理並篩選文本
def filter_vulnerabilities(data):
    filtered_texts = []
    for vuln_name, sources in data.items():
        combined_text = "\n".join(sources.values())
        sentences = combined_text.split("\n")
        relevant_sentences = [clean_text(sentence) for sentence in sentences if is_relevant(sentence)]
        if relevant_sentences:
            filtered_texts.append("\n".join(relevant_sentences))
    return filtered_texts

filtered_texts = filter_vulnerabilities(data)

# 文本切割
splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=200)  # 增加 chunk overlap 提高上下文連貫性
split_texts = [chunk for text in filtered_texts for chunk in splitter.split_text(text)]

if not split_texts:
    logging.warning("No text was split into chunks. Something might be wrong in preprocessing.")
    raise ValueError("Processed text data is empty.")
else:
    logging.info(f"Processed {len(split_texts)} refined text segments!")

# 初始化 Ollama embeddings
embedding_model = OllamaEmbeddings(model="llama3")

batch_size = 200
num_batches = len(split_texts) // batch_size + (1 if len(split_texts) % batch_size else 0)

# 初始化 FAISS
vectorstore = None

for i in range(num_batches):
    batch = split_texts[i * batch_size : (i + 1) * batch_size]
    logging.info(f"Processing batch {i+1}/{num_batches}...")

    # 生成嵌入
    batch_embeddings = embedding_model.embed_documents(batch)
    batch_embeddings = [list(embedding) for embedding in batch_embeddings]  # 確保格式正確

    if vectorstore is None:
        vectorstore = FAISS.from_texts(batch, embedding=embedding_model)
    else:
        vectorstore.add_texts(batch, embedding=embedding_model)

vectorstore.save_local(VECTOR_DB_PATH)
logging.info("FAISS vector database saved successfully!")

# 儲存處理後的文本
logging.info("Saving split_texts to JSON...")
with open(CHUNKS_PATH, "w", encoding="utf-8") as f:
    json.dump(split_texts, f, indent=4, ensure_ascii=False)
logging.info("Data successfully saved!")