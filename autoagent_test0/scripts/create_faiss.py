from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings  
import json
import os

# Load text data
data_path = "data/ms17-010_chunks.json"
if not os.path.exists(data_path):
    raise FileNotFoundError(f"File {data_path} not found. Please run preprocess_text.py first.")

with open(data_path, "r", encoding="utf-8") as f:
    texts = json.load(f)

if not texts:
    raise ValueError("Loaded text data is empty. Please check if preprocess_text.py executed correctly.")

# Test if Ollama Embeddings are working
try:
    embeddings = OllamaEmbeddings(model="llama3")
    test_vector = embeddings.embed_query("Test input")
    print("Ollama Embeddings test successful!", test_vector[:5])  # Display first 5 values

    # Create FAISS vector store
    vectorstore = FAISS.from_texts(texts, embeddings)
    vectorstore.save_local("data/ms17-010_knowledge_base")
    print("FAISS vector database created successfully!")

except Exception as e:
    print(f"FAISS creation failed: {e}")
