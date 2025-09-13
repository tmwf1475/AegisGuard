import os

print("Start building RAG knowledge base")

# Execute each step
os.system("python scripts/fetch_data.py")
os.system("python scripts/preprocess_text.py")
os.system("python scripts/create_faiss.py")

print("RAG knowledge base is ready! You can use query_rag.py to test queries!")
