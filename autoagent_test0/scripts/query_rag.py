from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings

# Set the embedding model (ensure this model is available)
EMBEDDING_MODEL = "mistral"  # Can be changed to "llama2" (Use `ollama list` to check available models)

try:
    # Load FAISS vector store
    vectorstore = FAISS.load_local("data/ms17-010_knowledge_base", OllamaEmbeddings(model=EMBEDDING_MODEL))
    print("FAISS vector store loaded successfully!")

    # Define query
    query = "How to patch MS17-010 on Windows Server 2008?"
    retrieved_docs = vectorstore.similarity_search(query, k=3)

    # Display search results
    if retrieved_docs:
        print("\nSearch Results:")
        for i, doc in enumerate(retrieved_docs, 1):
            print(f"\n--- Relevant Content {i} ---\n{doc.page_content}\n")
    else:
        print("⚠️ No relevant content found. Try different keywords.")

except FileNotFoundError:
    print("FAISS vector store not found. Please run `create_faiss.py` to build the index first!")

except Exception as e:
    print(f"Query failed: {e}")
