from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_core.retrievers import BaseRetriever
import os

# 設定嵌入模型和 LLM
EMBEDDING_MODEL = "llama3"
LLM_MODEL = "llama3"

# 加載 FAISS 向量資料庫
try:
    vectorstore = FAISS.load_local(
        "data/ms17-010_knowledge_base",
        OllamaEmbeddings(model=EMBEDDING_MODEL),
        allow_dangerous_deserialization=True
    )
    print("✅ FAISS 向量資料庫加載成功！")
except Exception as e:
    raise RuntimeError(f"❌ Failed to load FAISS: {e}")

# 設定 LLM
llm = OllamaLLM(model=LLM_MODEL)

# 創建更具體的 RAG 提示模板
rag_prompt = ChatPromptTemplate.from_messages([
    ("system", """
    You are a cybersecurity expert specializing in Windows vulnerability remediation. 
    Use the following context to generate a precise and secure PowerShell script. 
    If the context does not provide sufficient information, clearly state what additional details are needed.

    Context:
    {context}
    """),
    ("human", "{input}")
])

# 創建文檔處理鏈
document_chain = create_stuff_documents_chain(
    llm, 
    rag_prompt
)

# 設置檢索器
retriever: BaseRetriever = vectorstore.as_retriever(
    search_kwargs={
        "k": 5,  # 檢索最相關的5個文檔
        "filter": None  # 可以添加元數據過濾器
    }
)

# 創建更高級的檢索鏈
retrieval_chain = create_retrieval_chain(
    retriever,  # 檢索器
    document_chain,  # 文檔處理鏈
)

# 查詢範例
query = """
Generate a PowerShell script to patch the MS17-010 vulnerability on Windows Server 2008.
The script should:
1. Check if the system is vulnerable.
2. Download and install the patch.
3. Restart the system if necessary.
Ensure it follows best security practices and logs all actions.
"""

# 調用檢索鏈
try:
    response = retrieval_chain.invoke({
        "input": query
    })

    # 提取和處理響應
    script_content = response.get('answer', '')
    
    if not script_content or len(script_content.strip()) < 50:
        raise ValueError("生成的腳本內容不足")

    # 保存腳本
    script_path = "ms17-010_fix.ps1"
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_content)

    print("\n🔹 修補腳本生成成功！\n")
    print(script_content)
    print(f"\n✅ 修補腳本已儲存至 {script_path}")

except Exception as e:
    print(f"❌ 腳本生成失敗：{e}")
