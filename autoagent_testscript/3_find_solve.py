from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_core.retrievers import BaseRetriever
import json
import datetime

# Set embedding model and LLM
EMBEDDING_MODEL = "llama3"
LLM_MODEL = "llama3"

# Load FAISS vector database
try:
    vectorstore = FAISS.load_local(
        "data/knowledge_base",
        OllamaEmbeddings(model=EMBEDDING_MODEL),
        allow_dangerous_deserialization=True
    )
    print("FAISS vector database loaded successfully!")
except Exception as e:
    raise RuntimeError(f"Failed to load FAISS: {e}")

# Set up LLM
llm = OllamaLLM(model=LLM_MODEL)

# Create a specific RAG prompt template
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

# Create document processing chain
document_chain = create_stuff_documents_chain(
    llm, 
    rag_prompt
)

# Set up retriever
retriever: BaseRetriever = vectorstore.as_retriever(
    search_kwargs={
        "k": 5,  # Retrieve the top 5 most relevant documents
        "filter": None  # Optional metadata filter
    }
)

# Create an advanced retrieval chain
retrieval_chain = create_retrieval_chain(
    retriever,  # Retriever
    document_chain,  # Document processing chain
)

# Load system environment information
with open("data/system_info.json", "r", encoding="utf-8") as f:
    system_info = json.load(f)

# **Construct query to detect vulnerabilities**
query_vuln = f"""
Windows Version: {system_info.get('os_version', 'Unknown')}
Installed Hotfixes: {system_info.get('hotfixes', 'None')}
Open Ports: {system_info.get('open_ports', 'Unknown')}
Running Processes: {system_info.get('running_processes', 'Unknown')}
Enabled Windows Features: {system_info.get('windows_features', 'Unknown')}
Registry Settings: {system_info.get('registry_settings', 'Unknown')}
Firewall Status: {system_info.get('firewall_status', 'Unknown')}
Please list all potential vulnerabilities that may affect this system and provide detailed information.
"""

# Invoke retrieval chain to obtain vulnerability information
retrieved_vuln = retrieval_chain.invoke({"input": query_vuln})
detected_vulnerabilities = retrieved_vuln.get("answer", "")

if not detected_vulnerabilities.strip():
    print("No known vulnerabilities detected. The system is likely secure!")
    exit()

# **Construct query to obtain remediation methods**
query_fix = f"""
Detected vulnerabilities:
{detected_vulnerabilities}

Please provide:
- Remediation methods (official patches, manual fixes)
- Whether a reboot is required
- Fix priority level (High/Medium/Low)
- If the vulnerability cannot be patched, are there any mitigation measures?
"""

retrieved_fixes = retrieval_chain.invoke({"input": query_fix})
fix_recommendations = retrieved_fixes.get("answer", "")

# **Generate report**
report = {
    "timestamp": str(datetime.datetime.now()),
    "system_info": system_info,
    "detected_vulnerabilities": detected_vulnerabilities,
    "fix_recommendations": fix_recommendations
}

# **Save report**
with open("data/vulnerability_report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

print("\nThe following vulnerabilities were detected:")
print(detected_vulnerabilities)
print("\nRecommended Fixes:")
print(fix_recommendations)
print("\nThe vulnerability report has been saved to data/vulnerability_report.json")

# **Query LLM to generate remediation script**
query_script = f"""
Based on the following vulnerability report, generate a patching script for Windows Server 2008:
{json.dumps(report, indent=4)}

Requirements:
1. First, check if the system has already installed the patch (to avoid redundant installations).
2. If updates need to be downloaded, use bitsadmin or Invoke-WebRequest.
3. Automatically install and disable SMBv1, patch RDP settings, and apply other security configurations.
4. Generate a complete PowerShell script.
"""

# **Invoke retrieval chain to generate remediation script**
patch_script_response = retrieval_chain.invoke({"input": query_script})
patch_script = patch_script_response.get("answer", "")

# **Save remediation script**
script_path = "fix_solution.ps1"
with open(script_path, "w", encoding="utf-8") as f:
    f.write(patch_script)

print("\nRemediation script generated successfully!\n")
print(patch_script)
print(f"\nThe remediation script has been saved to {script_path}")
