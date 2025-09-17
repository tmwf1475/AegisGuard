from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_core.retrievers import BaseRetriever
import json
import datetime
import os

# Set LLM and FAISS models
EMBEDDING_MODEL = "llama3"
LLM_MODEL = "llama3"

# Define FAISS path
FAISS_PATH = "/home/st335/CTIAgent/autoagent_test1/data/base/vulnerability_knowledge_base"

# Load FAISS knowledge base
try:
    vectorstore = FAISS.load_local(
        FAISS_PATH,
        OllamaEmbeddings(model=EMBEDDING_MODEL),
        allow_dangerous_deserialization=True
    )
    print("FAISS vector database loaded successfully!")
except Exception as e:
    raise RuntimeError(f"Failed to load FAISS: {e}")

# Initialize LLM
llm = OllamaLLM(model=LLM_MODEL)

# Define RAG prompt
rag_prompt = ChatPromptTemplate.from_messages([
    ("system", """
    You are a cybersecurity expert specializing in Linux (Ubuntu 16.04) vulnerability remediation.
    Analyze the system information below, identify potential vulnerabilities, and provide detailed mitigation strategies.
    Your response should include:
    - Clear and detailed vulnerability explanations
    - Precise official patching methods
    - Additional security hardening recommendations
    - Commands that are copy-paste ready for execution
    
    **System Information**
    {context}
    """),
    ("human", "{input}")
])

# Configure retrieval chain
document_chain = create_stuff_documents_chain(llm, rag_prompt)
retriever: BaseRetriever = vectorstore.as_retriever(search_kwargs={"k": 10})
retrieval_chain = create_retrieval_chain(retriever, document_chain)

# Load system environment data
with open("/home/st335/CTIAgent/autoagent_test1/data/system_info.json", "r", encoding="utf-8") as f:
    system_info = json.load(f)

# Construct vulnerability query
query_vuln = f"""
Ubuntu Version: {system_info.get('os_version', 'Unknown')}
Installed Hotfixes: {system_info.get('installed_hotfixes', 'None')}
Open Ports: {system_info.get('open_ports', 'Unknown')}
Running Processes: {system_info.get('running_processes', 'Unknown')}
Enabled Services: {system_info.get('enabled_services', 'Unknown')}

List all potential vulnerabilities affecting this system and provide detailed insights with step-by-step remediation guidance.
"""

# Retrieve vulnerability information
retrieved_vuln = retrieval_chain.invoke({"input": query_vuln})
detected_vulnerabilities = retrieved_vuln.get("answer", "")

if not detected_vulnerabilities.strip():
    print("No known vulnerabilities detected. The system appears secure.")
else:
    # Query for remediation steps
    query_fix = f"""
    Detected vulnerabilities:
    {detected_vulnerabilities}
    
    Provide:
    1. Official patches and fixes (Kernel updates, APT updates, etc.) with exact commands.
    2. Whether a reboot is required and any potential downtime impact.
    3. Fix priority level (High/Medium/Low).
    4. Additional system hardening measures beyond patches.
    5. Provide structured and categorized responses.
    """
    
    retrieved_fixes = retrieval_chain.invoke({"input": query_fix})
    fix_recommendations = retrieved_fixes.get("answer", "")
    
    # Generate remediation report
    report = {
        "timestamp": str(datetime.datetime.now()),
        "system_info": system_info,
        "detected_vulnerabilities": detected_vulnerabilities,
        "fix_recommendations": fix_recommendations
    }
    
    # Save report
    report_path = "/home/st335/CTIAgent/autoagent_test1/data/vulnerability_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    
    print("\nDetected vulnerabilities:")
    print(detected_vulnerabilities)
    print("\nRecommended Fixes:")
    print(fix_recommendations)
    print(f"\nThe vulnerability report has been saved to {report_path}")
    
    # Generate remediation script
    query_script = f"""
    Based on the following vulnerability report, generate a **complete and production-ready Bash script** to patch Ubuntu 16.04:
    {json.dumps(report, indent=4)}
    
    Requirements:
    - Validate whether patches are already applied before executing.
    - Use explicit `apt-get install` or `dpkg` with specific versions.
    - Ensure necessary services restart correctly after patching.
    - Disable insecure services like `avahi-daemon` if applicable.
    - Implement additional security measures such as firewall rules.
    - Provide structured logging output in the script.
    """
    
    patch_script_response = retrieval_chain.invoke({"input": query_script})
    patch_script = patch_script_response.get("answer", "")
    
    # Save remediation script
    script_path = "/home/st335/CTIAgent/autoagent_test1/data/fix_solution.sh"
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(patch_script)
    
    print("\nPatch script successfully generated!\n")
    print(patch_script)
    print(f"\nThe remediation script has been saved to {script_path}")
