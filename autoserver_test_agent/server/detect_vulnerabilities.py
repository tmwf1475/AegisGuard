import time
import statistics
import json
import os
from datetime import datetime
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.documents import Document
from langchain_core.runnables import RunnableMap
from langchain.text_splitter import RecursiveCharacterTextSplitter

# === Config ===
EMBEDDING_MODEL = "llama3"
LLM_MODEL = "mistral:latest"
FAISS_PATH = "/home/st335/CTIAgent/advagent/data/base/vulnerability_knowledge_base_Ubuntu"
SYSTEM_SUMMARY_PATH = "/home/st335/CTIAgent/advagent/outputs/system_summary.json"
OUTPUT_PATH = "/home/st335/CTIAgent/advagent/outputs/vulnerability_list5.json"

# === Start overall timing ===
overall_start = time.time()
per_query_timings = []

# === Load Vector Store ===
vectorstore = FAISS.load_local(
    FAISS_PATH,
    OllamaEmbeddings(model=EMBEDDING_MODEL),
    allow_dangerous_deserialization=True
)

# === Load System Summary ===
with open(SYSTEM_SUMMARY_PATH, "r", encoding="utf-8") as f:
    loaded_info = json.load(f)
system_info = loaded_info[0] if isinstance(loaded_info, list) else loaded_info

# === Extract MCP-Aware Fields ===
os_version = system_info.get("os_version") or system_info.get("os")
running_services = [s["name"] for s in system_info.get("running_services", []) if s.get("name")]
installed_package_lines = [pkg["name"] for pkg in system_info.get("installed_packages", []) if pkg.get("name") and pkg["name"].startswith("ii")]

# === Semantic Queries (batched) ===
multi_queries = [f"The system is running Ubuntu {os_version}. Analyze it for privilege escalation (PE), remote code execution (RCE), or security bypass vulnerabilities."]

# Batch services
service_batches = [running_services[i:i+10] for i in range(0, len(running_services), 10)]
for batch in service_batches:
    joined = ", ".join(batch)
    multi_queries.append(f"The following services are running on Ubuntu {os_version}: {joined}. Are there known PE, RCE, or Bypass vulnerabilities among them?")

# Batch packages
package_batches = [installed_package_lines[i:i+10] for i in range(0, len(installed_package_lines), 10)]
for batch in package_batches:
    joined = ", ".join(batch)
    multi_queries.append(f"The following packages are installed on Ubuntu {os_version}: {joined}. Check for any known vulnerabilities or CVEs.")

# === Chunked Query from Raw MCP JSON ===
splitter = RecursiveCharacterTextSplitter(chunk_size=1024, chunk_overlap=100)
chunk_queries = [
    f"MCP SystemContext fragment:\n{chunk}\nIdentify known CVEs, PE, RCE, or Bypass vulnerabilities."
    for chunk in splitter.split_text(json.dumps(system_info, indent=2))
]

# === Remove duplicate queries ===
all_queries = list(set(multi_queries + chunk_queries))

# === Setup LLM + Retrieval Chain (reduced k for speed) ===
llm = OllamaLLM(model=LLM_MODEL)
rag_prompt = ChatPromptTemplate.from_messages([
    ("system", """
You are a cybersecurity analyst. Your job is to identify real exploitable vulnerabilities from a Linux system context.
Focus only on Privilege Escalation, Remote Code Execution, or Security Bypass.
List known CVEs, Metasploit modules, or public exploits when applicable.

Format:
## Identified Vulnerabilities
- [summary or CVE or exploit]
- ...
    """),
    ("human", "{context}")
])
document_chain = create_stuff_documents_chain(llm, rag_prompt, document_variable_name="context")
retriever = vectorstore.as_retriever(search_kwargs={"k": 10})
retrieval_chain = RunnableMap({
    "context": lambda x: [Document(page_content=x["context"])],
    "context_documents": lambda x: retriever.invoke(x["context"])
}).pipe(document_chain)

# === Run Queries and Time Each ===
all_results = []
for query in all_queries:
    start = time.time()
    result = retrieval_chain.invoke({"context": query})
    per_query_timings.append(time.time() - start)

    if isinstance(result, dict):
        answer = result.get("answer", "")
    elif isinstance(result, str):
        answer = result
    else:
        continue
    all_results.extend([line.strip()[2:] for line in answer.strip().split("\n") if line.strip().startswith("- ")])

# === Save Result ===
output = {
    "mcp_type": "VulnerabilityDetection",
    "generated_time": str(datetime.now()),
    "target_system": {
        "os_version": os_version,
        "hostname": system_info.get("hostname"),
        "source": system_info.get("source")
    },
    "vulnerability_findings": sorted(set(all_results)),
    "detection_runtime_summary": {
        "total_queries": len(all_queries),
        "average_query_time_sec": round(statistics.mean(per_query_timings), 2),
        "total_runtime_sec": round(time.time() - overall_start, 2)
    }
}

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)

print(f"Vulnerability detection (MCP-compatible) completed: {OUTPUT_PATH}")
