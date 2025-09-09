from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_core.retrievers import BaseRetriever
import json
from datetime import datetime
import os

# Set LLM and FAISS models
EMBEDDING_MODEL = "llama3"
LLM_MODEL = "deepseek-r1:14b"

# Define FAISS path
FAISS_PATH = "/home/st335/CTIAgent/autoagent_test2/data/base/vulnerability_knowledge_base"

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
    You are a cybersecurity expert specializing in Linux vulnerability assessment and remediation, 
    with a focus on Ubuntu-based systems. Your task is to analyze the provided system information, 
    identify potential vulnerabilities, and deliver a structured security assessment.

    Your response should include:
    - **Vulnerability Overview**: Explain identified risks clearly and concisely.
    - **Official Patching Methods**: Provide verified fixes from Ubuntu Security Advisories (USN) or CVE references.
    - **Security Hardening Recommendations**: Suggest additional best practices to mitigate risks beyond patching.
    - **Executable Commands**: List precise and safe shell commands that can be directly copied and executed.
    - **Prioritization**: Rank vulnerabilities by severity (Critical, High, Medium, Low) and recommend action urgency.

    **System Information:**
    {context}
    """),
    ("human", "{input}")
])


# Configure retrieval chain
document_chain = create_stuff_documents_chain(llm, rag_prompt)
retriever: BaseRetriever = vectorstore.as_retriever(search_kwargs={"k": 30})
retrieval_chain = create_retrieval_chain(retriever, document_chain)

# Load system environment data
with open("/home/st335/CTIAgent/autoagent_test2/data/system_info.json", "r", encoding="utf-8") as f:
    system_info = json.load(f)

# Construct vulnerability query
query_vuln = """
Ubuntu Version: {}
Kernel Version: {}
Architecture: {}
Installed Hotfixes: {}
Open Ports: {}
Running Processes: {}
Running Services: {}
Disk Partitions: {}
Firewall Status: {}

List all potential vulnerabilities affecting this system and provide detailed insights with step-by-step remediation guidance.
""".format(
    system_info.get('os_version', 'Unknown'),
    system_info.get('kernel_version', 'Unknown'),
    system_info.get('architecture', 'Unknown'),
    system_info.get('installed_hotfixes', 'None'),
    system_info.get('open_ports', 'Unknown'),
    system_info.get('running_processes', 'Unknown'),
    system_info.get('running_services', 'Unknown'),
    system_info.get('disk_partitions', 'Unknown'),
    system_info.get('firewall_status', 'Unknown')
)


# Retrieve vulnerability information
retrieved_vuln = retrieval_chain.invoke({"input": query_vuln})
detected_vulnerabilities = retrieved_vuln.get("answer", "")

if not detected_vulnerabilities.strip():
    print("No known vulnerabilities detected. The system appears secure.")
else:
    # Query for detailed remediation steps
    query_fix = f"""
    Detected vulnerabilities:
    {detected_vulnerabilities}
    
    Provide:
    1. Official patches and fixes (Kernel updates, APT updates, etc.) with exact commands.
    2. Whether a reboot is required and any potential downtime impact.
    3. Fix priority level (High/Medium/Low).
    4. Additional system hardening measures beyond patches.
    5. Detailed explanation of each vulnerability and its impact.
    6. Provide structured and categorized responses.
    7. Include verification steps to confirm patch application.
    8. Ensure rollback procedures are included in case of failure.
    9. Each vulnerability should be handled individually with clear steps.
    """
    
    retrieved_fixes = retrieval_chain.invoke({"input": query_fix})
    fix_recommendations = retrieved_fixes.get("answer", "")
    
    # Generate remediation report
    report = {
        "timestamp": str(datetime.datetime.now()),
        "system_info": system_info,
        "detected_vulnerabilities": detected_vulnerabilities,
        "fix_recommendations": fix_recommendations,
        "patch_verification": "Include verification steps to ensure patches are applied correctly."
    }
    
    # Save report
    report_path = "/home/st335/CTIAgent/autoagent_test2/data/vulnerability_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    
    print("\nDetected vulnerabilities:")
    print(detected_vulnerabilities)
    print("\nRecommended Fixes:")
    print(fix_recommendations)
    print(f"\nThe vulnerability report has been saved to {report_path}")
    
    # Generate fully executable Bash script with individual fixes for each vulnerability
    query_script = f"""
    Based on the following vulnerability report, generate a **fully functional and production-ready Bash script** to patch Ubuntu:
    {json.dumps(report, indent=4)}
    
    Requirements:
    - The script must be a **valid, well-structured Bash script (`.sh`)** that is directly executable on Ubuntu **without syntax errors**.
    - Each vulnerability should be handled **individually**, ensuring that:
    -   Execution and verification are completed **before proceeding to the next vulnerability**.
    -   If a patch is already applied, the script should **skip redundant updates** to avoid unnecessary system modifications.
    - Validate whether patches are already applied **before executing**:
    -   Use commands such as `dpkg -l`, `apt-cache policy`, `uname -r`, and `lsb_release -a` to check versions before installing updates.
    -   If the patch is missing, proceed with installation using **explicit package versions**.
    -   If a required package is missing, install it before attempting an update.
    - Use **explicit `apt-get install` or `dpkg` commands** with specific versions:
    -   Prefer `apt-get install --only-upgrade <package>` over `apt-get upgrade` to minimize unintended updates.
    -   Ensure that kernel updates are handled **carefully** to avoid unintended breaking changes.
    -   If a critical package update is required, verify the package’s digital signature before installation.
    - Ensure necessary services **restart correctly** after patching:
    -   Restart only the relevant services instead of rebooting the system whenever possible.
    -   Use `systemctl restart <service>` and verify service status with `systemctl is-active <service>`.
    -   If a service fails to restart, log the failure and attempt a rollback if necessary.
    - Disable insecure services like `avahi-daemon`, `rpcbind`, `cups`, and other potentially exploitable services **if they are enabled**.
    -   Ensure that disabling these services does not break essential system functionalities.
    - Implement **additional security measures**, including:
    -   Enabling and configuring **firewall rules (UFW or iptables)**.
    -   Applying **kernel hardening techniques** such as ASLR (`kernel.randomize_va_space = 2`), stack protection, and sysctl hardening.
    -   Restricting `su` access using `pam_wheel.so`.
    -   Enabling SSH security configurations (`PermitRootLogin no`, `PasswordAuthentication no`).
    -   Installing and configuring `Fail2Ban` to mitigate brute-force attacks.
    - Provide structured logging:
    -   Log all operations to `/var/log/vulnerability_patch.log`.
    -   Use `tee -a` or `logger` to maintain a structured record of actions.
    -   Each major step must be logged with timestamps and success/failure status.
    -   If an operation fails, log the error message and provide details on the failure.
    - Include **detailed comments** for each major step to improve maintainability and clarity.
    - Perform a **system-wide verification** at the end to:
    -   Confirm that all applied patches are correctly installed.
    -   Validate system integrity by checking package versions and service statuses.
    -   Ensure that disabled services remain deactivated.
    -   Check if additional vulnerabilities have emerged post-update.
    - Generate a **final remediation report**, summarizing:
    -   Detected vulnerabilities and affected system components.
    -   Actions taken, including patches applied and configurations changed.
    -   Any errors encountered during the patching process.
    -   Whether a **system reboot is required**, and provide a clear notification to the administrator.
    -   The report should be saved in **both human-readable (`.log`) and structured JSON (`.json`) formats** for easy integration with security monitoring tools.
    - Ensure the script:
    -   Uses `set -e` to exit immediately if a patch fails.
    -   Logs failures in `/var/log/vulnerability_patch.log` and provides **rollback** if necessary (e.g., re-enabling services if they were mistakenly disabled).
    -   Implements a **safe rollback mechanism** that restores the previous state if a patch disrupts critical system functionalities.
    -   Supports execution via **cron jobs or remote SSH automation** to facilitate scheduled security maintenance.
    """
    
    patch_script_response = retrieval_chain.invoke({"input": query_script})
    patch_script = patch_script_response.get("answer", "")
    
    # Save remediation script as an executable Bash script
    script_path = "/home/st335/CTIAgent/autoagent_test2/data/fix_solution.sh"
    with open(script_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\n")
        f.write("set -e\n")  # Exit on error
        f.write("set -o pipefail\n")  # Ensure piped commands return errors
        f.write("LOG_FILE='/home/st335/CTIAgent/autoagent_test2/data/vulnerability_patch.log'\n")
        f.write("exec > >(tee -a $LOG_FILE) 2>&1\n")
        f.write("echo '===== Ubuntu Auto Vulnerability Fix Script ====='\n")
        f.write("echo 'Execution Time: $(date)'\n")
        f.write("echo 'Logs stored at: $LOG_FILE'\n")
        f.write("if [[ $EUID -ne 0 ]]; then echo 'This script requires root privileges. Please run with sudo.'; exit 1; fi\n")
        f.write(patch_script)
    
    # Make the script executable
    import os
    os.chmod(script_path, 0o755)
    
    print("\nPatch script successfully generated and is ready for execution!\n")
    print(patch_script)
    print(f"\nThe remediation script has been saved to {script_path} and made executable.")


 