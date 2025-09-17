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
FAISS_PATH = "/home/st335/CTIAgent/autoagent_test3/data/base/vulnerability_knowledge_base"

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
    particularly for Ubuntu-based systems. Your role is to analyze system configurations, 
    identify known and potential vulnerabilities, and generate a structured security report.

    Your response **must strictly follow** this structured format:

    ## **1. Identified Vulnerabilities**
    - List all security vulnerabilities affecting the system.
    - Identify **potential hidden vulnerabilities** due to misconfigurations, outdated dependencies, or unpatched software.
    - Provide CVE references where applicable.

    ## **2. Official Patching Methods**
    - Provide **official patches** from **Ubuntu Security Advisories (USN)**, **CVE reports**, or **trusted sources**.
    - Specify **exact update commands**, ensuring compatibility and minimal disruption.
    - If multiple patching methods exist, compare their advantages and risks.

    ## **3. Security Hardening Recommendations**
    - Suggest additional security best practices **beyond patching**, such as:
      - Kernel security hardening (e.g., ASLR, `sysctl` policies, SELinux, AppArmor).
      - Disabling unnecessary services.
      - Enhancing firewall configurations and SSH security.
      - System-wide integrity monitoring (e.g., `aide` or `tripwire`).

    ## **4. Risks & Side Effects of Fixes**
    - Describe **potential security risks or operational disruptions** associated with applying patches.
    - Highlight any **dependencies or system components that may be affected**.
    - Provide **rollback strategies** in case an update introduces issues.

    ## **5. Executable Commands & Automation**
    - Provide **only valid Bash commands** required for mitigation.
    - Do **not** include explanations, reasoning statements, or additional descriptions.
    - Ensure that:
      - Commands are precise and tested.
      - Updates avoid unintended package upgrades.
      - Verification steps are included:
        - `dpkg -l` (package installation verification)
        - `uname -r` (kernel version check)
        - `systemctl status` (service status verification)
    
    ## **6. Error Handling & Recovery**
    - Identify common failure points and provide contingency solutions.
    - If a patch fails, provide:
      - Alternative installation methods.
      - Fallback strategies.
      - Step-by-step rollback commands for safe reversion.

    ## **7. Impact Prioritization & Execution Order**
    - **Rank vulnerabilities by severity** (`Critical`, `High`, `Medium`, `Low`).
    - Recommend the **optimal sequence for applying patches** to avoid dependency conflicts.
    - Prioritize kernel and privilege escalation vulnerabilities first.
    - Group patches that do not require reboots separately to reduce downtime.
    
    ## **8. Final Validation & Reporting**
    - Ensure that all patches are correctly applied and that **system integrity remains intact**.
    - Suggest **post-patching verification steps** (e.g., checking package versions, verifying service status).
    - Generate a **structured cybersecurity report**, including:
      - Summary of vulnerabilities patched.
      - Security improvements made.
      - Additional hardening recommendations.
      - Risk assessment before and after patching.

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
with open("/home/st335/CTIAgent/autoagent_test3/data/system_info.json", "r", encoding="utf-8") as f:
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

    Your task is to generate a **structured, executable vulnerability remediation plan** that ensures an effective fix while minimizing risks and disruptions.

    ## **1. Vulnerability Analysis**
    For each identified vulnerability, provide:
    - **Detailed description** including root cause, affected components, and security impact.
    - **Potential hidden vulnerabilities** from outdated dependencies, misconfigurations, or weak policies.
    - **Impact assessment** covering:
    - Data exposure risks
    - Privilege escalation
    - Service disruptions
    - Remote exploitation possibilities

    ## **2. Official Patching & Mitigation**
    For each vulnerability, provide:
    - **The official patch/update** from Ubuntu Security Advisories (USN), CVE references, or security bulletins.
    - **Exact commands** for applying the patch, ensuring:
    - The correct package version is installed.
    - Dependency conflicts are resolved.
    - Kernel updates are handled safely (if applicable).
    - Updates avoid unintended system modifications.
    - **Verification steps** post-installation to confirm patch success.

    ## **3. Risk Assessment & Contingency Planning**
    - **Analyze system impact** before, during, and after patching:
    - Will any critical services stop or restart?
    - Is a system reboot required? What are the implications?
    - Are there known package dependency conflicts?
    - **Provide contingency plans** for failure scenarios:
    - Alternative patching methods if the primary method fails.
    - Steps to revert changes if instability occurs.
    - Emergency rollback procedures to restore system functionality.

    ## **4. Error Handling & Rollback Strategy**
    - **Pre-execution checks**:
    - Verify disk space (`df -h`) before installation.
    - Detect APT lock issues (`fuser /var/lib/dpkg/lock`).
    - Ensure internet connectivity (`ping -c 1 security.ubuntu.com`).
    - **Log monitoring for failures**:
    - Relevant log files (`/var/log/syslog`, `/var/log/apt/history.log`).
    - Expected error messages and their meanings.
    - Recommended troubleshooting steps.
    - **Rollback mechanism**:
    - Commands to undo patch changes (`apt-cache policy`, `dpkg --get-selections`).
    - Methods to restore previous package versions.
    - Steps to recover affected services and validate system integrity.

    ## **5. Post-Patch Validation & System Verification**
    After applying the patch, ensure:
    - The vulnerability is fully mitigated.
    - No unintended regressions or conflicts arise.
    - Validation checks:
    - Installed package versions (`dpkg -l`, `apt-cache policy`).
    - Kernel version verification (`uname -r`, `lsb_release -a`).
    - Service status confirmation (`systemctl is-active <service>`).
    - Additional debugging recommendations if issues persist.

    ## **6. Security Hardening & Preventive Measures**
    Beyond applying patches, enhance system security by:
    - **Kernel hardening** (`sysctl` policies, SELinux/AppArmor).
    - **Service restrictions** (disabling unused services, enhancing firewall policies).
    - **Advanced monitoring/logging** (intrusion detection systems, real-time auditing).

    ## **7. Individual Vulnerability Handling**
    - **Address each vulnerability separately** with a clear step-by-step remediation process.
    - **Avoid combining multiple patches into a single execution**, reducing risk and simplifying debugging.

    ## **8. Optimized Patch Execution Order**
    - Prioritize fixes **strategically** to minimize downtime.
    - Address patches by severity (`Critical`, `High`, `Medium`, `Low`).
    - Resolve package dependencies in the correct sequence to prevent conflicts.
    - Group non-reboot patches together to improve efficiency.

    ### **Output Format**
    - **Only provide executable commands**; avoid additional explanation or reasoning.
    - **Include risk assessment for each step**.
    - **Specify rollback options explicitly** for each patch.

    Follow these guidelines strictly to ensure a reliable and seamless vulnerability remediation process.
    """
    
    retrieved_fixes = retrieval_chain.invoke({"input": query_fix})
    fix_recommendations = retrieved_fixes.get("answer", "")
    
    # Generate structured remediation report
report = {
    "report_metadata": {
        "generated_timestamp": str(datetime.now()),
        "report_version": "1.0",
        "source": "Automated Vulnerability Assessment System"
    },
    "system_info": {
        "os_version": system_info.get("os_version", "Unknown"),
        "kernel_version": system_info.get("kernel_version", "Unknown"),
        "architecture": system_info.get("architecture", "Unknown"),
        "installed_hotfixes": system_info.get("installed_hotfixes", []),
        "open_ports": system_info.get("open_ports", []),
        "running_processes": system_info.get("running_processes", []),
        "running_services": system_info.get("running_services", []),
        "disk_partitions": system_info.get("disk_partitions", []),
        "firewall_status": system_info.get("firewall_status", "Unknown")
    },
    "vulnerabilities": []
}

# Parse vulnerabilities and recommendations into structured format
for vuln in detected_vulnerabilities.split("\n\n"):
    vuln_entry = {
        "description": vuln.strip(),
        "severity": "Unknown",  # Placeholder for severity ranking (Critical, High, Medium, Low)
        "cve_reference": "N/A",  # Placeholder for CVE reference if available
        "patch_recommendations": [],
        "risk_assessment": {
            "potential_impact": "N/A",
            "service_disruptions": "N/A",
            "reboot_required": False,
            "dependency_conflicts": "N/A"
        },
        "rollback_strategy": "N/A"
    }

    # Extract corresponding fix recommendations
    for fix in fix_recommendations.split("\n\n"):
        if vuln in fix:
            vuln_entry["patch_recommendations"].append({
                "fix_details": fix.strip(),
                "verification_steps": "Ensure the patch is correctly applied using appropriate commands.",
                "rollback_commands": "Provide commands for rolling back in case of failure."
            })

    report["vulnerabilities"].append(vuln_entry)

# Save report as JSON
report_path = "/home/st335/CTIAgent/autoagent_test3/data/vulnerability_report.json"
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)
    
    # Generate fully executable Bash script with individual fixes for each vulnerability
    query_script = f"""
    Generate a **fully functional, production-ready Bash script** for patching vulnerabilities based on the following vulnerability report:
    {json.dumps(report, indent=4)}

    ## **Requirements**
    - The script must be a **valid, well-structured Bash script (`.sh`)** that is directly executable on Ubuntu **without syntax errors**.
    - Each vulnerability should be handled **individually**, ensuring:
    - If a fix fails, an alternative method is attempted.
    - Errors are logged instead of stopping the script.
    - The script should always continue executing even if some patches fail.
    - If a failure occurs, send a real-time alert to the administrator via `logger` or a remote notification system.
    - If a vulnerability is **already patched**, the script should **skip redundant updates** to avoid unnecessary system modifications.
    - The script must validate whether patches are already applied **before execution**, using commands such as:
    - `dpkg -l`
    - `apt-cache policy`
    - `uname -r`
    - `lsb_release -a`
    - If a required package is missing, install it before attempting an update.
    - Implement a **watchdog mechanism** that detects if a critical failure occurs and attempts a rollback automatically.
    - Perform **pre-execution environment checks** to detect:
    - Low disk space (`df -h` check before updating packages).
    - APT lock (`fuser /var/lib/dpkg/lock` check before running `apt-get`).
    - Internet connectivity (`ping -c 1 security.ubuntu.com`).

    ## **Patch Execution Order**
    - **Sort vulnerabilities by severity (Critical > High > Medium > Low)**.
    - Ensure dependencies are resolved before applying patches.
    - Prioritize kernel and privilege escalation vulnerabilities.
    - Where possible, group fixes that do not require reboots together.
    - Minimize system downtime by scheduling patches efficiently.

    ## **Error Handling & Fallback Strategy**
    - If a patch fails:
    - Log the failure and attempt an alternative patching method.
    - If no alternative is available, **gracefully exit with a logged error** rather than halting execution.
    - Notify the administrator immediately and suggest manual intervention if needed.
    - If patching causes a system failure:
    - Attempt to roll back using `dpkg --get-selections` and `apt-cache policy`.
    - Provide clear rollback instructions in logs.
    - Ensure essential services restart after rollback.
    - If critical services fail to restart after patching:
    - Use `systemctl restart <service>` and verify service status with `systemctl is-active <service>`.
    - If a service remains inactive, attempt an alternative restart method or log the issue for manual intervention.
    - Provide a recovery plan for manual fixes if needed.

    ## **Security & Optimization Measures**
    - **Prevent unintended package upgrades** by using:
    - `apt-get install --only-upgrade <package>`
    - Ensure necessary services **restart correctly** after patching:
    - If a service fails to restart, log the failure and attempt rollback.
    - Disable insecure services like:
    - `avahi-daemon`, `rpcbind`, `cups`, etc.
    - Ensure that disabling these services does not break essential functionalities.
    - Implement **real-time security monitoring**:
    - Monitor logs continuously for any anomalies.
    - Send alerts if a system compromise is detected during patching.
    - **Reduce unnecessary reboots**:
    - Apply kernel patches last to prevent multiple system restarts.

    ## **Logging & Validation**
    - Log all operations to `/var/log/vulnerability_patch.log`:
    - Use `tee -a` or `logger` to maintain a structured record of actions.
    - Each major step must be logged with timestamps and success/failure status.
    - If an operation fails:
        - Log the error message and provide rollback details.
        - Store logs in a separate error report file for further investigation.
    - **Final validation steps**:
    - Confirm that all applied patches are correctly installed.
    - Validate system integrity by checking package versions and service statuses.
    - Ensure that disabled services remain deactivated.
    - Check if additional vulnerabilities have emerged post-update.
    - Provide a final system status summary to the administrator.

    ## **Post-Patch Security Hardening**
    - Enable and configure **firewall rules (UFW or iptables)**.
    - Apply **kernel hardening techniques** such as ASLR (`kernel.randomize_va_space = 2`).
    - Restrict `su` access using `pam_wheel.so`.
    - Enable SSH security configurations (`PermitRootLogin no`, `PasswordAuthentication no`).
    - Install and configure `Fail2Ban` to mitigate brute-force attacks.
    - Perform system-wide security scans after patching.

    ## **Final Remediation Report**
    - Generate a **structured cybersecurity report** in both human-readable (`.log`) and structured JSON (`.json`) formats, including:
    - **Detailed patching steps performed** with timestamps.
    - **Errors encountered** and how they were handled.
    - **Fallback methods used** in case of failures.
    - **Post-patch security enhancements** implemented.
    - **Overall cybersecurity risk assessment**, summarizing:
        - The system security posture before and after patching.
        - Recommendations for further hardening.
        - Additional preventive measures to avoid similar vulnerabilities in the future.
    - **Final report should be stored at `/var/log/vulnerability_patch_summary.json` and `/var/log/vulnerability_patch_summary.log`**.
    """
    
    # Retrieve generated patch script from LLM
patch_script_response = retrieval_chain.invoke({"input": query_script})
patch_script = patch_script_response.get("answer", "")

# Define script path
script_path = "/home/st335/CTIAgent/autoagent_test3/data/fix_solution.sh"

# Create and write the script
with open(script_path, "w", encoding="utf-8") as f:
    f.write("#!/bin/bash\n\n")
    f.write("# ==========================\n")
    f.write("# Ubuntu Auto Vulnerability Fix Script\n")
    f.write("# Auto-generated remediation script\n")
    f.write("# Execution Timestamp: $(date)\n")
    f.write("# ==========================\n\n")

    # Script settings
    f.write("set -e  # Exit immediately if a command fails\n")
    f.write("set -o pipefail  # Fail if any command in a pipeline fails\n\n")

    # Define log file
    f.write("LOG_FILE='/home/st335/CTIAgent/autoagent_test3/data/vulnerability_patch.log'\n")
    f.write("exec > >(tee -a $LOG_FILE) 2>&1  # Log all output\n\n")

    # Root check
    f.write("if [[ $EUID -ne 0 ]]; then\n")
    f.write("  echo '[ERROR] This script requires root privileges. Please run with sudo.' | tee -a $LOG_FILE\n")
    f.write("  exit 1\n")
    f.write("fi\n\n")

    # Pre-execution system checks
    f.write("echo '===== Starting Ubuntu Auto Vulnerability Fix =====' | tee -a $LOG_FILE\n")
    f.write("echo 'Logs stored at: $LOG_FILE'\n")
    f.write("echo 'Checking system requirements...'\n\n")

    # Check internet connectivity
    f.write("if ! ping -c 1 security.ubuntu.com &> /dev/null; then\n")
    f.write("  echo '[ERROR] No internet connection. Ensure the system can reach security.ubuntu.com' | tee -a $LOG_FILE\n")
    f.write("  exit 1\n")
    f.write("fi\n\n")

    # Check for APT locks
    f.write("if sudo fuser /var/lib/dpkg/lock &> /dev/null; then\n")
    f.write("  echo '[ERROR] APT is locked. Another process may be running updates. Retry later.' | tee -a $LOG_FILE\n")
    f.write("  exit 1\n")
    f.write("fi\n\n")

    # Check for disk space
    f.write("FREE_SPACE=$(df -h / | awk 'NR==2 {print $4}' | sed 's/G//')\n")
    f.write("if [[ $FREE_SPACE -lt 2 ]]; then\n")
    f.write("  echo '[ERROR] Insufficient disk space (<2GB free). Clean up before proceeding.' | tee -a $LOG_FILE\n")
    f.write("  exit 1\n")
    f.write("fi\n\n")

    # Check package manager is available
    f.write("if ! command -v apt-get &> /dev/null; then\n")
    f.write("  echo '[ERROR] apt-get not found. Ensure APT package manager is available.' | tee -a $LOG_FILE\n")
    f.write("  exit 1\n")
    f.write("fi\n\n")

    # Insert patch commands directly from retrieval (only raw bash commands)
    f.write("echo '===== Applying Security Patches =====' | tee -a $LOG_FILE\n")
    
    # Ensure each command execution is logged
    for line in patch_script.split("\n"):
        if line.strip():
            f.write(f"echo 'Executing: {line.strip()}' | tee -a $LOG_FILE\n")
            f.write(line.strip() + "\n")

    # Post-execution verification steps
    f.write("\n# ===== Post-Patch Verification =====\n")
    f.write("echo 'Checking updated package versions...' | tee -a $LOG_FILE\n")
    f.write("dpkg -l | grep -E 'openssl|linux-image|apache2' || echo 'No critical updates detected.' | tee -a $LOG_FILE\n\n")

    # Reboot prompt (if required)
    f.write("if grep -q 'linux-image' $LOG_FILE; then\n")
    f.write("  echo '[INFO] Kernel update detected. A reboot is recommended.' | tee -a $LOG_FILE\n")
    f.write("  read -p 'Reboot now? (y/n): ' REBOOT_ANSWER\n")
    f.write("  if [[ $REBOOT_ANSWER == 'y' || $REBOOT_ANSWER == 'Y' ]]; then\n")
    f.write("    echo 'Rebooting system...' | tee -a $LOG_FILE\n")
    f.write("    reboot\n")
    f.write("  else\n")
    f.write("    echo 'Reboot skipped. Ensure you restart the system later if required.' | tee -a $LOG_FILE\n")
    f.write("  fi\n")
    f.write("fi\n\n")

# Make script executable
os.chmod(script_path, 0o755)

# Print completion message
print("\nPatch script successfully generated and ready for execution!\n")
print(f"he remediation script has been saved to: {script_path}")
print("All logs will be stored in: /home/st335/CTIAgent/autoagent_test3/data/vulnerability_patch.log")
