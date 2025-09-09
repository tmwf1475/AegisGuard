import json
import re
from datetime import datetime
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from typing import List, Dict, Optional, Union, Tuple
from pydantic import BaseModel, Field
from collections import Counter
from langchain_ollama import OllamaLLM

# === Config ===
INPUT_PATH = "/home/st335/CTIAgent/advagent/outputs/vulnerability_list.json"
OUTPUT_PATH = "/home/st335/CTIAgent/advagent/outputs/vulnerability_classified.json"
LLM_MODEL = "llama3"

# === MCP Models ===
class DetectedVulnerability(BaseModel):
    mcp_type: str = Field(default="DetectedVulnerability")
    description: str
    cve_reference: Optional[str] = None
    risk_level_code: str
    risk_level: str
    classified_time: str
    repair_suggestion: str
    automation_policy: Optional[str] = None
    source: Optional[str] = "LLM"
    classification_reason: Optional[str] = None
    cvss_score: Optional[Union[str, float]] = None
    cvss_vector: Optional[str] = None
    exploitability: Optional[str] = None
    reference_links: Optional[List[str]] = []

class VulnerabilityRiskClassification(BaseModel):
    mcp_type: str = Field(default="VulnerabilityRiskClassification")
    source: str
    generated_time: str
    target_system: Dict[str, str]
    vulnerability_risks: List[DetectedVulnerability]
    summary_statistics: Optional[Dict[str, int]] = None
    classification_strategy: Optional[str] = None

# === Load Input ===
with open(INPUT_PATH, "r", encoding="utf-8") as f:
    detected_data = json.load(f)

findings = detected_data.get("vulnerability_findings", [])
target_system = detected_data.get("target_system", {})

# === LLM Setup ===
llm = OllamaLLM(model=LLM_MODEL)

AUTOMATION_POLICIES = {
    "L0": "Log only. No remediation actions. Used for analysis or model training.",
    "L1": "Auto-patch with simple configuration changes. No validation or rollback required.",
    "L2": "Test in sandbox before deployment. Moderate system risk.",
    "L3": "LLM generates mitigation options. Tested in sandbox with impact prediction.",
    "L4": "Critical. Immediate forced patching with snapshot + rollback threshold."
}

PROMPT_TEMPLATE = (
    "You are a cybersecurity analyst. Analyze the following vulnerability description.\n"
    "Classify the severity of this vulnerability into one of: Critical, High, Medium, Low, Info.\n\n"
    "Description:\n{desc}\n\n"
    "Answer format:\nRisk Level: [YourAnswerHere]"
)

# === CVE Extractor ===
def extract_cve(text):
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0) if match else None

# === Risk Normalization with explanation ===
def normalize_risk_level(initial_level: str, desc: str) -> Tuple[str, str]:
    desc = desc.lower()

    # L4 - Critical threats: RCE + exploit or unauthenticated + high CVSS
    if ("remote code execution" in desc or "rce" in desc) and \
       any(x in desc for x in ["exploit exists", "public exploit", "unauthenticated", "cvss 9", "cvss 10"]):
        return "L4", "Detected RCE with known exploit and/or unauthenticated access or high CVSS score"

    # L3 - High risk: standalone RCE, sandbox, bypass, etc.
    if any(x in desc for x in [
        "remote code execution", "rce", "sandbox escape", "kernel crash", "heap corruption",
        "auth bypass", "csrf bypass", "unauthenticated access", "root access", "code injection"
    ]):
        return "L3", "Detected standalone RCE or critical system compromise indicators"

    # L2 - Medium risk: standard exploit classes
    if any(x in desc for x in [
        "privilege escalation", "escalate privileges", "sql injection", "command injection",
        "denial of service", "arbitrary write", "path traversal", "directory traversal",
        "stack overflow", "buffer overflow", "memory corruption"
    ]):
        return "L2", "Detected standard vulnerability type with exploit potential"

    # L1 - Low risk: information leaks, misconfigurations, weak defaults
    if any(x in desc for x in [
        "information disclosure", "info leak", "leakage", "misconfiguration", "exposure",
        "debug mode", "admin panel", "stack trace", "insecure cookie", "clickjacking",
        "verbose logging", "default credentials", "open directory", "security header missing"
    ]):
        return "L1", "Detected weak configuration or information leakage pattern"

    return "L0", "No identifiable threat pattern detected"

# === LLM Classifier ===
def classify_with_llm(description):
    prompt = PROMPT_TEMPLATE.format(desc=description)
    try:
        response = llm.invoke(prompt)
        match = re.search(r"Risk Level:\s*(Critical|High|Medium|Low|Info)", response, re.IGNORECASE)
        if match:
            return match.group(1).capitalize()
    except Exception as e:
        print(f"[!] LLM classification failed: {e}")
    return "Info"

# === Analyze with reason ===
def analyze_vulnerability(desc):
    cve = extract_cve(desc)
    if not cve:
        return None
    initial_level = classify_with_llm(desc)
    norm_level_code, reason = normalize_risk_level(initial_level, desc)
    return DetectedVulnerability(
        description=desc,
        cve_reference=cve,
        risk_level=initial_level,
        risk_level_code=norm_level_code,
        classified_time=str(datetime.now()),
        repair_suggestion=f"Please review and mitigate the {initial_level} vulnerability accordingly.",
        automation_policy=AUTOMATION_POLICIES[norm_level_code],
        classification_reason=reason
    )

# === Run Parallel Analysis ===
classified = []
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(analyze_vulnerability, item) for item in findings]
    for f in tqdm(as_completed(futures), total=len(futures), desc="Classifying vulnerabilities"):
        result = f.result()
        if result:
            classified.append(result)

# === Output ===
risk_stats = Counter([v.risk_level_code for v in classified])
mcp_report = VulnerabilityRiskClassification(
    source="risk_classifier_llm.py",
    generated_time=str(datetime.now()),
    target_system=target_system,
    vulnerability_risks=classified,
    summary_statistics=dict(risk_stats),
    classification_strategy="LLM + Risk Normalization v5.1 (Heuristic + Explanation)"
)

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(mcp_report.dict(), f, indent=2, ensure_ascii=False)

# === Print result ===
print(f"\n Exported {len(classified)} vulnerabilities with CVE to → {OUTPUT_PATH}")
print(" Risk Level Distribution:")
for lvl in ["L4", "L3", "L2", "L1", "L0"]:
    print(f"  {lvl}: {risk_stats.get(lvl, 0)}")
