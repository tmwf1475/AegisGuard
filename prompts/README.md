# AegisGuard Prompt Library

This directory contains the **prompt templates** used across the AegisGuard
LLM-driven vulnerability detection, summarization, and risk stratification
pipeline.  
Each prompt is designed to be **deterministic, reproducible, and aligned with
the system’s RAG-enhanced semantic reasoning engine**.

AegisGuard relies on three categories of prompts:

1. **Telemetry Summarization Prompts**  
2. **Vulnerability-Matching Prompts**  
3. **Risk-Classification Prompts**

These prompts collectively enable AegisGuard to convert host telemetry into
actionable vulnerability insights using a fully transparent and verifiable workflow.


# 1. Telemetry Summarization Prompts 

These prompts instruct the LLM to convert raw host telemetry into a
structured, security-focused summary.

### **Purpose**
Summarization normalizes heterogeneous system outputs (Linux/Windows/Containers)
into a consistent semantic representation that downstream detection and
classification modules can consume.

### **Input**
- `RAW_TELEMETRY`  
  Raw monitoring data (kernel, OS info, processes, packages, services,
  privilege context, ports, configs, etc.)

### **Output**
A structured JSON object:

```json
{
  "system": "...",
  "attack_surface": [...],
  "packages": [...],
  "privilege_context": [...],
  "security_observations": [...]
}
````

### **Role in Pipeline**

```
Raw Telemetry → Summarization Prompt → Structured Security Summary
```


# 2. Vulnerability-Matching Prompts 

These prompts govern how the LLM determines whether known vulnerabilities
(CVEs) apply to the target system.

### **Purpose**

To semantically match system characteristics against retrieved threat
intelligence (RAG), including:

* CVE descriptions
* version ranges
* exploit notes
* ATT&CK patterns
* misconfiguration indicators

### **Input**

* `SYSTEM_SUMMARY`
  Structured telemetry output from the summarization prompt.
* `CTI_CONTEXT`
  Top-k FAISS-retrieved CVE and ATT&CK chunks containing relevant knowledge.

### **Output**

A JSON array:

```json
[
  {
    "vulnerability_detected": true,
    "matched_cves": ["CVE-XXXX-YYYY"],
    "confidence": 0.0,
    "evidence": [...],
    "explanation": "..."
  }
]
```

### **Role in Pipeline**

```
Structured Summary + RAG Retrieval → Vulnerability-Matching Prompt → Candidate CVEs
```

# 3. Risk Classification Prompts 

These prompts evaluate each detected vulnerability and assign a
**five-level risk rating (L0–L4)** based on the AegisGuard rubric.

### **Purpose**

To incorporate operational context, exposure, exploitability, and system
configuration into a final risk score.

### **Input**

* CVE metadata (CVSS, CWE, impact type, exploit maturity)
* System context (exposure, privilege pathways, configurations)
* Detection-stage evidence

### **Output**

A JSON object:

```json
{
  "risk_level": "L3",
  "justification": "...",
  "signals": [...],
  "confidence": 0.92,
  "provenance": [...]
}
```

### **Role in Pipeline**

```
Candidate CVEs → Risk Classification Prompt → L0–L4 Severity Output
```

# 4. RAG Integration (Applies to All Prompts)

AegisGuard enhances all prompt stages using **retrieval-augmented generation**:

1. **Chunk CTI corpus** (CVE descriptions, malware reports, ATT&CK mappings)
2. **Embed using LLM-based encoder**
3. **Build FAISS index**
4. **Retrieve top-k relevant documents**
5. **Inject retrieved context into the prompt** before final inference

### RAG Workflow:

```
Host Telemetry
   ↓
Summarization Prompt
   ↓
Structured Summary
   ↓
FAISS Retrieval (Top-k CTI Chunks)
   ↓
Vulnerability-Matching Prompt
   ↓
Candidate Vulnerabilities
   ↓
Risk-Classification Prompt
   ↓
Final L0–L4 Risk Output
```

# 5. Design Principles

The prompt library adheres to the following principles:

### **Determinism**

Inputs and outputs follow strict schemas to support benchmarking and reproducibility.

### **Traceability**

Every prompt incorporates provenance fields linking outputs back to:

* telemetry evidence
* CTI retrieval chunks
* model decisions

### **Modularity**

Each prompt is self-contained and corresponds to one stage in the pipeline.

### **Transparency**

Prompts are intentionally kept readable and auditable for security analysts.

# 6. Files Included

| File                                | Description                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------- |
| `telemetry_summarization_prompt.md` | Summarizes raw telemetry into structured OS/service/attack-surface features |
| `vulnerability_matching_prompt.md`  | Performs CVE applicability reasoning with RAG-injected context              |
| `risk_classification_prompt.md`     | Assigns L0–L4 severity with justification and contextual reasoning          |


# 7. How These Prompts Are Used in Experiments

AegisGuard uses the same prompts across all evaluation scenarios:

* Linux hosts (Ubuntu, Debian, Kali)
* Windows hosts (Win10, Win2012R2)
* Containers / microservice testbeds
* Multi-vulnerability experimental scenarios (Web, CI/CD, Exposure)

This ensures **cross-platform consistency** and stable comparisons across
detection accuracy, risk classification, and ablation studies.
