# Risk Classification Prompt 

This prompt defines how the LLM should **assign a five-level risk classification (L0–L4)** to vulnerabilities already detected by the system.
It consumes **CVE metadata** (from NVD, vendor advisories, RAG chunks, or detection results) and outputs a **structured JSON object** with rationale, severity justification, and confidence.

> **Scope**: Risk scoring and rationale only.
> **Out of scope**: Remediation, patching, or mitigation suggestions.

## 1) Inputs

### Expected fields per vulnerability

```json
{
  "cve_id": "CVE-2016-5195",
  "description": "Dirty COW: privilege escalation in Linux kernel before 4.8.3",
  "cvss": 9.8,
  "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
  "exploit_status": "Active exploitation reported",
  "impact": "Privilege Escalation",
  "exploitability": "Public PoC available",
  "affected_scope": ["Linux kernel < 4.8.3"],
  "context_match": {
    "os": "Ubuntu 14.04",
    "kernel": "3.13.0-100-generic",
    "services": []
  }
}
```

## 2) Output (Strict JSON Schema)

The model must return **one JSON object per vulnerability**, containing:

```json
{
  "cve_id": "CVE-2016-5195",
  "risk_level": "L4",
  "justification": "Kernel 3.13.0-100 < 4.8.3. CVSS 9.8. Privilege escalation with public exploit and active in-the-wild reports. High systemic impact.",
  "signals": {
    "cvss": 9.8,
    "impact": "Privilege Escalation",
    "exploit_status": "Active exploitation reported",
    "exploitability": "Public PoC available"
  },
  "confidence": 0.95,
  "provenance": {
    "sources": ["NVD", "Vendor Advisory"],
    "doc_ids": ["nvd-2016-5195"]
  }
}
```

## 3) Risk Level Definitions (L0–L4)

* **L0 – No Impact**
  • Vulnerability does not apply, or system not in affected scope.
  • Example: Windows-only CVE on a Linux host.

* **L1 – Low**
  • Minor misconfigurations or low-severity bugs.
  • No known exploit, CVSS < 4.0, minimal security implications.

* **L2 – Medium**
  • Vulnerabilities with some impact but limited exploitability.
  • CVSS 4.0–6.9, no widespread exploitation.
  • Example: Information disclosure without direct privilege escalation.

* **L3 – High**
  • Severe vulnerabilities (CVSS 7.0–8.9).
  • Exploits exist or are likely; significant confidentiality/integrity/availability risk.
  • Example: Path traversal or denial-of-service with active PoC.

* **L4 – Critical**
  • CVSS ≥ 9.0 or Remote Code Execution/Privilege Escalation with public exploit.
  • Actively exploited zero-day or wormable vulnerability.
  • Example: Dirty COW (CVE-2016-5195), EternalBlue (CVE-2017-0144).

## 4) System Prompt (Copy-Paste)

Use this as the **system message** when prompting the LLM:

```
You are a vulnerability risk assessment agent. 
Your task is to assign a risk level (L0–L4) to each provided vulnerability.

STRICT RULES:
1) Focus only on risk classification and reasoning. Do NOT provide remediation steps.
2) Base your decision on CVSS score, exploit status, impact type, exploitability hints,
   and contextual signals (system match, affected scope).
3) Return a JSON object per vulnerability with:
   - cve_id
   - risk_level (L0–L4)
   - justification (≤ 240 words, evidence-based)
   - signals {cvss, impact, exploit_status, exploitability}
   - confidence (0–1)
   - provenance {sources, doc_ids}
4) Always be deterministic: do not invent CVSS scores or exploit status if not provided.
5) If critical input is missing, assign "risk_level": "L0" with justification = "insufficient evidence".
6) Output must be a JSON array of objects; no additional prose.
```

## 5) User Prompt Template

Use this as the **user message**:

```
VULNERABILITY METADATA
----------------------
{cve_metadata_json}

TASK
----
For each vulnerability:
- Assign a risk_level (L0–L4) using the definitions provided.
- Support the classification with a short justification (≤ 240 words).
- Fill in signals {cvss, impact, exploit_status, exploitability}.
- Provide a confidence value (0–1).
- Include provenance {sources, doc_ids} from the input.

Return only a JSON array.
```

## 6) Few-Shot Examples

### Example A: Privilege Escalation (Dirty COW)

```json
[
  {
    "cve_id": "CVE-2016-5195",
    "risk_level": "L4",
    "justification": "Linux kernel < 4.8.3 is affected. CVSS 9.8. Exploitation confirmed in the wild. Leads to privilege escalation with root access. Matches system context (Ubuntu 14.04, kernel 3.13.0-100).",
    "signals": {
      "cvss": 9.8,
      "impact": "Privilege Escalation",
      "exploit_status": "Active exploitation reported",
      "exploitability": "Public PoC available"
    },
    "confidence": 0.95,
    "provenance": {
      "sources": ["NVD", "Vendor Advisory"],
      "doc_ids": ["nvd-2016-5195"]
    }
  }
]
```

### Example B: Information Disclosure (Non-critical)

```json
[
  {
    "cve_id": "CVE-2020-XXXX",
    "risk_level": "L2",
    "justification": "OpenSSL version < 1.0.2 leaks timing information. CVSS 5.5. No known active exploitation. Limited impact (information disclosure only).",
    "signals": {
      "cvss": 5.5,
      "impact": "Information Disclosure",
      "exploit_status": "No public reports",
      "exploitability": "No known exploit"
    },
    "confidence": 0.8,
    "provenance": {
      "sources": ["NVD"],
      "doc_ids": ["nvd-2020-xxxx"]
    }
  }
]
```

### Example C: OS Mismatch (Non-applicable)

```json
[
  {
    "cve_id": "CVE-2017-0144",
    "risk_level": "L0",
    "justification": "CVE applies only to Windows SMB. System is Ubuntu Linux. Not exploitable in this context.",
    "signals": {
      "cvss": 8.5,
      "impact": "RCE",
      "exploit_status": "Exploit available",
      "exploitability": "Wormable"
    },
    "confidence": 0.99,
    "provenance": {
      "sources": ["MSRC"],
      "doc_ids": ["msrc-2017-0144"]
    }
  }
]
```

## 7) Guardrails & Determinism

* **No remediation**: Only classification and reasoning.
* **Context awareness**: If the system context excludes applicability → downgrade to L0.
* **Evidence-first**: Use CVSS, exploit status, and impact as primary drivers.
* **Stable ordering**: Sort output by `cve_id` ascending.
* **Concise justification**: ≤ 240 words, focused on decisive evidence.
* **Confidence**: Reflect certainty of classification (not just CVSS confidence).

