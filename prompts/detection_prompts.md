# Detection Prompt 

This prompt defines how the LLM should determine whether a given system configuration is affected by known vulnerabilities using **system information** and **RAG-retrieved vulnerability chunks**.
It emphasizes **deterministic, evidence-grounded outputs**, explicit **non-applicability** handling, and a **strict JSON schema** suitable for downstream use.

> **Scope**: Detection only.
> **Out of scope**: Remediation, patch commands, hardening guidance.

## 1) Inputs

### 1.1 `system_info.json`

Recommended fields (extend as needed):

```json
{
  "os": "Ubuntu",
  "version": "20.04",
  "kernel": "5.4.0-42-generic",
  "architecture": "x86_64",
  "installed_packages": [
    { "name": "openssl", "version": "1.1.1f-1ubuntu2" },
    { "name": "apache2", "version": "2.4.41-4ubuntu3.9" }
  ],
  "running_services": ["ssh", "nginx"],
  "open_ports": ["22/tcp", "80/tcp"],
  "security_controls": {
    "firewall": "ufw-enabled",
    "selinux_apparmor": "apparmor-enforcing"
  },
  "container": {
    "is_container": false,
    "runtime": null,
    "image": null
  },
  "cloud": {
    "provider": null,
    "instance_type": null,
    "public_ip_exposed": false
  },
  "logs_optional": [
    {
      "source": "/var/log/auth.log",
      "time_range": "last_24h",
      "lines": ["...optional evidence snippets..."]
    }
  ]
}
```

### 1.2 `vulnerability_chunks.json`

RAG-retrieved entries. Include doc provenance to support traceability:

```json
[
  {
    "doc_id": "nvd-2021-12345",
    "source": "NVD",
    "retrieved_at": "2025-09-10T08:15:00Z",
    "cve_id": "CVE-2021-41773",
    "title": "Apache HTTP Server path traversal",
    "description": "Path traversal in Apache HTTP Server...",
    "affected_os": "linux",
    "affected_versions": ">= 2.4.49, < 2.4.51",
    "affected_kernel": null,
    "affected_package": "apache2",
    "affected_pkg_versions": ">= 2.4.49, < 2.4.51",
    "required_service": "httpd|apache2",
    "required_ports": ["80/tcp","443/tcp"],
    "cpe": ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"],
    "cvss": 7.5,
    "exploit_status": "Exploit available",
    "impact": "RCE"
  }
]
```

> Tips
> • Use concise **range expressions** like `< 4.8.3`, `>= 2.4.49, < 2.4.51`.
> • Include **required service/port** hints when applicable (e.g., SMB, HTTP).
> • Add `doc_id`/`source` to enable provenance in the output.

## 2) Output (Strict JSON Schema)

The model must return an **array** of objects—one per candidate vulnerability—**including non-matches** with explanations.

```json
[
  {
    "cve_id": "CVE-YYYY-XXXX",
    "match": true,
    "match_score": 0.86,
    "reason": "Kernel 3.13.0-100 < 4.8.3; matches Dirty COW affected range.",
    "signals": {
      "os_match": true,
      "kernel_match": true,
      "os_version_match": false,
      "package_match": false,
      "package_version_match": false,
      "service_exposure": false,
      "port_exposure": false,
      "log_evidence_used": false
    },
    "risk_hint": "L3",
    "confidence": 0.86,
    "provenance": {
      "doc_ids": ["nvd-2016-5195"],
      "sources": ["NVD"]
    }
  }
]
```

### Field requirements

* **cve\_id** *(string, required)*
* **match** *(boolean, required)* — whether the CVE applies to the system.
* **match\_score** *(0–1, required)* — calibrated similarity/applicability score.
* **reason** *(string, required)* — max \~240 words; cite decisive evidence (versions, services, ports).
* **signals** *(object, required)* — boolean flags showing what matched/didn’t.
* **risk\_hint** *(L0–L4, required)* — preliminary severity hint for downstream modules (final grading happens elsewhere).
* **confidence** *(0–1, required)* — self-assessment of detection certainty.
* **provenance** *(object, required)* — `doc_ids` and `sources` from the provided chunks.

> **Important:** Return **all** candidates, including those with `"match": false` and a clear reason (e.g., OS mismatch, package absent).

## 3) System Prompt (Copy-Paste)

> Use this as the **system** message when constructing your prompt:

```
You are a cybersecurity detection agent. Your job is to decide if the provided
system is affected by candidate vulnerabilities retrieved via RAG.

STRICT RULES:
1) Detection only. Do NOT provide remediation, patch commands, or hardening tips.
2) Base all decisions strictly on the given inputs (system_info, vulnerability_chunks, optional logs).
   Do not hallucinate missing versions, packages, or services.
3) For each candidate vulnerability, return one JSON object with:
   - cve_id, match (true/false), match_score (0–1), reason (≤ ~240 words),
   - signals{...}, risk_hint (L0–L4), confidence (0–1),
   - provenance{doc_ids, sources}.
4) Always include non-matching items with an explicit reason (e.g., OS mismatch).
5) Use concrete evidence: version ranges, kernel values, package versions,
   presence of required services/ports, and any explicit log lines provided.
6) If evidence is insufficient, set match=false with reason="insufficient evidence".
7) Be deterministic and concise. Do not include remediation or general advice.
8) Output MUST be a single JSON array; no prose outside the JSON.
```

## 4) User Prompt Template

> Provide as the **user** message:

```
SYSTEM INFORMATION
------------------
{system_info_json}

CANDIDATE VULNERABILITIES (RAG)
-------------------------------
{vulnerability_chunks_json}

TASK
----
For each candidate vulnerability:
- Determine applicability (match true/false) using explicit evidence only.
- Provide a calibrated match_score (0–1).
- Explain the decision briefly in "reason" (≤ ~240 words).
- Fill boolean "signals" for which checks matched: os/kernel/version/package/service/port/log evidence.
- Set a preliminary "risk_hint" (L0–L4) without providing mitigation steps.
- Provide "confidence" (0–1) as your self-estimate.
- Include "provenance" with doc_ids and sources from the input.

Return ONLY a single JSON array as specified.
```

## 5) Few-Shot Examples

### Example A: Linux kernel (Dirty COW)

**Input (excerpt)**

* `system_info.json`: Ubuntu 14.04, kernel `3.13.0-100-generic`.
* `vulnerability_chunks.json`: CVE-2016-5195 with `affected_kernel: "< 4.8.3"`, `impact: "Privilege Escalation"`, `cvss: 9.8`.

**Expected (condensed)**

```json
[
  {
    "cve_id": "CVE-2016-5195",
    "match": true,
    "match_score": 0.9,
    "reason": "Kernel 3.13.0-100 < 4.8.3 (affected range). OS is Linux. No conflicting evidence.",
    "signals": {
      "os_match": true,
      "kernel_match": true,
      "os_version_match": false,
      "package_match": false,
      "package_version_match": false,
      "service_exposure": false,
      "port_exposure": false,
      "log_evidence_used": false
    },
    "risk_hint": "L4",
    "confidence": 0.9,
    "provenance": { "doc_ids": ["nvd-2016-5195"], "sources": ["NVD"] }
  }
]
```

### Example B: Windows SMB (EternalBlue) on Linux host (Non-match)

**Input (excerpt)**

* `system_info.json`: Ubuntu Linux.
* `vulnerability_chunks.json`: CVE-2017-0144 requires Windows SMB.

**Expected**

```json
[
  {
    "cve_id": "CVE-2017-0144",
    "match": false,
    "match_score": 0.0,
    "reason": "OS mismatch: Windows-only SMB vulnerability; system is Ubuntu Linux.",
    "signals": {
      "os_match": false,
      "kernel_match": false,
      "os_version_match": false,
      "package_match": false,
      "package_version_match": false,
      "service_exposure": false,
      "port_exposure": false,
      "log_evidence_used": false
    },
    "risk_hint": "L0",
    "confidence": 0.98,
    "provenance": { "doc_ids": ["msrc-2017-0144"], "sources": ["MSRC"] }
  }
]
```

### Example C: Package & Port Requirements

**Input (excerpt)**

* `system_info.json`: Apache `2.4.49` running, ports `80/tcp`, `443/tcp`.
* `vulnerability_chunks.json`: CVE-2021-41773 requires Apache 2.4.49–2.4.50 and HTTP exposure.

**Expected**

```json
[
  {
    "cve_id": "CVE-2021-41773",
    "match": true,
    "match_score": 0.88,
    "reason": "apache2 2.4.49 in affected range; HTTP service exposed on 80/tcp; consistent with path traversal vulnerability.",
    "signals": {
      "os_match": true,
      "kernel_match": false,
      "os_version_match": false,
      "package_match": true,
      "package_version_match": true,
      "service_exposure": true,
      "port_exposure": true,
      "log_evidence_used": false
    },
    "risk_hint": "L3",
    "confidence": 0.88,
    "provenance": { "doc_ids": ["nvd-2021-41773"], "sources": ["NVD"] }
  }
]
```

## 6) Guardrails & Determinism

* **No remediation**: Do not suggest patches, commands, or hardening steps.
* **Evidence-first**: Only use facts present in the inputs. Unknown ≠ vulnerable.
* **Non-matches matter**: Always include clear reasons for `"match": false`.
* **Stable ordering**: Sort results by `cve_id` ascending to maximize reproducibility.
* **Concise reason**: ≤ \~240 words per item; emphasize decisive checks (version ranges, ports, services).
* **Confidence vs score**:

  * `match_score` reflects signal alignment (versions, services, ports).
  * `confidence` reflects your certainty given the available evidence (data completeness).

## 7) Optional Signals to Leverage

* **Kernel/OS ranges**: `< 4.8.3`, `>= 5.10`, etc.
* **Package name & version**: `affected_package`, `affected_pkg_versions`.
* **Service/port exposure**: `required_service`, `required_ports`.
* **Container**: `is_container`, `image`, `runtime`.
* **Cloud**: `provider`, `public_ip_exposed`.
* **Logs (optional)**: Bruteforce patterns, crash traces; cite source if used.
