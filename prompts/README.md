# Prompts

This folder contains **prompt templates** used in our LLM-based vulnerability detection pipeline.  
They demonstrate how system information and RAG-retrieved knowledge are provided to the LLM, and how the model is asked to respond.

- `detection_prompts.md`  
  Template for detecting whether the system is affected by known CVEs.  
  Input: `system_info.json` + `vulnerability_chunks.json`  
  Output: JSON array of matched vulnerabilities with reasoning.

- `risk_classification_prompts.md`  
  Template for assigning a **5-level risk score (L0–L4)** to detected vulnerabilities.  
  Input: CVE metadata (description, CVSS, exploitability)  
  Output: JSON object with risk level and rationale.

These prompts are **minimal but functional examples** for reproducibility and reviewer verification.
