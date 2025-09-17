# Prompts

This folder contains **prompt templates** used in the AegisGuard LLM-based vulnerability detection pipeline.
They illustrate how system information and RAG-retrieved knowledge are structured for the model, and how the model is instructed to respond in a **deterministic, reproducible, and verifiable** way.

## Files

* **`detection_prompts.md`**
  Defines how the LLM determines whether a system configuration is affected by candidate CVEs.

  * **Input**:

    * `system_info.json` (OS, kernel, installed packages, services, ports, optional logs)
    * `vulnerability_chunks.json` (retrieved CVE metadata such as affected ranges, CVSS, exploitability)
  * **Output**:

    * A JSON **array** of candidate vulnerabilities with fields for match status, reasoning, applicability signals, preliminary risk hints, and provenance.

* **`risk_classification_prompts.md`**
  Defines how the LLM assigns a **five-level risk score (L0–L4)** to vulnerabilities identified in the detection stage.

  * **Input**:

    * CVE metadata (ID, description, CVSS score/vector, exploitability hints, impact type, provenance)
  * **Output**:

    * A JSON **object** per vulnerability containing risk level, justification, supporting signals, confidence, and provenance.

## Purpose

These prompts are designed as **minimal but functional examples** that reviewers and practitioners can reproduce.
They provide:

1. **Transparency** – clear instructions on how the LLM is guided.
2. **Reproducibility** – deterministic input/output formats for evaluation.
3. **Traceability** – explicit use of provenance fields linking back to RAG sources.

Together, the detection and risk classification prompts form the core of the pipeline:

* **Detection** decides if a CVE applies.
* **Risk classification** evaluates its severity (L0–L4) for downstream analysis and reporting.

