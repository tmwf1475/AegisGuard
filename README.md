# AegisGuard – Research Artifacts

This repository contains the **research artifacts** associated with the **AegisGuard framework**.
It collects historical prototypes, evolving agent versions, testing scripts, telemetry datasets, prompt templates, and simplified demos.
The goal is to provide **reviewer-verifiable evidence** of development, testing, and reproducibility for the work described in our manuscript.

**Note**: The repository is not intended to provide production-ready code. Instead, it documents **the experimental path** taken during research. Many scripts are simplified, partially functional, or serve as fixed artifacts that capture experimental results.

---

## Repository Structure and Details

### 1. Historical Agent Versions (Autoagent Tests)

* **autoagent\_test0 – autoagent\_test3**
  These directories contain **early versions of the automated vulnerability detection agent**.
  Each folder reflects a specific stage of the design process:

  * `autoagent_test0`: Initial skeleton with placeholder detection logic.
  * `autoagent_test1`: Added log parsing and package version checking.
  * `autoagent_test2`: Expanded to support CVE chunk matching with more conditions.
  * `autoagent_test3`: Integrated preliminary risk hints (mapping CVSS → L0–L4).

  These folders are important because they serve as **historical test records**. They show how the idea evolved from a simple script into more structured detection pipelines.
  The code here is not polished but demonstrates the incremental nature of the research.

* **autoagent\_testscript**
  A collection of helper scripts and experimental pipelines.
  Includes detection scripts, evaluation runs, and outputs (JSON, logs). Some files here were one-off experiments to validate ideas.

* **autoagent\_testexample**
  Minimal working example of the pipeline.
  Useful for showing the **smallest reproducible demo** that connects system info → CVE → detection output.

### 2. More Complete Records (Server-Side)

* **autoserver\_test\_agent**
  A more **comprehensive version** of the agent pipeline.
  This directory contains:

  * Server-side testing components
  * Evaluation utilities (logging, parsing, CVE comparison)
  * More complete pipelines that go beyond the toy examples

  Compared to the `autoagent_test*` folders, this directory is **closer to an end-to-end system**. It demonstrates how the detection agent was integrated with a server workflow and used in experimental environments.

* **metasploitable3**
  Telemetry, logs, and configuration files collected from **Metasploitable3** environments.
  This folder includes:

  * Host snapshots (system info, installed packages, open ports)
  * Observed exploit attempts
  * Simplified datasets used for reproducibility

  These artifacts show that the experiments were run against real vulnerable environments, not just toy datasets.

### 3. Prompts (LLM Integration)

* **prompts/**
  This directory contains **prompt templates** used in the LLM-based pipeline. They are critical for reproducibility of the reasoning process.

  * **detection\_prompts.md**

    * Input: `system_info.json` (system snapshot) + `vulnerability_chunks.json` (retrieved CVEs).
    * Task: Ask the LLM whether the system is affected by each vulnerability.
    * Output: JSON array of matches with reasoning.
    * Purpose: Demonstrates how vulnerabilities are mapped from raw data to structured detections.

  * **risk\_classification\_prompts.md**

    * Input: Detected CVEs (metadata, CVSS score, exploitability).
    * Task: Assign a **5-level risk score (L0–L4)**.
    * Output: JSON object containing the risk level and rationale.
    * Purpose: Demonstrates adaptive severity grading that goes beyond static CVSS scores.

  These files are **minimal but functional examples**. They show reviewers exactly how the LLM was prompted in practice.

### 4. Examples (Simplified Demos)

* **examples/**
  A key section for reviewers, since it contains **self-contained, runnable demos**.
  These examples illustrate the pipeline in the simplest possible form:

  * `system_info.sample.json`
    A **sample system snapshot** (Ubuntu 16.04). Includes OS version, kernel, installed packages, running services, open ports, firewall status, Docker images, and even a few log entries.
    This file shows what kind of telemetry the system collects.

  * `vulnerability_chunks.sample.json`
    A **sample set of vulnerability records** (Dirty COW, Apache, OpenSSH, MySQL, Samba, PHP).
    Each entry contains CVE ID, description, affected versions, CVSS, and exploitability.
    This file simulates the knowledge retrieved by the RAG module.

  * `simple_detect.py`
    A **lightweight detection-only script**.
    Reads `system_info.sample.json` and `vulnerability_chunks.sample.json`, performs simple matching, and writes `detections.json`.
    The logic includes:

    * Kernel version checks
    * Package version comparisons
    * CVSS-based risk hints (mapped to L0–L4)

  * `detections.json`
    Example output file.
    Contains a list of CVEs, whether they matched, the reasoning, and the risk hint.
    This demonstrates **end-to-end flow** from system info → CVE knowledge → detection output.
