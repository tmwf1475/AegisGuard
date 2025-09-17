# AegisGuard

## Overview

AegisGuard is a framework for automated vulnerability detection and risk classification.
It collects system telemetry, enriches it with threat intelligence data, and applies LLM-based reasoning to detect vulnerabilities in real-world environments.
The system outputs vulnerabilities with risk levels from **L0 (negligible) to L4 (critical)**.

AegisGuard is designed to be:

* Context-aware – considers privilege states, exposure, and system configuration.
* Lightweight – runs efficiently on commodity hardware.
* Complementary – works alongside tools like Wazuh or OpenVAS.

---

## Repository Structure

* `src/` – Core detection and risk classification modules.
* `telemetry/` – Scripts for collecting telemetry on Linux and Windows.
* `datasets/` – Sample anonymized datasets for testing.
* `prompts/` – Example prompts used for LLM inference and retrieval-augmented reasoning.
* `examples/` – End-to-end demonstrations:

  * **CVE-2017-0144 (EternalBlue)** walkthrough.
  * Detection logs, prompts, and outputs.
* `autoagent_test/` – A **lightweight testbed** for running simple experiments and validating the pipeline quickly (e.g., using a single CVE scenario).
* `autoserver_test_agent/` – A **more complete testing framework** simulating server-side scenarios, closer to production deployment. Includes multi-step workflows and broader vulnerability coverage.
* `docs/` – Additional documentation, figures, and evaluation notes.

---

## Example: CVE-2017-0144 (EternalBlue)

The `examples/eternalblue_walkthrough/` directory contains a full pipeline demonstration:

1. Telemetry collection from Windows Server 2008 R2.
2. Threat intelligence retrieval.
3. LLM inference and reasoning.
4. Risk classification result: **L4 (Critical)**.

