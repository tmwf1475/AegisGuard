"""
Minimal, reproducible demonstration of the "prompt + reasoning + structured output"
stage for AegisGuard. This script focuses on detection and preliminary risk
classification (L0–L4) ONLY. It does NOT perform remediation/patching.

Inputs:
  - system_info.json: basic system snapshot (OS, kernel, packages, services)
  - vulnerability_chunks.json: RAG-retrieved vulnerability snippets (CVE, affected ranges, CVSS, etc.)

Output:
  - JSON list of detection results (printed to stdout and optionally saved)
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path

RISK_LEVELS = ("L0", "L1", "L2", "L3", "L4")

def cvss_to_risk(cvss: Optional[float],
                 exploitability: Optional[str] = None,
                 impact_hint: Optional[str] = None) -> str:
    """
    Map CVSS score and simple exploitability hints to rough L0–L4.
    This is a deterministic *preliminary* mapping for demo purposes.
    """
    if cvss is None:
        base = "L2"
    elif cvss >= 9.0:
        base = "L4"
    elif cvss >= 7.0:
        base = "L3"
    elif cvss >= 4.0:
        base = "L2"
    elif cvss > 0.0:
        base = "L1"
    else:
        base = "L0"

    expl = (exploitability or "").lower()
    if any(k in expl for k in ("public poc", "exploit available", "active exploitation", "wormable")):
        if base == "L3":
            base = "L4"
        elif base == "L2":
            base = "L3"

    hint = (impact_hint or "").lower()
    if "rce" in hint or "remote code execution" in hint or "privilege escalation" in hint:
        if base == "L3":
            base = "L4"
        elif base == "L2":
            base = "L3"

    return base

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[^\d].*)?$")

def parse_version(ver: str) -> Tuple[int, int, int]:
    """
    Parse a semantic-ish version string to a comparable (major, minor, patch) tuple.
    Non-numeric suffixes are ignored. Missing parts default to 0.
    Examples:
      "4.8.3" -> (4, 8, 3)
      "3.13.0-100-generic" -> (3, 13, 0)
      "1.0.1f" -> (1, 0, 1)
    """
    m = _VERSION_RE.match(ver.strip())
    if not m:
        return (0, 0, 0)
    major = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    return (major, minor, patch)

def cmp_version(a: str, b: str) -> int:
    """
    Compare version strings (a vs b). Returns:
      -1 if a < b, 0 if a == b, 1 if a > b
    """
    ta = parse_version(a)
    tb = parse_version(b)
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0

def match_version_range(current: str, expr: str) -> bool:
    """
    Check whether 'current' satisfies a simple range expression like:
      "< 4.8.3", "<= 5.4.0", "> 1.0.1", ">= 2.4.7", "== 1.2.3"
    Also supports a comma-separated AND of conditions, e.g. "< 4.8.3, >= 3.0.0"
    Whitespace is ignored. Unrecognized expressions return False generously.

    This is intentionally simple and deterministic for the demo.
    """
    parts = [p.strip() for p in expr.split(",")]
    for p in parts:
        m = re.match(r"(<=|>=|<|>|==)\s*([\w\.\-\_]+)", p)
        if not m:
            return False
        op, rhs = m.group(1), m.group(2)
        c = cmp_version(current, rhs)
        ok = {
            "<":  c < 0,
            "<=": c <= 0,
            ">":  c > 0,
            ">=": c >= 0,
            "==": c == 0
        }.get(op, False)
        if not ok:
            return False
    return True

@dataclass
class PackageInfo:
    name: str
    version: str

@dataclass
class SystemInfo:
    os: str
    version: str
    kernel: Optional[str] = None
    architecture: Optional[str] = None
    installed_packages: List[PackageInfo] = field(default_factory=list)
    running_services: List[str] = field(default_factory=list)
    open_ports: List[str] = field(default_factory=list)

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "SystemInfo":
        pkgs = []
        for p in d.get("installed_packages", []):
            if isinstance(p, dict) and "name" in p and "version" in p:
                pkgs.append(PackageInfo(name=str(p["name"]), version=str(p["version"])))
        return SystemInfo(
            os=str(d.get("os", "")),
            version=str(d.get("version", "")),
            kernel=str(d.get("kernel")) if d.get("kernel") is not None else None,
            architecture=str(d.get("architecture")) if d.get("architecture") is not None else None,
            installed_packages=pkgs,
            running_services=[str(s) for s in d.get("running_services", [])],
            open_ports=[str(p) for p in d.get("open_ports", [])]
        )

@dataclass
class VulnChunk:
    cve_id: str
    description: Optional[str] = None
    affected_os: Optional[str] = None           # e.g., "Windows", "Ubuntu", "Linux", "Windows NT kernels"
    affected_versions: Optional[str] = None     # version range expression like "< 4.8.3, >= 3.0.0"
    affected_kernel: Optional[str] = None       # kernel range (same syntax)
    affected_package: Optional[str] = None      # if vulnerability ties to a package name
    affected_pkg_versions: Optional[str] = None # version range expression for the package
    cvss: Optional[float] = None
    exploitability: Optional[str] = None        # free-text hints: "public PoC", "active exploitation"
    impact: Optional[str] = None                # e.g., "RCE", "Privilege Escalation", etc.

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "VulnChunk":
        cvss_val = d.get("cvss")
        try:
            cvss_num = float(cvss_val) if cvss_val is not None else None
        except Exception:
            cvss_num = None
        return VulnChunk(
            cve_id=str(d.get("cve_id", "")),
            description=d.get("description"),
            affected_os=d.get("affected_os"),
            affected_versions=d.get("affected_versions"),
            affected_kernel=d.get("affected_kernel"),
            affected_package=d.get("affected_package"),
            affected_pkg_versions=d.get("affected_pkg_versions"),
            cvss=cvss_num,
            exploitability=d.get("exploitability"),
            impact=d.get("impact")
        )


def system_matches_chunk(sysinfo: SystemInfo, chunk: VulnChunk) -> Tuple[bool, List[str]]:
    """
    Determine if a vulnerability chunk applies to the given system.
    Returns (match_boolean, reasons_list).
    """
    reasons: List[str] = []

    if chunk.affected_os:
        os_need = chunk.affected_os.lower()
        os_has = sysinfo.os.lower()
        if os_need not in os_has:
            reasons.append(f"OS mismatch: requires '{chunk.affected_os}', system is '{sysinfo.os}'.")
            return (False, reasons)
        reasons.append(f"OS match: '{sysinfo.os}' satisfies affected_os='{chunk.affected_os}'.")

    if chunk.affected_kernel and sysinfo.kernel:
        if match_version_range(sysinfo.kernel, chunk.affected_kernel):
            reasons.append(f"Kernel match: {sysinfo.kernel} satisfies '{chunk.affected_kernel}'.")
        else:
            reasons.append(f"Kernel mismatch: {sysinfo.kernel} does not satisfy '{chunk.affected_kernel}'.")
            return (False, reasons)

    if chunk.affected_versions and sysinfo.version:
        if match_version_range(sysinfo.version, chunk.affected_versions):
            reasons.append(f"OS version match: {sysinfo.version} satisfies '{chunk.affected_versions}'.")
        else:
            reasons.append(f"OS version mismatch: {sysinfo.version} does not satisfy '{chunk.affected_versions}'.")
            return (False, reasons)

    if chunk.affected_package:
        pkg = next((p for p in sysinfo.installed_packages
                    if p.name.lower() == chunk.affected_package.lower()), None)
        if not pkg:
            reasons.append(f"Package '{chunk.affected_package}' not installed.")
            return (False, reasons)
        reasons.append(f"Package present: {pkg.name} {pkg.version}")
        if chunk.affected_pkg_versions:
            if match_version_range(pkg.version, chunk.affected_pkg_versions):
                reasons.append(f"Package version match: {pkg.version} satisfies '{chunk.affected_pkg_versions}'.")
            else:
                reasons.append(f"Package version mismatch: {pkg.version} does not satisfy '{chunk.affected_pkg_versions}'.")
                return (False, reasons)

    if not reasons:
        reasons.append("No concrete matching constraints found in chunk; skipping.")
        return (False, reasons)

    return (True, reasons)


def classify_detection(sysinfo: SystemInfo, chunk: VulnChunk, matched: bool, reasons: List[str]) -> Dict[str, Any]:
    """
    Build the structured detection record, including preliminary risk level.
    """
    if not matched:
        return {
            "cve_id": chunk.cve_id or "UNKNOWN",
            "match": False,
            "reason": "; ".join(reasons)[:1200],
            "risk_level": "L0",
            "next_action": "ignore"
        }

    risk = cvss_to_risk(chunk.cvss, chunk.exploitability, chunk.impact)
    if risk == "L4":
        next_action = "proceed_to_patch"
    elif risk == "L3":
        next_action = "monitor_and_patch"
    elif risk == "L2":
        next_action = "monitor"
    elif risk == "L1":
        next_action = "monitor"
    else:
        next_action = "ignore"

    return {
        "cve_id": chunk.cve_id or "UNKNOWN",
        "match": True,
        "reason": "; ".join(reasons)[:1200],
        "risk_level": risk,
        "next_action": next_action,
        "metadata": {
            "cvss": chunk.cvss,
            "exploitability": chunk.exploitability,
            "impact": chunk.impact,
            "description": chunk.description
        }
    }


def load_json(path: Union[str, Path]) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: Union[str, Path], obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def main():
    parser = argparse.ArgumentParser(
        description="Minimal, reproducible prompt reasoning demo (detection + L0–L4 classification)."
    )
    parser.add_argument("--system", default="examples/system_info.json",
                        help="Path to system_info.json")
    parser.add_argument("--vulns", default="examples/vulnerability_chunks.json",
                        help="Path to vulnerability_chunks.json")
    parser.add_argument("--out", default="examples/sample_output.json",
                        help="Path to write output JSON")
    args = parser.parse_args()

    sys_raw = load_json(args.system)
    vulns_raw = load_json(args.vulns)

    sysinfo = SystemInfo.from_json(sys_raw)
    chunks = [VulnChunk.from_json(v) for v in vulns_raw]

    results: List[Dict[str, Any]] = []
    for ch in chunks:
        matched, reasons = system_matches_chunk(sysinfo, ch)
        record = classify_detection(sysinfo, ch, matched, reasons)
        results.append(record)

    # Output
    print(json.dumps(results, indent=2, ensure_ascii=False))
    save_json(args.out, results)

    print(f"\n[INFO] Wrote structured results to: {args.out}")
    print("[INFO] This demo performs deterministic rule-based reasoning only (no patching).")

if __name__ == "__main__":
    main()
