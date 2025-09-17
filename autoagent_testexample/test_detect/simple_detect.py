import json, re, sys
from typing import Tuple

def parse_version(v: str):
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m: return (0,0,0)
    return tuple(int(x or 0) for x in m.groups(default="0"))

def cmp_version(a: str, b: str) -> int:
    va, vb = parse_version(a), parse_version(b)
    return (va>vb) - (va<vb)

def match_range(current: str, expr: str) -> bool:
    for part in [p.strip() for p in expr.split(",")]:
        m = re.match(r"(<=|>=|<|>|==)\s*([\w\.\-]+)", part)
        if not m: return False
        op, rhs = m.group(1), m.group(2)
        c = cmp_version(current, rhs)
        ok = {"<": c<0, "<=": c<=0, ">": c>0, ">=": c>=0, "==": c==0}.get(op, False)
        if not ok: return False
    return True

def risk_hint(cvss: float, exploit: str, impact: str) -> str:
    base = "L2"
    if cvss >= 9.0: base = "L4"
    elif cvss >= 7.0: base = "L3"
    elif cvss >= 4.0: base = "L2"
    else: base = "L1"
    e = (exploit or "").lower()
    if any(k in e for k in ["public poc","exploit available","active exploitation","wormable"]):
        if base == "L3": base = "L4"
        elif base == "L2": base = "L3"
    i = (impact or "").lower()
    if "rce" in i or "remote code execution" in i or "privilege escalation" in i:
        if base == "L3": base = "L4"
        elif base == "L2": base = "L3"
    return base

def main(sys_path: str, vuln_path: str, out_path: str):
    with open(sys_path, "r", encoding="utf-8") as f:
        sysinfo = json.load(f)
    with open(vuln_path, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    results = []
    for ch in chunks:
        reasons = []
        match = True

        if ch.get("affected_os"):
            if ch["affected_os"].lower() not in sysinfo.get("os","").lower():
                reasons.append(f"OS mismatch: requires {ch['affected_os']}, system is {sysinfo.get('os')}")
                match = False
            else:
                reasons.append(f"OS match: {sysinfo.get('os')} includes {ch['affected_os']}")

        if match and ch.get("affected_kernel") and sysinfo.get("kernel"):
            if match_range(sysinfo["kernel"], ch["affected_kernel"]):
                reasons.append(f"Kernel match: {sysinfo['kernel']} satisfies {ch['affected_kernel']}")
            else:
                reasons.append(f"Kernel mismatch: {sysinfo['kernel']} not in {ch['affected_kernel']}")
                match = False

        if match and ch.get("affected_package"):
            pkg = next((p for p in sysinfo.get("installed_packages",[]) if p["name"].lower()==ch["affected_package"].lower()), None)
            if not pkg:
                reasons.append(f"Package {ch['affected_package']} not installed")
                match = False
            else:
                reasons.append(f"Package present: {pkg['name']} {pkg['version']}")
                if ch.get("affected_pkg_versions"):
                    if match_range(pkg["version"], ch["affected_pkg_versions"]):
                        reasons.append(f"Package version match: {pkg['version']} in {ch['affected_pkg_versions']}")
                    else:
                        reasons.append(f"Package version mismatch: {pkg['version']} not in {ch['affected_pkg_versions']}")
                        match = False

        record = {
            "cve_id": ch.get("cve_id","UNKNOWN"),
            "match": bool(match),
            "reason": "; ".join(reasons) if reasons else "insufficient evidence",
            "signals": {
                "os_match": ch.get("affected_os","").lower() in sysinfo.get("os","").lower() if ch.get("affected_os") else False,
                "kernel_match": bool(ch.get("affected_kernel")),
                "package_match": bool(ch.get("affected_package")),
                "package_version_match": bool(ch.get("affected_pkg_versions")),
                "service_exposure": False,
                "port_exposure": False
            },
            "risk_hint": risk_hint(float(ch.get("cvss", 0.0)), ch.get("exploitability",""), ch.get("impact","")) if match else "L0",
            "confidence": 0.85 if match else 0.98,
            "provenance": {"doc_ids": [ch.get("doc_id","")], "sources": [ch.get("source","")]}
        }
        results.append(record)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[INFO] Wrote detections to {out_path}")

if __name__ == "__main__":
    sys_path = sys.argv[1] if len(sys.argv)>1 else "system_info.sample.json"
    vuln_path = sys.argv[2] if len(sys.argv)>2 else "vulnerability_chunks.sample.json"
    out_path = sys.argv[3] if len(sys.argv)>3 else "detections.json"
    main(sys_path, vuln_path, out_path)
