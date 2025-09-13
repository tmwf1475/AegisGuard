#!/usr/bin/env python3
# collect_logs_linux.py — minimal log sampler (Linux)
# Output: ./out/logs_sample.json
import os, json, glob, subprocess, datetime, re
os.makedirs("./out", exist_ok=True)
targets = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log"
]
def tail(path, n=100):
    try:
        out = subprocess.check_output(["tail", "-n", str(n), path], text=True, stderr=subprocess.STDOUT)
        out = re.sub(r'[\x00-\x1F]+', ' ', out)
        return out
    except Exception as e:
        return f"[ERR] {e}"
snap = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "logs": {}}
for t in targets:
    for p in glob.glob(t):
        snap["logs"][p] = tail(p, 100)
with open("./out/logs_sample.json", "w", encoding="utf-8") as f:
    json.dump(snap, f, indent=2, ensure_ascii=False)
print("[INFO] Log sample written to ./out/logs_sample.json")
