#!/usr/bin/env bash
# collector_min.sh — Minimal, remediation-free environment snapshot (Linux)
# Output: JSON to ./out/system_snapshot.json (no network POST).

set -euo pipefail
mkdir -p ./out
OUT="./out/system_snapshot.json"
TS="$(date -Iseconds)"

# Small helpers
sanitize_json() {
  tr -d '\000-\011\013\014\016-\037' | sed 's/\\/\\\\/g; s/"/\\\"/g'
}

cmd_out() {
  local cmd="$1"; local timeout="${2:-10}"
  if command -v timeout >/dev/null 2>&1; then
    timeout "${timeout}s" bash -lc "$cmd" 2>/dev/null | sanitize_json
  else
    bash -lc "$cmd" 2>/dev/null | sanitize_json
  fi
}

# Gather signals (bounded)
HOSTNAME="$(hostname | sanitize_json)"
OS="$( (lsb_release -ds || grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"' || uname -a) 2>/dev/null | sanitize_json)"
KERNEL="$(uname -r | sanitize_json)"
ARCH="$(uname -m | sanitize_json)"
IP="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 | sanitize_json)"

CPU="$(LANG=C top -bn1 2>/dev/null | awk '/Cpu\(s\)/{print $2+$4}' | head -n1)"
MEM="$(free 2>/dev/null | awk '/Mem:/{printf "%.2f", $3/$2*100.0}')"
DISK="$(df -h / 2>/dev/null | awk 'NR==2{gsub("%",""); print $5}')"

SERVICES="$(cmd_out "ps -eo pid,comm --no-headers | head -n 200" 5)"
PORTS="$(cmd_out "ss -tulpen | head -n 200" 5)"
RUNNING_SVC="$(cmd_out "systemctl list-units --type=service --state=running | head -n 200" 5)"
UPGRADES="$(cmd_out "apt list --upgradable 2>/dev/null | head -n 200" 8)"
PKGS="$(cmd_out "dpkg -l 2>/dev/null | head -n 200" 8)"
SYSLOG="$(cmd_out "journalctl -n 50 --no-pager 2>/dev/null || tail -n 50 /var/log/syslog 2>/dev/null" 5)"
UFW="$(cmd_out "ufw status verbose 2>/dev/null" 5)"
DOCKER_IMG="$(cmd_out "docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}}' 2>/dev/null | head -n 100" 5)"
PIP_LIST="$(cmd_out "pip list 2>/dev/null | head -n 200" 5)"

cat > "$OUT" <<JSON
{
  "timestamp": "$TS",
  "hostname": "$HOSTNAME",
  "os": "$OS",
  "kernel": "$KERNEL",
  "arch": "$ARCH",
  "ip": "$IP",
  "cpu_usage_pct": "$CPU",
  "mem_usage_pct": "$MEM",
  "disk_usage_pct_root": "$DISK",
  "processes_top200": "$SERVICES",
  "listening_ports": "$PORTS",
  "running_services": "$RUNNING_SVC",
  "upgradable_packages_top200": "$UPGRADES",
  "installed_packages_top200": "$PKGS",
  "system_logs_tail50": "$SYSLOG",
  "firewall_status": "$UFW",
  "docker_images_top100": "$DOCKER_IMG",
  "python_packages_top200": "$PIP_LIST"
}
JSON

echo "[INFO] Snapshot written to $OUT"
