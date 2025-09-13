#!/usr/bin/env bash
set -euo pipefail

echo "[*] Installing minimal dependencies (no remediation actions)..."
if command -v apt >/dev/null 2>&1; then
  sudo apt update -y
  sudo apt install -y jq curl wget net-tools lsof ss sysstat python3 python3-pip
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y jq curl wget net-tools lsof iproute python3 python3-pip
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y epel-release || true
  sudo yum install -y jq curl wget net-tools lsof iproute python3 python3-pip
else
  echo "[WARN] Unsupported package manager. Please install: jq curl wget net-tools lsof ss/python3 manually."
fi

python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
echo "[*] Done."
