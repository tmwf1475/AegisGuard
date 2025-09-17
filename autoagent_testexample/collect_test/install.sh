#!/bin/bash

echo "[*] Updating system and installing packages..."
apt update && apt install -y \
  curl wget jq ufw chkrootkit rkhunter lynis \
  net-tools lsof sysstat software-properties-common \
  docker.io python3-pip

echo "[*] install linpeas..."
LINPEAS_URL="https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
wget -O /usr/local/bin/linpeas.sh "$LINPEAS_URL"
chmod +x /usr/local/bin/linpeas.sh

echo "[*] install pip ..."
pip install --upgrade pip
pip install setuptools

echo "[*] Complete"
