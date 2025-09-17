#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] This script must be run as root."
  echo "Try: sudo $0"
  exit 1
fi

set -x
export LC_ALL=C
TIMESTAMP=$(date -Iseconds)
echo "[INFO] Collector started at $TIMESTAMP"

MCP_URL="http://140.128.101.238:8000/detection/monitor/snapshot"
readonly LOGFILE="${HOME}/mcp_collector.log"
readonly TMPFILE="/tmp/mcp_payload.json"
readonly TMPGZ="/tmp/mcp_payload.json.gz"
mkdir -p "$(dirname "$LOGFILE")"
exec > >(tee -a "$LOGFILE") 2>&1

sanitize_and_limit() {
  local input="$1"
  local max_len=${2:-8000}
  local clean=$(echo "$input" |
    tr -d '\000-\011\013\014\016-\037\r' |
    sed 's/\\/\\\\/g' |
    sed 's/"/\\"/g' |
    sed 's/\x27/\\x27/g' |
    sed 's/\x5c/\\\\/g' |
    tr '\n' ' ')
  if [ ${#clean} -gt $max_len ]; then
    echo "\"[Trimmed] Output too long ($max_len chars max)\""
  else
    echo "\"$clean\""
  fi
}

REAL_USER=$(logname 2>/dev/null || echo "$USER")
HOSTNAME_RAW=$(hostname)
HOSTNAME=$(sanitize_and_limit "$HOSTNAME_RAW")
[ -z "$HOSTNAME_RAW" ] && HOSTNAME="\"unknown\""

IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n 1)

# Improved OS detection
if command -v lsb_release &>/dev/null; then
  OS_RAW=$(lsb_release -ds 2>/dev/null)
elif [ -f /etc/os-release ]; then
  OS_RAW=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
elif command -v hostnamectl &>/dev/null; then
  OS_RAW=$(hostnamectl | grep "Operating System" | cut -d: -f2 | xargs)
else
  OS_RAW="unknown"
fi

OS=$(sanitize_and_limit "$OS_RAW")
[ -z "$OS_RAW" ] && OS="\"unknown\""

# Debug log
echo "[DEBUG] OS_RAW=$OS_RAW"
echo "[DEBUG] HOSTNAME_RAW=$HOSTNAME_RAW"
echo "[DEBUG] UPTIME_RAW=$UPTIME_RAW"

KERNEL=$(uname -r)
UPTIME_RAW=$(uptime -p)
UPTIME=$(sanitize_and_limit "$UPTIME_RAW")
[ -z "$UPTIME_RAW" ] && UPTIME="\"unknown\""
ARCH=$(uname -m)

CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | awk '{printf "%.2f", $1}')
MEM=$(free | awk '/Mem:/ {printf "%.2f", $3/$2 * 100.0}')
DISK=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')

SERVICES=$(timeout 10s ps -eo pid,comm --no-headers | tr -d '\000-\011\013\014\016-\037\r' | sed 's/"/\\"/g' | awk '{printf "{\"pid\":%s,\"name\":\"%s\"},", $1, $2}')
SERVICES="[${SERVICES%,}]"
STARTUP=$(timeout 5s ls /etc/init.d/ 2>/dev/null | sed 's/"/\\"/g' | awk '{printf "\"%s\",", $1}')
STARTUP="[${STARTUP%,}]"

NET_CONN=$(timeout 5s ss -tunlp 2>/dev/null | tr -d '\000-\011\013\014\016-\037\r' | sed 's/"/\\"/g' | awk '{printf "\"%s %s %s\",", $1, $5, $NF}')
NET_CONN="[${NET_CONN%,}]"
LOGS_RAW=$(timeout 5s tail -n 50 /var/log/syslog 2>/dev/null)
LOGS=$(sanitize_and_limit "$LOGS_RAW")

USERS=$(cat /etc/passwd | awk -F: '$3 >= 1000 {printf "\"%s\",", $1}')
USERS="[${USERS%,}]"

UFW=$(sanitize_and_limit "$(timeout 5s ufw status verbose 2>/dev/null)")
PARTITIONS=$(timeout 5s lsblk -o NAME,SIZE,MOUNTPOINT,FSTYPE | tr -d '\000-\011\013\014\016-\037\r' | sed 's/"/\\"/g' | awk '{printf "\"%s\",", $0}')
PARTITIONS="[${PARTITIONS%,}]"
HOTFIX=$(timeout 10s dpkg-query -l | head -n 100 | tr -d '\000-\011\013\014\016-\037\r' | sed 's/"/\\"/g' | awk '{printf "\"%s\",", $0}')
HOTFIX="[${HOTFIX%,}]"
CVE_LOGS=$(timeout 5s grep "CVE" /var/log/dpkg.log 2>/dev/null)
CVE_LOGS=$(sanitize_and_limit "$CVE_LOGS")
KERNEL_SEC=$(timeout 10s sysctl -a 2>/dev/null | tr -d '\000-\011\013\014\016-\037\r' | sed 's/"/\\"/g' | awk '{printf "\"%s\",", $0}')
KERNEL_SEC="[${KERNEL_SEC%,}]"
UPGRADES=$(timeout 10s apt list --upgradable 2>/dev/null | tr -d '\000-\011\013\014\016-\037\r' | sed 's/"/\\"/g' | awk '{printf "\"%s\",", $0}')
UPGRADES="[${UPGRADES%,}]"
SOFTWARE=$(timeout 10s dpkg-query -l | head -n 100 | tr -d '\000-\011\013\014\016-\037\r' | sed 's/"/\\"/g' | awk '{printf "\"%s\",", $0}')
SOFTWARE="[${SOFTWARE%,}]"
JAVA=$(sanitize_and_limit "$(timeout 5s java -version 2>&1)")
PIP=$(sanitize_and_limit "$(timeout 5s pip list 2>/dev/null)")
DOCKER=$(timeout 5s docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | tr -d '\000-\011\013\014\016-\037\r' | sed 's/"/\\"/g' | awk '{printf "\"%s\",", $0}')
DOCKER="[${DOCKER%,}]"
SYSLOG_RAW=$(timeout 5s journalctl -n 50 --no-pager 2>/dev/null)
SYSLOG=$(sanitize_and_limit "$SYSLOG_RAW")

LINPEAS_RESULT="\"Not Run or No Permission\""
if [ -x /usr/local/bin/linpeas.sh ] && [ "$(id -u)" -eq 0 ]; then
  LINPEAS_RAW=$(timeout 120s /usr/local/bin/linpeas.sh -q 2>/dev/null)
  LINPEAS_RESULT=$(sanitize_and_limit "$LINPEAS_RAW" 10000)
fi

MITRE_MATCHES="[]"
ATTACK_SIGNATURES=("nmap:T1046" "nc:T1059.001" "python -c:T1059.006" "gcc:T1505.003" "wget|curl.*sh:T1059.004")
PROCESSES=$(ps aux)
for sig in "${ATTACK_SIGNATURES[@]}"; do
  IFS=":" read -r pattern tid <<< "$sig"
  if echo "$PROCESSES" | grep -E -i "$pattern" >/dev/null; then
    MITRE_MATCHES=$(echo "$MITRE_MATCHES" | jq ". += [{\"technique_id\": \"$tid\", \"match\": \"$pattern\"}]")
  fi
done

JSON=$(cat <<EOF
{
  "timestamp": "$TIMESTAMP",
  "hostname": $HOSTNAME,
  "ip": "$IP",
  "os": $OS,
  "kernel": "$KERNEL",
  "arch": "$ARCH",
  "user": "$REAL_USER",
  "uptime": $UPTIME,
  "cpu_usage": $CPU,
  "memory_usage": $MEM,
  "disk_usage": "$DISK",
  "services": $SERVICES,
  "startup_services": $STARTUP,
  "network_connections": $NET_CONN,
  "logs": $LOGS,
  "lynis_report": "Not Included",
  "chkrootkit_report": "Not Included",
  "rkhunter_report": "Not Included",
  "firewall_status": $UFW,
  "disk_partitions": $PARTITIONS,
  "installed_hotfixes": $HOTFIX,
  "cve_patches": $CVE_LOGS,
  "kernel_security": $KERNEL_SEC,
  "kernel_upgrades": $UPGRADES,
  "installed_software": $SOFTWARE,
  "java_version": $JAVA,
  "python_packages": $PIP,
  "docker_images": $DOCKER,
  "system_logs": $SYSLOG,
  "users": $USERS,
  "linpeas": $LINPEAS_RESULT,
  "mitre_matches": $MITRE_MATCHES
}
EOF
)

echo "$JSON" > "$TMPFILE"
echo "[DEBUG] JSON saved to $TMPFILE"

jq . "$TMPFILE" >/dev/null || {
  echo "[ERROR] JSON is not valid. Aborting."
  exit 1
}

gzip -n -c "$TMPFILE" > "$TMPGZ" || {
  echo "[ERROR] Failed to gzip payload."
  exit 1
}

FILESIZE=$(stat -c%s "$TMPGZ" 2>/dev/null || echo 0)
echo "[DEBUG] Gzip-compressed to $TMPGZ (size: ${FILESIZE} bytes)"

RESPONSE=$(curl --max-time 10 -s -o /dev/null -w "%{http_code}" -X POST "$MCP_URL" \
     -H "Content-Type: application/json" \
     -H "Content-Encoding: gzip" \
     --data-binary "@$TMPGZ")

if [ "$RESPONSE" == "200" ]; then
  echo "[INFO] Upload successful to MCP ($MCP_URL)"
else
  echo "[ERROR] Upload failed! HTTP CODE: $RESPONSE"
  cp "$TMPFILE" ~/last_failed_payload.json
fi
