#!/usr/bin/env bash
# collector_docker.sh — Container snapshot (Docker), remediation-free
set -euo pipefail
mkdir -p ./out
OUT="./out/docker_snapshot.json"
TS="$(date -Iseconds)"

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

IMAGES="$(cmd_out "docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}} {{{{.ID}}}}' | head -n 200" 8)"
CONTAINERS="$(cmd_out "docker ps -a --format '{{{{.ID}}}} {{{{.Image}}}} {{{{.Status}}}}' | head -n 200" 8)"
INSPECT="$(cmd_out "for c in $(docker ps -q); do docker inspect $c | jq -c .[]; done | head -n 50" 15)"

cat > "$OUT" <<JSON
{
  "timestamp": "$TS",
  "docker_images_top200": "$IMAGES",
  "docker_containers_top200": "$CONTAINERS",
  "docker_inspect_top50": "$INSPECT"
}
JSON

echo "[INFO] Docker snapshot written to $OUT"
