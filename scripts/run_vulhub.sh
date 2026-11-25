#!/usr/bin/env bash
# ============================================================================
# run_vulhub.sh — Run a vulhub environment against VAPT-AI
#
# Usage:
#   ./scripts/run_vulhub.sh deploy flask/ssti 8002
#   ./scripts/run_vulhub.sh run flask/ssti 8002
#   ./scripts/run_vulhub.sh teardown flask/ssti
#   ./scripts/run_vulhub.sh full flask/ssti 8002   # deploy + run + collect
# ============================================================================
set -euo pipefail

API="http://localhost:8000"
COOKIE_FILE="$HOME/.vapt_cookie"
VULHUB_ROOT="$HOME/vulhub"
RESULTS_DIR="./vulhub-eval-results"
TIMEOUT=900

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

mkdir -p "$RESULTS_DIR"

# ---------------------------------------------------------------------------
deploy() {
  local env_path=$1 port=$2
  local dir="$VULHUB_ROOT/$env_path"
  [ -d "$dir" ] || { echo -e "${RED}Not found: $dir${NC}"; return 1; }

  echo -e "${CYAN}Deploying $env_path on port $port...${NC}"

  # Check if port in docker-compose matches what we want; if not, override
  local orig_port
  orig_port=$(grep -A1 "ports:" "$dir/docker-compose.yml" | grep -E '^\s+-' | head -1 | tr -d ' "' | sed 's/^-//')

  cd "$dir"
  if echo "$orig_port" | grep -qE "^(127\.0\.0\.1:)?${port}:"; then
    docker compose up -d
  else
    # Override the port mapping
    local container_port
    container_port=$(echo "$orig_port" | rev | cut -d: -f1 | rev)
    PORT_OVERRIDE="$port:$container_port" docker compose -f docker-compose.yml up -d \
      2>/dev/null || {
      # Fallback: use sed to temporarily adjust
      echo -e "${YELLOW}Port override failed, using compose as-is${NC}"
      docker compose up -d
    }
  fi
  cd - > /dev/null

  # Wait for the service
  echo -n "  Waiting for http://localhost:$port "
  for i in $(seq 1 30); do
    if curl -s -o /dev/null -w '%{http_code}' "http://localhost:$port" 2>/dev/null | grep -qE '^[2345]'; then
      echo -e " ${GREEN}UP${NC}"
      return 0
    fi
    echo -n "."
    sleep 2
  done
  echo -e " ${YELLOW}timeout (may still be starting)${NC}"
}

# ---------------------------------------------------------------------------
teardown() {
  local env_path=$1
  local dir="$VULHUB_ROOT/$env_path"
  echo -e "${CYAN}Tearing down $env_path...${NC}"
  cd "$dir" && docker compose down -v 2>/dev/null; cd - > /dev/null
  echo -e "${GREEN}Done${NC}"
}

# ---------------------------------------------------------------------------
create_engagement() {
  local env_path=$1 port=$2
  local url="http://localhost:$port"
  local name="Vulhub: $env_path"

  local body
  body="{\"name\":\"$name\",\"testing_mode\":\"black_box\",\"target_type\":\"web\",\"target_description\":\"Vulhub $env_path on $url\",\"scope\":{\"domains\":[\"localhost\"],\"ip_cidrs\":[\"127.0.0.1/32\"],\"url_paths\":[\"$url\"],\"exclusions\":[],\"allowed_ports\":\"$port\",\"allowed_action_classes\":[\"p0_passive\",\"p1_low_impact\",\"p2_intrusive\"],\"allow_exploitation\":true,\"poc_playbook\":\"http_evidence\",\"data_sensitivity\":\"standard\"}}"

  local resp
  resp=$(curl -s -b "$COOKIE_FILE" "$API/api/v2/engagements" \
    -H "Content-Type: application/json" -d "$body")

  local eng_id
  eng_id=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)
  if [ -n "$eng_id" ]; then
    echo "$eng_id"
  else
    echo -e "${RED}Failed to create engagement: $resp${NC}" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
create_run() {
  local eng_id=$1
  local body="{\"engagement_id\":\"$eng_id\",\"auto_approve\":true}"
  local resp
  resp=$(curl -s -b "$COOKIE_FILE" "$API/api/v2/runs" \
    -H "Content-Type: application/json" -d "$body")
  local run_id
  run_id=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)
  if [ -n "$run_id" ]; then
    echo "$run_id"
  else
    echo -e "${RED}Failed to create run: $resp${NC}" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
poll_run() {
  local run_id=$1
  local start=$SECONDS
  while [ $(( SECONDS - start )) -lt $TIMEOUT ]; do
    local status
    status=$(curl -s -b "$COOKIE_FILE" "$API/api/v2/runs/$run_id" | \
      python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
    case "$status" in
      completed|failed|cancelled) echo "$status"; return 0 ;;
    esac
    echo -n "."
    sleep 10
  done
  echo "timeout"
}

# ---------------------------------------------------------------------------
get_findings() {
  local run_id=$1
  curl -s -b "$COOKIE_FILE" "$API/api/v2/runs/$run_id/findings"
}

get_findings_count() {
  local run_id=$1
  get_findings "$run_id" | python3 -I -c "
import sys, json
data = json.load(sys.stdin)
items = data if isinstance(data, list) else data.get('items', [])
total = len(items)
confirmed = sum(1 for f in items if f.get('status') == 'confirmed')
print(f'{total} {confirmed}')
" 2>/dev/null || echo "0 0"
}

get_events() {
  local run_id=$1
  curl -s -b "$COOKIE_FILE" "$API/api/v2/runs/$run_id/events?after_seq=0"
}

# ---------------------------------------------------------------------------
run_scan() {
  local env_path=$1 port=$2

  echo -e "${CYAN}Creating engagement for $env_path...${NC}"
  local eng_id
  eng_id=$(create_engagement "$env_path" "$port") || return 1
  echo -e "  Engagement: $eng_id"

  echo -e "  Creating auto-approve run..."
  local run_id
  run_id=$(create_run "$eng_id") || return 1
  echo -e "  Run: $run_id"

  echo -e "  Waiting for completion (timeout ${TIMEOUT}s)..."
  local status
  status=$(poll_run "$run_id")
  echo -e "\n  Status: $status"

  local fc
  fc=$(get_findings_count "$run_id")
  local total confirmed
  total=$(echo "$fc" | cut -d' ' -f1)
  confirmed=$(echo "$fc" | cut -d' ' -f2)
  echo -e "  Findings: ${GREEN}$confirmed confirmed${NC} / $total total"

  # Grade
  local grade
  if [ "$status" == "timeout" ]; then
    grade="TIMEOUT"
  elif [ "$confirmed" -gt 0 ] 2>/dev/null; then
    grade="PASS"
  elif [ "$total" -gt 0 ] 2>/dev/null; then
    grade="PARTIAL"
  else
    grade="FAIL"
  fi

  local elapsed=$(( SECONDS ))

  # Save result
  local result_file="$RESULTS_DIR/$(echo "$env_path" | tr '/' '_').json"
  cat > "$result_file" <<EOJSON
{
  "vulhub_env": "$env_path",
  "grade": "$grade",
  "run_status": "$status",
  "findings_count": $total,
  "confirmed_count": $confirmed,
  "elapsed_s": $elapsed,
  "run_id": "$run_id",
  "engagement_id": "$eng_id",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOJSON

  echo -e "\n${CYAN}Result: ${GREEN}$grade${NC} → $result_file"
  echo -e "  Run ID: $run_id"
  echo -e "  Engagement ID: $eng_id"
}

# ---------------------------------------------------------------------------
full() {
  local env_path=$1 port=$2
  deploy "$env_path" "$port" || return 1
  run_scan "$env_path" "$port"
  echo -e "\n${YELLOW}Teardown with: $0 teardown $env_path${NC}"
}

# ---------------------------------------------------------------------------
case "${1:-help}" in
  deploy)   deploy "$2" "$3" ;;
  run)      run_scan "$2" "$3" ;;
  teardown) teardown "$2" ;;
  full)     full "$2" "$3" ;;
  *)
    echo "Usage: $0 {deploy|run|teardown|full} <env_path> [port]"
    echo "  deploy   flask/ssti 8002   - Start the vulhub environment"
    echo "  run      flask/ssti 8002   - Run VAPT-AI scan against it"
    echo "  teardown flask/ssti        - Stop and remove containers"
    echo "  full     flask/ssti 8002   - Deploy + scan + report"
    ;;
esac
