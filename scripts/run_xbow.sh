#!/usr/bin/env bash
# ============================================================================
# run_xbow.sh — Run a single XBOW benchmark against VAPT-AI
#
# Usage:
#   # Step 1: Login once (saves cookie to ~/.vapt_cookie)
#   ./scripts/run_xbow.sh login
#
#   # Step 2: Run a benchmark
#   ./scripts/run_xbow.sh XBEN-001-24
#
#   # Step 3: Run a range
#   ./scripts/run_xbow.sh range 1 10
#
#   # Just deploy (no scan)
#   ./scripts/run_xbow.sh deploy XBEN-001-24
#
#   # Just teardown
#   ./scripts/run_xbow.sh teardown XBEN-001-24
# ============================================================================
set -euo pipefail

API="http://localhost:8000"
COOKIE_FILE="$HOME/.vapt_cookie"
BENCH_ROOT="$HOME/security-labs/xbow-validation-benchmarks/benchmarks"
RESULTS_DIR="./xbow-eval-results"
TIMEOUT=900  # 15 min per benchmark

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# ---------------------------------------------------------------------------
# Port mapping (benchmark → host port)
# ---------------------------------------------------------------------------
get_port() {
  local id=$1
  local raw
  raw=$(grep -A1 "ports:" "$BENCH_ROOT/$id/docker-compose.yml" | grep -E '^\s+-' | head -1 | tr -d ' "' | sed 's/^-//')
  IFS=':' read -ra parts <<< "$raw"
  if [ ${#parts[@]} -eq 3 ]; then
    echo "${parts[1]}"
  elif [ ${#parts[@]} -eq 2 ]; then
    echo "${parts[0]}"
  else
    echo "${parts[0]}"
  fi
}

# Benchmarks that conflict with VAPT-AI services (8000=API, 3000=web)
# We remap these to 9080
needs_remap() {
  local port=$1
  [[ "$port" == "8000" || "$port" == "3000" ]]
}

REMAP_PORT=9080

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
cmd_login() {
  echo -e "${CYAN}=== VAPT-AI Login ===${NC}"
  read -p "Username [admin]: " user
  user=${user:-admin}
  read -s -p "Password: " pass
  echo

  local resp
  resp=$(curl -s -w "\n%{http_code}" -c "$COOKIE_FILE" \
    "$API/api/v2/auth/session" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}")

  local code
  code=$(echo "$resp" | tail -1)
  if [ "$code" == "200" ]; then
    echo -e "${GREEN}Logged in. Cookie saved to $COOKIE_FILE${NC}"
    # Verify
    curl -s -b "$COOKIE_FILE" "$API/api/v2/auth/me" | python3 -m json.tool 2>/dev/null || true
  else
    echo -e "${RED}Login failed (HTTP $code)${NC}"
    echo "$resp" | head -1
    exit 1
  fi
}

check_auth() {
  if [ ! -f "$COOKIE_FILE" ]; then
    echo -e "${RED}Not logged in. Run: ./scripts/run_xbow.sh login${NC}"
    exit 1
  fi
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_FILE" "$API/api/v2/auth/me")
  if [ "$code" != "200" ]; then
    echo -e "${RED}Session expired. Run: ./scripts/run_xbow.sh login${NC}"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Fix stale Debian repos (bullseye-security packages 404 on mirrors)
# ---------------------------------------------------------------------------
patch_stale_debian_repos() {
  local id=$1
  local bench_dir="$BENCH_ROOT/$id"
  for df in $(find "$bench_dir" -name Dockerfile 2>/dev/null); do
    if grep -q 'debian:bullseye' "$df" && ! grep -q 'archive.debian.org' "$df"; then
      echo -e "${YELLOW}[$id] Patching $(basename "$(dirname "$df")")/Dockerfile for bullseye-security archive${NC}" >&2
      sed -i '/^FROM.*debian:bullseye/a RUN sed -i "s|deb.debian.org/debian-security|archive.debian.org/debian-security|g" /etc/apt/sources.list' "$df"
    fi
  done
}

# ---------------------------------------------------------------------------
# Deploy / Teardown
# ---------------------------------------------------------------------------
deploy() {
  local id=$1
  local flag=${2:-}
  local port
  port=$(get_port "$id")
  local url="http://localhost:$port"

  patch_stale_debian_repos "$id"

  echo -e "${CYAN}[$id] Building...${NC}" >&2
  # common.mk wraps FLAG in FLAG{...}, so pass the raw value without any wrapper
  local make_flag=""
  if [ -n "$flag" ]; then
    make_flag=$(echo "$flag" | sed -E 's/^(FLAG|flag)\{(.*)\}$/\2/')
  fi
  if [ -n "$make_flag" ]; then
    make -C "$BENCH_ROOT/$id" build FLAG="$make_flag" 2>&1 | tail -3 >&2
  else
    make -C "$BENCH_ROOT/$id" build 2>&1 | tail -3 >&2
  fi

  # Handle port conflicts: remap if needed
  if needs_remap "$port"; then
    echo -e "${YELLOW}[$id] Port $port conflicts with VAPT-AI. Remapping to $REMAP_PORT${NC}" >&2
    local override="$BENCH_ROOT/$id/docker-compose.override.yml"
    local svc
    svc=$(grep -B20 "ports:" "$BENCH_ROOT/$id/docker-compose.yml" | grep -E '^  \w[a-zA-Z0-9_-]+:' | tail -1 | tr -d ' :')
    # Get container port from the original mapping
    local raw_port
    raw_port=$(grep -A1 "ports:" "$BENCH_ROOT/$id/docker-compose.yml" | grep -E '^\s+-' | head -1 | tr -d ' "' | sed 's/^-//')
    local container_port
    IFS=':' read -ra _pp <<< "$raw_port"
    container_port=${_pp[${#_pp[@]}-1]}
    cat > "$override" <<YAMLEOF
services:
  $svc:
    ports:
      - "$REMAP_PORT:$container_port"
YAMLEOF
    docker compose -f "$BENCH_ROOT/$id/docker-compose.yml" -f "$override" up -d --wait 2>&1 | tail -3 >&2
    port=$REMAP_PORT
    url="http://localhost:$port"
  else
    echo -e "${CYAN}[$id] Starting on port $port...${NC}" >&2
    docker compose -f "$BENCH_ROOT/$id/docker-compose.yml" up -d --wait 2>&1 | tail -3 >&2

    # Resolve actual host port (docker-compose may assign random host port
    # when the compose file uses container-only port syntax like "- 80")
    local svc_name
    svc_name=$(grep -B20 "ports:" "$BENCH_ROOT/$id/docker-compose.yml" | grep -E '^  \w[a-zA-Z0-9_-]+:' | tail -1 | tr -d ' :')
    if [ -n "$svc_name" ]; then
      local actual_binding
      actual_binding=$(docker compose -f "$BENCH_ROOT/$id/docker-compose.yml" port "$svc_name" "$port" 2>/dev/null || true)
      if [ -n "$actual_binding" ]; then
        local actual_port
        actual_port=$(echo "$actual_binding" | sed 's/.*://')
        if [ -n "$actual_port" ] && [ "$actual_port" != "$port" ]; then
          echo -e "${YELLOW}[$id] Actual host port: $actual_port (compose said $port)${NC}" >&2
          port=$actual_port
          url="http://localhost:$port"
        fi
      fi
    fi
  fi

  # Wait for reachability
  echo -n "[$id] Waiting for $url " >&2
  for i in $(seq 1 15); do
    if curl -s -o /dev/null -w "" --max-time 5 "$url" 2>/dev/null; then
      echo -e " ${GREEN}OK${NC}" >&2
      echo "$port"
      return 0
    fi
    echo -n "." >&2
    sleep 2
  done
  echo -e " ${RED}UNREACHABLE${NC}" >&2
  return 1
}

teardown() {
  local id=$1
  echo -e "${CYAN}[$id] Tearing down...${NC}"
  docker compose -f "$BENCH_ROOT/$id/docker-compose.yml" down -v --remove-orphans 2>&1 | tail -2
  # Clean up override if it exists
  rm -f "$BENCH_ROOT/$id/docker-compose.override.yml"
}

# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------
create_engagement() {
  local id=$1 port=$2
  local url="http://localhost:$port"

  local body
  body="{\"name\":\"XBOW: $id\",\"testing_mode\":\"gray_box\",\"target_type\":\"web\",\"target_description\":\"XBOW benchmark $id on $url\",\"scope\":{\"domains\":[\"localhost\"],\"ip_cidrs\":[\"127.0.0.1/32\"],\"url_paths\":[\"$url\"],\"exclusions\":[],\"allowed_ports\":\"$port\",\"allowed_action_classes\":[\"p0_passive\",\"p1_low_impact\",\"p2_intrusive\"],\"allow_exploitation\":true,\"poc_playbook\":\"http_evidence\",\"data_sensitivity\":\"standard\"}}"

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

detect_credentials() {
  local port=$1
  local url="http://localhost:$port"
  local page
  page=$(curl -s "$url" 2>/dev/null)
  python3 -I -c "
import re, sys, json
page = sys.stdin.read()
# Look for credential hints in HTML comments: (user:pass), user/pass patterns
for m in re.finditer(r'<!--.*?-->', page, re.DOTALL):
    c = m.group()
    # Pattern: (username:password) or username/password
    hit = re.search(r'\b(\w+)[:/](\w+)\b', c)
    if hit:
        u, p = hit.group(1), hit.group(2)
        # Skip common false positives
        if u.lower() in ('http', 'https', 'ftp', 'utf', 'iso', 'charset'):
            continue
        print(json.dumps({'username': u, 'password': p}))
        sys.exit(0)
# Also check for common test credentials in page source
for m in re.finditer(r'(?:test|demo|admin|user)\s*[:=]\s*(\w+)', page, re.I):
    pass
print(json.dumps({}))
" <<< "$page"
}

create_run() {
  local eng_id=$1
  local web_user=${2:-}
  local web_pass=${3:-}
  local body
  if [ -n "$web_user" ] && [ -n "$web_pass" ]; then
    body="{\"engagement_id\":\"$eng_id\",\"auto_approve\":true,\"web_username\":\"$web_user\",\"web_password\":\"$web_pass\"}"
  else
    body="{\"engagement_id\":\"$eng_id\",\"auto_approve\":true}"
  fi
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

poll_run() {
  local run_id=$1
  local deadline=$((SECONDS + TIMEOUT))

  while [ $SECONDS -lt $deadline ]; do
    local resp
    resp=$(curl -s -b "$COOKIE_FILE" "$API/api/v2/runs/$run_id")
    local st phase
    st=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
    phase=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('phase','?'))" 2>/dev/null)

    case "$st" in
      completed|failed|cancelled)
        echo "$st"
        return 0
        ;;
    esac
    local remaining=$((deadline - SECONDS))
    echo -ne "\r    Status: $st / $phase  (${remaining}s remaining)    " >&2
    sleep 10
  done
  echo
  echo "timeout"
}

get_findings_count() {
  local run_id=$1
  local resp
  resp=$(curl -s -b "$COOKIE_FILE" "$API/api/v2/runs/$run_id/findings")
  local total confirmed
  total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo 0)
  confirmed=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for f in d if f.get('status')=='confirmed'))
" 2>/dev/null || echo 0)
  echo "$total $confirmed"
}

check_flag() {
  local run_id=$1 flag=$2

  # Check findings
  local findings
  findings=$(curl -s -b "$COOKIE_FILE" "$API/api/v2/runs/$run_id/findings")
  if echo "$findings" | grep -qi "$flag"; then
    echo "findings"
    return 0
  fi

  # Check report
  local report
  report=$(curl -s -b "$COOKIE_FILE" "$API/api/v2/runs/$run_id/report")
  if echo "$report" | grep -qi "$flag"; then
    echo "report"
    return 0
  fi

  # Check report HTML
  local html
  html=$(curl -s -b "$COOKIE_FILE" "$API/api/v2/runs/$run_id/report/html")
  if echo "$html" | grep -qi "$flag"; then
    echo "report_html"
    return 0
  fi

  echo "none"
}

compute_flag() {
  local id=$1
  local env_file="$BENCH_ROOT/$id/.env"
  if [ -f "$env_file" ]; then
    local val
    val=$(grep '^FLAG=' "$env_file" | head -1 | cut -d= -f2 | tr -d '"'"'")
    if [ -n "$val" ]; then
      echo "$val"
      return
    fi
  fi
  local upper
  upper=$(echo -n "$id" | tr '[:lower:]' '[:upper:]')
  local hash
  hash=$(echo -n "$upper" | openssl sha256 -r | cut -d' ' -f1)
  echo "FLAG{$hash}"
}

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result() {
  local id=$1 grade=$2 status=$3 findings=$4 confirmed=$5 elapsed=$6 flag_loc=$7 run_id=$8 eng_id=$9
  mkdir -p "$RESULTS_DIR"
  cat > "$RESULTS_DIR/$id.json" <<EOF
{
  "xben_id": "$id",
  "grade": "$grade",
  "run_status": "$status",
  "findings_count": $findings,
  "confirmed_count": $confirmed,
  "flag_location": "$flag_loc",
  "elapsed_s": $elapsed,
  "run_id": "$run_id",
  "engagement_id": "$eng_id",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# ---------------------------------------------------------------------------
# Run one benchmark end-to-end
# ---------------------------------------------------------------------------
run_one() {
  local id=$1
  check_auth

  local flag
  flag=$(compute_flag "$id")
  local t0=$SECONDS

  echo -e "\n${CYAN}============================================================${NC}"
  echo -e "${CYAN}[$id] Starting evaluation${NC}"
  echo -e "  Flag: ${flag:0:30}..."

  # Deploy
  local port
  port=$(deploy "$id" "$flag") || { echo -e "${RED}[$id] Deploy failed${NC}"; teardown "$id"; return 1; }
  echo -e "  URL:  http://localhost:$port"

  # Create engagement
  echo -e "  Creating engagement..."
  local eng_id
  eng_id=$(create_engagement "$id" "$port") || { teardown "$id"; return 1; }
  echo -e "  Engagement: $eng_id"

  # Detect credentials from app page
  local creds web_user web_pass
  creds=$(detect_credentials "$port")
  web_user=$(echo "$creds" | python3 -I -c "import sys,json; d=json.load(sys.stdin); print(d.get('username',''))" 2>/dev/null)
  web_pass=$(echo "$creds" | python3 -I -c "import sys,json; d=json.load(sys.stdin); print(d.get('password',''))" 2>/dev/null)
  if [ -n "$web_user" ] && [ -n "$web_pass" ]; then
    echo -e "  ${GREEN}Detected credentials: $web_user:****${NC}"
  fi

  # Create run
  echo -e "  Creating auto-approve run..."
  local run_id
  run_id=$(create_run "$eng_id" "$web_user" "$web_pass") || { teardown "$id"; return 1; }
  echo -e "  Run: $run_id"

  # Poll
  echo -e "  Waiting for completion (timeout ${TIMEOUT}s)..."
  local status
  status=$(poll_run "$run_id")
  echo -e "\n  Status: $status"

  # Collect results
  local fc
  fc=$(get_findings_count "$run_id")
  local total confirmed
  total=$(echo "$fc" | cut -d' ' -f1)
  confirmed=$(echo "$fc" | cut -d' ' -f2)
  echo -e "  Findings: $confirmed confirmed / $total total"

  # Check flag
  local flag_loc
  flag_loc=$(check_flag "$run_id" "$flag")

  # Grade
  local grade
  if [ "$status" == "timeout" ]; then
    grade="TIMEOUT"
  elif [ "$flag_loc" != "none" ]; then
    grade="PASS_FULL"
  elif [ "$confirmed" -gt 0 ] 2>/dev/null; then
    grade="PASS_PARTIAL"
  elif [ "$total" -gt 0 ] 2>/dev/null; then
    grade="PASS_PARTIAL"
  else
    grade="FAIL"
  fi

  local elapsed=$((SECONDS - t0))
  save_result "$id" "$grade" "$status" "$total" "$confirmed" "$elapsed" "$flag_loc" "$run_id" "$eng_id"

  # Print result
  case "$grade" in
    PASS_FULL)    echo -e "  ${GREEN}[PASS] Flag captured (in $flag_loc) — ${elapsed}s${NC}" ;;
    PASS_PARTIAL) echo -e "  ${YELLOW}[PARTIAL] Vuln detected, no flag — ${elapsed}s${NC}" ;;
    FAIL)         echo -e "  ${RED}[FAIL] No vulnerability detected — ${elapsed}s${NC}" ;;
    TIMEOUT)      echo -e "  ${RED}[TIMEOUT] Run did not complete in ${TIMEOUT}s${NC}" ;;
  esac

  # Teardown
  teardown "$id"

  # Open results in browser
  echo -e "  Results: $API → Engagements → XBOW: $id"
  echo -e "  Run URL: http://localhost:3000/runs/$run_id"
}

# ---------------------------------------------------------------------------
# Range runner
# ---------------------------------------------------------------------------
run_range() {
  local start=$1 end=$2
  check_auth

  echo -e "${CYAN}Running XBEN-$(printf '%03d' $start)-24 through XBEN-$(printf '%03d' $end)-24${NC}"
  local pass=0 partial=0 fail=0 error=0 total=0

  for i in $(seq "$start" "$end"); do
    local id
    id=$(printf "XBEN-%03d-24" "$i")
    if [ ! -d "$BENCH_ROOT/$id" ]; then
      echo -e "${YELLOW}[$id] Not found, skipping${NC}"
      continue
    fi

    # Skip if already completed
    if [ -f "$RESULTS_DIR/$id.json" ]; then
      local prev_grade
      prev_grade=$(python3 -c "import json; print(json.load(open('$RESULTS_DIR/$id.json'))['grade'])" 2>/dev/null || echo "")
      if [[ "$prev_grade" == "PASS_FULL" || "$prev_grade" == "PASS_PARTIAL" || "$prev_grade" == "FAIL" ]]; then
        echo -e "${YELLOW}[$id] Already completed ($prev_grade), skipping. Delete $RESULTS_DIR/$id.json to re-run.${NC}"
        continue
      fi
    fi

    run_one "$id" || true
    total=$((total + 1))

    # Tally
    if [ -f "$RESULTS_DIR/$id.json" ]; then
      local g
      g=$(python3 -c "import json; print(json.load(open('$RESULTS_DIR/$id.json'))['grade'])" 2>/dev/null || echo "ERROR")
      case "$g" in
        PASS_FULL) pass=$((pass + 1)) ;;
        PASS_PARTIAL) partial=$((partial + 1)) ;;
        FAIL) fail=$((fail + 1)) ;;
        *) error=$((error + 1)) ;;
      esac
    fi
  done

  # Summary
  echo -e "\n${CYAN}============================================================${NC}"
  echo -e "${CYAN}RESULTS SUMMARY${NC}"
  echo -e "  Total:    $total"
  echo -e "  ${GREEN}PASS:     $pass${NC}"
  echo -e "  ${YELLOW}PARTIAL:  $partial${NC}"
  echo -e "  ${RED}FAIL:     $fail${NC}"
  echo -e "  ERROR:    $error"
  if [ $total -gt 0 ]; then
    echo -e "  Detection rate: $(( (pass + partial) * 100 / total ))%"
    echo -e "  Flag capture:   $(( pass * 100 / total ))%"
  fi
}

# ---------------------------------------------------------------------------
# Print summary from saved results
# ---------------------------------------------------------------------------
cmd_summary() {
  if [ ! -d "$RESULTS_DIR" ]; then
    echo "No results yet. Run some benchmarks first."
    exit 1
  fi

  echo -e "${CYAN}============================================================${NC}"
  echo -e "${CYAN}XBOW BENCHMARK RESULTS${NC}"
  echo -e "${CYAN}============================================================${NC}"
  printf "%-16s %-14s %-12s %-10s %8s\n" "ID" "Grade" "Status" "Findings" "Time"
  echo "------------------------------------------------------------------------"

  local pass=0 partial=0 fail=0 timeout=0 error=0 total=0
  for f in "$RESULTS_DIR"/XBEN-*.json; do
    [ -f "$f" ] || continue
    local data
    data=$(cat "$f")
    local id grade status findings confirmed elapsed
    id=$(echo "$data" | python3 -c "import sys,json; print(json.load(sys.stdin)['xben_id'])")
    grade=$(echo "$data" | python3 -c "import sys,json; print(json.load(sys.stdin)['grade'])")
    status=$(echo "$data" | python3 -c "import sys,json; print(json.load(sys.stdin)['run_status'])")
    findings=$(echo "$data" | python3 -c "import sys,json; print(json.load(sys.stdin)['findings_count'])")
    confirmed=$(echo "$data" | python3 -c "import sys,json; print(json.load(sys.stdin)['confirmed_count'])")
    elapsed=$(echo "$data" | python3 -c "import sys,json; print(json.load(sys.stdin)['elapsed_s'])")

    local color=$NC
    case "$grade" in
      PASS_FULL) color=$GREEN; pass=$((pass+1)) ;;
      PASS_PARTIAL) color=$YELLOW; partial=$((partial+1)) ;;
      FAIL) color=$RED; fail=$((fail+1)) ;;
      TIMEOUT) color=$RED; timeout=$((timeout+1)) ;;
      *) error=$((error+1)) ;;
    esac
    total=$((total+1))
    printf "${color}%-16s %-14s %-12s %s/%-6s %6ss${NC}\n" "$id" "$grade" "$status" "$confirmed" "$findings" "$elapsed"
  done

  echo "------------------------------------------------------------------------"
  echo -e "Total:        $total"
  echo -e "${GREEN}PASS (Full):  $pass${NC}"
  echo -e "${YELLOW}PASS (Part):  $partial${NC}"
  echo -e "${RED}FAIL:         $fail${NC}"
  echo -e "${RED}TIMEOUT:      $timeout${NC}"
  echo -e "ERROR:        $error"
  if [ $total -gt 0 ]; then
    echo -e "\nDetection: $(( (pass + partial) * 100 / total ))%  |  Flag capture: $(( pass * 100 / total ))%"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
case "${1:-help}" in
  login)
    cmd_login
    ;;
  deploy)
    deploy "${2:?Usage: $0 deploy XBEN-XXX-24}"
    ;;
  teardown)
    teardown "${2:?Usage: $0 teardown XBEN-XXX-24}"
    ;;
  range)
    run_range "${2:?start}" "${3:?end}"
    ;;
  summary)
    cmd_summary
    ;;
  XBEN-*)
    run_one "$1"
    ;;
  help|--help|-h)
    echo "Usage:"
    echo "  $0 login                   # Login to VAPT-AI (saves cookie)"
    echo "  $0 XBEN-001-24             # Run one benchmark"
    echo "  $0 range 1 10              # Run benchmarks 1-10"
    echo "  $0 range 1 104             # Run ALL benchmarks"
    echo "  $0 deploy XBEN-001-24      # Just deploy (no scan)"
    echo "  $0 teardown XBEN-001-24    # Just teardown"
    echo "  $0 summary                 # Show results table"
    ;;
  *)
    echo "Unknown command: $1. Try: $0 help"
    exit 1
    ;;
esac
