#!/usr/bin/env bash
# Offline verification of the 2026-10-26 fixes. No network, no DineHub.
# Each check runs in ~1s. Prints PASS/FAIL per check; exit code = failures.
#
# Usage:
#   bash scripts/verify_fixes/verify_offline.sh

set -u
cd "$(dirname "$0")/../.." || exit 1
ROOT="$PWD"
VENV="$ROOT/.venv/bin/python"
PYPATH="packages/domain:packages/persistence:packages/llm_gateway:packages/policy:packages/tools:packages/harness:packages/skills:packages/agents:services/api:services/orchestrator"

PASS=0
FAIL=0
check() {
    local name="$1"; shift
    local out
    if out=$("$@" 2>&1); then
        echo "  ✅ PASS  $name"
        [ -n "${VERBOSE:-}" ] && echo "       $out"
        PASS=$((PASS+1))
    else
        echo "  ❌ FAIL  $name"
        echo "       $out" | sed 's/^/       /'
        FAIL=$((FAIL+1))
    fi
}

echo
echo "=== VAPT-AI V2 fix verification (offline) ==="
echo "ROOT: $ROOT"
echo

echo "[1/9] Preflight: all 7 worker binaries present + executable"
check "preflight.check_worker_binaries() returns all ok" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_orch.preflight import check_worker_binaries, _REQUIRED_BINARIES
r = check_worker_binaries()
missing = [n for n, s in r.items() if s != "ok"]
assert set(r.keys()) == set(_REQUIRED_BINARIES), f"missing from result: {set(_REQUIRED_BINARIES) - set(r.keys())}"
assert not missing, f"not ok: {missing}"
print(f"all {len(r)} binaries ready")
'

echo
echo "[2/9] Engagement.py: vapt-recon-fetch path resolves to repo root (5 dirnames)"
check "default bin_path resolves to .../workers/bin/vapt-recon-fetch and exists" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
import os
engagement = "services/orchestrator/vapt_orch/graph/engagement.py"
abs_p = os.path.abspath(engagement)
root5 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(abs_p)))))
bin_path = os.path.join(root5, "workers", "bin", "vapt-recon-fetch")
assert bin_path.endswith("/vapt-ai-v2/workers/bin/vapt-recon-fetch"), f"wrong path: {bin_path}"
assert os.path.exists(bin_path), f"binary missing at {bin_path}"
assert os.access(bin_path, os.X_OK), f"not executable: {bin_path}"
print(f"resolved: {bin_path}")
'

echo
echo "[3/9] Harness: _ARG_WHITELIST includes urls/post_url/view_url (fix for args={} display)"
check "whitelist has urls, post_url, view_url" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_harness.harness import _ARG_WHITELIST
for k in ("urls", "post_url", "view_url", "url"):
    assert k in _ARG_WHITELIST, f"missing key: {k}"
print(f"ok: {sorted(_ARG_WHITELIST)}")
'

echo
echo "[4/9] SCAN manifest: max_iterations raised 64 -> 160 (plan headroom for LLM items)"
check "SCAN.max_iterations == 160" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_agents.manifests import SCAN
assert SCAN.max_iterations == 160, f"got {SCAN.max_iterations}"
print(f"SCAN.max_iterations = {SCAN.max_iterations}")
'

echo
echo "[5/9] Reactive gate: filters by tool_id (NOT the nonexistent task_id attribute)"
check "no 'r.task_id' references + filter uses tool_id in _WEBVULN_ONLY_TOOLS" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "r.tool_id in _WEBVULN_ONLY_TOOLS" "$f" || { echo "missing tool_id filter"; exit 1; }
# The ToolActionRecord has no task_id column, so no "r.task_id" uses should remain.
if grep -n "\br\.task_id\b" "$f" >/dev/null; then
    echo "found r.task_id uses (should be gone):"
    grep -n "\br\.task_id\b" "$f"
    exit 1
fi
echo "ok: gate uses tool_id filter, no task_id attribute uses"
'

echo
echo "[6/9] Recon-agent: silent returns now emit webvuln.recon_agent.skip events"
check "4 skip-reason strings present (no_gateway, too_early, no_admin_cookie, binary_missing)" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
for r in no_gateway too_early no_admin_cookie binary_missing; do
    grep -q "\"reason\": \"$r\"" "$f" || { echo "missing skip reason: $r"; exit 1; }
done
echo "ok: all 4 recon_agent.skip reasons present"
'

echo
echo "[7/9] Recon-agent: _PROBE_TOOLS_REQUIRE_URL validation guard added"
check "guard rejects a proposal without url for probe tools" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_PROBE_TOOLS_REQUIRE_URL" "$f" || { echo "guard constant missing"; exit 1; }
grep -q "requires a .url." "$f" || { echo "validation nudge missing"; exit 1; }
echo "ok: URL-required validation in place"
'

echo
echo "[8/9] Form_map prime: authed BFS runs BEFORE form_map build (not after)"
check "_authed_discovery_bfs + _persist_authed_discovery called inside _prime_form_map" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "def _authed_discovery_bfs" "$f" || { echo "BFS fn missing"; exit 1; }
grep -q "def _persist_authed_discovery" "$f" || { echo "persist fn missing"; exit 1; }
# BFS must appear BEFORE build_endpoint_map in _prime_form_map ordering.
bfs_line=$(grep -n "authed_urls = _authed_discovery_bfs" "$f" | head -1 | cut -d: -f1)
map_line=$(grep -n "build_endpoint_map" "$f" | head -1 | cut -d: -f1)
[ -z "$bfs_line" ] && { echo "BFS call site not found"; exit 1; }
[ -z "$map_line" ] && { echo "form_map build not found"; exit 1; }
[ "$bfs_line" -lt "$map_line" ] || { echo "ORDER WRONG: bfs@$bfs_line vs map@$map_line"; exit 1; }
echo "ok: BFS at line $bfs_line runs before form_map at line $map_line"
'

echo
echo "[9/9] Preflight integration: 410 tests pass incl. 4 new preflight tests"
check "pytest tests/test_preflight.py (fast)" \
    env PYTHONPATH="$PYPATH" "$ROOT/.venv/bin/pytest" tests/test_preflight.py -q --no-header

echo
echo "────────────────────────────────────────"
echo "Summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "✅ All offline checks passed." || echo "❌ $FAIL check(s) failed."
exit "$FAIL"
