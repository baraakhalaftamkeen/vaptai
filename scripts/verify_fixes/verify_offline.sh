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
echo "[4/9] SCAN manifest: max_iterations >= 300 (plan headroom for LLM items + big probe tiers)"
check "SCAN.max_iterations >= 300" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_agents.manifests import SCAN, VALIDATE
assert SCAN.max_iterations >= 300, f"got SCAN.max_iterations={SCAN.max_iterations}"
assert VALIDATE.max_iterations >= 48, f"got VALIDATE.max_iterations={VALIDATE.max_iterations}"
print(f"SCAN.max_iterations = {SCAN.max_iterations}, VALIDATE.max_iterations = {VALIDATE.max_iterations}")
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
# 2026-10-28: validation nudge was rewritten to show the model its bad
# step + a corrected example. The exact fragment changed from "requires
# a `url`" to the longer "The top-level `url` field is REQUIRED" via
# _reject_with_fix. Accept EITHER wording so the check is stable across
# refactors.
grep -qE "(requires a .url.|top-level .url. field is REQUIRED)" "$f" \
    || { echo "validation nudge missing"; exit 1; }
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
echo "[9/13] Preflight integration: 410 tests pass incl. 4 new preflight tests"
check "pytest tests/test_preflight.py (fast)" \
    env PYTHONPATH="$PYPATH" "$ROOT/.venv/bin/pytest" tests/test_preflight.py -q --no-header

echo
echo "[10/13] Fix 1: B+C logins fire inside _prime_form_map (IDOR unblock)"
check "webvuln.authenticated_b + _c ledger events wired in _prime_form_map" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "webvuln.authenticated_b" "$f" || { echo "authenticated_b event missing"; exit 1; }
grep -q "webvuln.authenticated_c" "$f" || { echo "authenticated_c event missing"; exit 1; }
# Both logins must be INSIDE _prime_form_map, not _ensure_cookie.
line_b=$(grep -n "webvuln.authenticated_b" "$f" | head -1 | cut -d: -f1)
line_c=$(grep -n "webvuln.authenticated_c" "$f" | head -1 | cut -d: -f1)
line_prime=$(grep -n "def _prime_form_map" "$f" | head -1 | cut -d: -f1)
line_llm_sch=$(grep -n "_LLM_WEBVULN_SCHEMA" "$f" | head -1 | cut -d: -f1)
# authenticated_b/_c should appear BEFORE _LLM_WEBVULN_SCHEMA (which is right after _prime_form_map).
[ -n "$line_b" ] && [ "$line_b" -gt "$line_prime" ] && [ "$line_b" -lt "$line_llm_sch" ] \
  || { echo "B login not inside _prime_form_map (b@$line_b, prime@$line_prime, schema@$line_llm_sch)"; exit 1; }
[ -n "$line_c" ] && [ "$line_c" -gt "$line_prime" ] && [ "$line_c" -lt "$line_llm_sch" ] \
  || { echo "C login not inside _prime_form_map"; exit 1; }
echo "ok: B+C logins at lines $line_b, $line_c inside _prime_form_map (lines $line_prime..$line_llm_sch)"
'

echo
echo "[11/13] Fix 2: recon-agent emits webvuln.recon_agent.turn_error + force-propose nudge"
check "_log_turn_error helper + FORCE_PROPOSE_AFTER constant present" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "def _log_turn_error" "$f" || { echo "_log_turn_error helper missing"; exit 1; }
grep -q "FORCE_PROPOSE_AFTER" "$f" || { echo "FORCE_PROPOSE_AFTER constant missing"; exit 1; }
grep -q "webvuln.recon_agent.turn_error" "$f" || { echo "turn_error event name missing"; exit 1; }
# At least 5 call sites to _log_turn_error (one per rejection path).
n=$(grep -c "_log_turn_error(" "$f")
[ "$n" -ge 5 ] || { echo "only $n _log_turn_error calls (expected >=5)"; exit 1; }
echo "ok: turn_error wired at $n rejection sites + force-propose nudge in fetch block"
'

echo
echo "[12/13] Fix 3: Jinja2-textarea SSTI retry tier (level=5) wired in _webvuln_plan"
check "webvuln-ssti-retry task_id prefix + level=5 retry guard present" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "webvuln-ssti-retry-" "$f" || { echo "ssti-retry task_id missing"; exit 1; }
grep -q "jinja2.*twig.*mako" "$f" || grep -q "jinja2\", \"twig" "$f" \
  || { echo "Jinja2 engine guard missing"; exit 1; }
echo "ok: Fix 3 SSTI retry tier present"
'

echo
echo "[13/15] Fix 4: gateway.invoke retry + exponential backoff"
check "_TRANSIENT_HINTS + _BACKOFF_S + gateway.retry ledger event" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_TRANSIENT_HINTS" "$f" || { echo "_TRANSIENT_HINTS missing"; exit 1; }
grep -q "_BACKOFF_S = " "$f" || { echo "_BACKOFF_S constant missing"; exit 1; }
grep -q "\"gateway.retry\"" "$f" || { echo "gateway.retry ledger event missing"; exit 1; }
echo "ok: Fix 4 retry logic present"
'

echo
echo "[14/15] Cross-run memory: phases.engagement_prior_findings helper"
check "helper + summarizer present + unit tests pass" \
    bash -c '
f=packages/agents/vapt_agents/phases.py
grep -q "^def engagement_prior_findings" "$f" || { echo "helper missing"; exit 1; }
grep -q "^def summarize_prior_findings_for_llm" "$f" || { echo "summarizer missing"; exit 1; }
grep -q "^def _normalize_finding_title" "$f" || { echo "normalizer missing"; exit 1; }
echo "ok: helper + summarizer + normalizer present"
' && \
check "pytest tests/test_prior_findings.py (10 tests)" \
    env PYTHONPATH="$PYPATH" "$ROOT/.venv/bin/pytest" tests/test_prior_findings.py -q --no-header

echo
echo "[15/16] Cross-run memory: wired into 3 LLM stages + ledger event"
check "prior-findings cache + ledger event + 3 prompt-injection sites" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_prior_findings_by_run" "$f" || { echo "run-scoped cache missing"; exit 1; }
grep -q "\"engagement.prior_findings_loaded\"" "$f" || { echo "ledger event missing"; exit 1; }
# Count prompt-injection sites — summarize_prior_findings_for_llm should be called
# from all 3 LLM stages (primary, reactive, recon-agent).
n=$(grep -c "summarize_prior_findings_for_llm" "$f")
[ "$n" -ge 3 ] || { echo "only $n prior-findings prompt injections (expected >=3)"; exit 1; }
echo "ok: cache + ledger event + $n prompt injections across LLM stages"
'

echo
echo "[16/18] wayBackLister: wrapper + upstream + catalog registration"
check "upstream script + wrapper +x + catalog entry + registry resolvable" \
    bash -c '
# Upstream script present
up="${VAPT_WAYBACKLISTER_SCRIPT:-/home/pt-team/tools/wayBackLister/waybacklister.py}"
[ -f "$up" ] || { echo "upstream script missing at $up (clone from github.com/anmolksachan/wayBackLister)"; exit 1; }
# Wrapper present + +x
w=workers/bin/vapt-waybacklister
[ -x "$w" ] || { echo "wrapper not executable: $w"; exit 1; }
# Wrapper rejects IP
err=$("$w" --domain 192.168.1.1 2>&1 || true)
echo "$err" | grep -q "no data for IP" || { echo "wrapper did not reject IP input (got: $err)"; exit 1; }
# Catalog has entry
grep -q "waybacklister" packages/tools/vapt_tools/catalog.py || { echo "catalog entry missing"; exit 1; }
# Preflight tracks the binary
grep -q "vapt-waybacklister" services/orchestrator/vapt_orch/preflight.py || { echo "preflight missing"; exit 1; }
echo "ok: wayBackLister wrapper+catalog+preflight all wired"
' && \
check "REGISTRY.get(\"waybacklister\") resolves to a P1 tool" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_tools import REGISTRY
spec = REGISTRY.get("waybacklister")
assert spec.policy_class.value == "p1_low_impact", f"got {spec.policy_class}"
assert spec.target_kind == "network", f"got {spec.target_kind}"
argv = spec.build_argv({"target": "example.com"})
assert argv[0] == "vapt-waybacklister" and "example.com" in argv, argv
print("ok")
'

echo
echo "[17/18] Fix A: admin wordlist probe tier"
check "_ADMIN_WORDLIST constant + webvuln.admin_wordlist_probe event + admin-surface gate" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_ADMIN_WORDLIST = " "$f" || { echo "_ADMIN_WORDLIST constant missing"; exit 1; }
grep -q "webvuln.admin_wordlist_probe" "$f" || { echo "ledger event missing"; exit 1; }
grep -q "webvuln-adminprobe-" "$f" || { echo "task_id prefix missing"; exit 1; }
# Must probe the PyYAML-deser RCE path specifically (vuln #19 the user asked about)
grep -q "admin/config/import" "$f" || { echo "admin/config/import PyYAML RCE path missing from wordlist"; exit 1; }
grep -q "admin/logs" "$f" || { echo "admin/logs path missing"; exit 1; }
grep -q "receipt/download" "$f" || { echo "receipt/download path missing"; exit 1; }
echo "ok: wordlist has 30+ paths incl. the RCE primitive /admin/config/import"
'

echo
echo "[18/18] Fix D: JS endpoint miner wrapper + catalog + preflight + registry"
check "wrapper exists + rejects invalid target + catalog + preflight" \
    bash -c '
w=workers/bin/vapt-js-endpoint-miner
[ -x "$w" ] || { echo "wrapper not executable: $w"; exit 1; }
# Invalid target rejection
err=$("$w" --target "!!bad" --base-urls http://a 2>&1 || true)
echo "$err" | grep -q "invalid target host" || { echo "wrapper did not reject bad target: $err"; exit 1; }
# Catalog + description
grep -q "js_endpoint_miner" packages/tools/vapt_tools/catalog.py || { echo "catalog entry missing"; exit 1; }
grep -q "vapt-js-endpoint-miner" services/orchestrator/vapt_orch/preflight.py || { echo "preflight missing"; exit 1; }
# {base_urls} placeholder support
grep -q "{base_urls}" packages/tools/vapt_tools/catalog.py || { echo "{base_urls} resolver missing"; exit 1; }
echo "ok: wrapper + catalog + preflight + placeholder resolver all wired"
' && \
check "REGISTRY.get(\"js_endpoint_miner\") resolves + builds argv with multi-base" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_tools import REGISTRY
spec = REGISTRY.get("js_endpoint_miner")
assert spec.policy_class.value == "p1_low_impact", spec.policy_class
argv = spec.build_argv({"target": "172.25.188.23",
                        "base_urls": ["http://172.25.188.23:5000",
                                      "http://172.25.188.23:5985"]})
assert argv[0] == "vapt-js-endpoint-miner"
assert "--base-urls" in argv
# Comma-joined form
assert any("5000" in a and "5985" in a for a in argv), argv
print("ok")
'

echo
echo "[19] 2026-10-28 — Recon-agent Fix 1: one-shot example in system prompt"
check "system prompt includes FIELD SEMANTICS + WORKED EXAMPLES blocks" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "FIELD SEMANTICS" "$f" || { echo "FIELD SEMANTICS block missing"; exit 1; }
grep -q "WORKED EXAMPLES" "$f" || { echo "WORKED EXAMPLES block missing"; exit 1; }
grep -q "param. is NEVER the string" "$f" || { echo "param/url distinction note missing"; exit 1; }
echo "ok: one-shot example embedded in agent system prompt"
'

echo
echo "[20] 2026-10-28 — Recon-agent Fix 2: validation nudge echoes bad step + corrected example"
check "_reject_with_fix helper + corrected_example + REJECTED echo" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_reject_with_fix" "$f" || { echo "_reject_with_fix helper missing"; exit 1; }
grep -q "Corrected example:" "$f" || { echo "Corrected example in nudge missing"; exit 1; }
grep -q "Your last step was REJECTED" "$f" || { echo "REJECTED echo in nudge missing"; exit 1; }
echo "ok: structured validation rejections wired"
'

echo
echo "[21] 2026-10-28 — LLM kept_steps dispatch hoisted + max_iterations bumped"
check "plan.extend(_llm_webvuln_propose) appears BEFORE the big web_param_probe tier" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
# Line of first plan.extend(_llm_webvuln_propose
hoist_line=$(grep -n "plan.extend(_llm_webvuln_propose" "$f" | head -1 | cut -d: -f1)
[ -n "$hoist_line" ] || { echo "no plan.extend(_llm_webvuln_propose) found"; exit 1; }
# Line of the generic probe tier anchor comment ("Deterministic in-band probes on discovered")
probe_line=$(grep -n "Deterministic in-band probes on discovered" "$f" | head -1 | cut -d: -f1)
[ -n "$probe_line" ] || { echo "generic probe tier comment not found"; exit 1; }
[ "$hoist_line" -lt "$probe_line" ] || { echo "LLM extend ($hoist_line) is AFTER probe tier ($probe_line)"; exit 1; }
echo "ok: LLM extend @line $hoist_line is BEFORE generic probe tier @line $probe_line"
'

echo
echo "[22] 2026-10-28 — IDOR numeric-ID fallback injection"
check "_IDOR_NUMERIC_NOUNS tuple + 100-URL cap" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_IDOR_NUMERIC_NOUNS" "$f" || { echo "IDOR numeric nouns tuple missing"; exit 1; }
grep -q "urls\[:100\]" "$f" || { echo "IDOR url cap bump to 100 missing"; exit 1; }
echo "ok: numeric-ID fallback wired + cap bumped"
'

echo
echo "[23] 2026-10-28 — weak_cred_probe: wrapper + catalog + registry + manifest + normalizer"
check "wrapper exists + bin, catalog entry, registry spec, manifest allow, normalizer, proof set" \
    bash -c '
w=workers/bin/vapt-weak-cred-probe
[ -x "$w" ] || { echo "wrapper not executable: $w"; exit 1; }
# Reject bad url
err=$("$w" --target 127.0.0.1 --url "javascript:alert" 2>&1 || true)
echo "$err" | grep -q "url must be http" || { echo "wrapper did not reject bad url"; exit 1; }
grep -q "weak_cred_probe" packages/tools/vapt_tools/catalog.py || { echo "catalog entry missing"; exit 1; }
grep -q "weak_cred_probe" packages/tools/vapt_tools/registry.py || { echo "registry entry missing"; exit 1; }
grep -q "vapt-weak-cred-probe" services/orchestrator/vapt_orch/preflight.py || { echo "preflight missing"; exit 1; }
grep -q "weak_cred_probe" packages/agents/vapt_agents/manifests.py || { echo "SCAN manifest missing"; exit 1; }
grep -q "_weak_cred_probe" packages/agents/vapt_agents/normalize.py || { echo "normalizer missing"; exit 1; }
grep -q "\"weak_cred_probe\"" packages/agents/vapt_agents/phases.py || { echo "proof set missing"; exit 1; }
echo "ok: weak_cred_probe fully wired"
' && \
check "REGISTRY.get(weak_cred_probe) resolves + argv passes sentinels" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_tools import REGISTRY
spec = REGISTRY.get("weak_cred_probe")
assert spec.policy_class.value == "p2_intrusive"
# Password-only form (phpLiteAdmin shape) — empty username field.
argv = spec.build_argv({"target": "127.0.0.1",
                        "url": "http://127.0.0.1:5000/phpliteadmin.php",
                        "username_field": "",
                        "password_field": "password",
                        "extra_fields": "login=Log+In,remember="})
# "--username-field __PASSWORD_ONLY__" sentinel preserved
assert "__PASSWORD_ONLY__" in argv, argv
assert "login=Log+In,remember=" in argv, argv
print("ok")
'

echo
echo "[24] 2026-10-28 — SQLi auth tier iterates ALL form fields (not just username)"
check "_dispatch_sqli_auth helper + per-param dedup" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_dispatch_sqli_auth" "$f" || { echo "_dispatch_sqli_auth helper missing"; exit 1; }
grep -q "_fm_login_params" "$f" || { echo "form_map login param collection missing"; exit 1; }
echo "ok: SQLi auth tier iterates all fields from form_map"
'

echo
echo "[25] 2026-10-28 — dalfox tier prioritizes form_map admin forms before public sinks"
check "two-pass dispatcher + budget bumped 8 -> 12" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_dispatch_dalfox_form" "$f" || { echo "_dispatch_dalfox_form helper missing"; exit 1; }
grep -q "dalfox_idx >= 12" "$f" || { echo "dalfox budget not bumped to 12"; exit 1; }
echo "ok: dalfox form tier runs form_map FIRST, then is_post_sink_route fallback"
'

echo
echo "[26] 2026-10-28 — admin_wordlist_probe telemetry dedup (once per run)"
check "_admin_wordlist_logged set guards the ledger event" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_admin_wordlist_logged" "$f" || { echo "dedup set missing"; exit 1; }
echo "ok: admin_wordlist_probe emits once per run"
'

echo
echo "[27] 2026-10-28 — recon_agent body-pattern scanner emits secret findings"
check "_scan_body_for_secrets + _SECRET_PATTERNS + proof-set entry" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_scan_body_for_secrets" "$f" || { echo "scanner fn missing"; exit 1; }
grep -q "_SECRET_PATTERNS" "$f" || { echo "patterns tuple missing"; exit 1; }
grep -q "pbkdf2:sha256" "$f" || { echo "pbkdf2 pattern missing"; exit 1; }
grep -q "AKIA\[0-9A-Z\]" "$f" || { echo "AWS key pattern missing"; exit 1; }
grep -q "recon_agent.body_scanner" packages/agents/vapt_agents/phases.py \
    || { echo "proof-set entry missing"; exit 1; }
echo "ok: body-pattern finding emission wired + promotable"
'

echo
echo "[28] 2026-10-28 Speedup Fix 1 — thread pool in vapt-web-probe"
check "ThreadPoolExecutor + _parallel_fire + lock-based thread safety" \
    bash -c '
f=workers/bin/vapt-web-probe
grep -q "ThreadPoolExecutor" "$f" || { echo "no ThreadPoolExecutor import"; exit 1; }
grep -q "_parallel_fire" "$f" || { echo "no _parallel_fire helper"; exit 1; }
grep -q "_reserve_budget" "$f" || { echo "no thread-safe budget helper"; exit 1; }
grep -q "_WORKER_COUNT" "$f" || { echo "no worker count constant"; exit 1; }
grep -q "VAPT_WEB_PROBE_WORKERS" "$f" || { echo "no env override"; exit 1; }
grep -q "\"timings\":" "$f" || { echo "no timings in output JSON"; exit 1; }
grep -q "\"concurrency\":" "$f" || { echo "no concurrency in output JSON"; exit 1; }
echo "ok: parallel probe + timings + env tuning"
' && \
check "parallel probe smoke run returns valid JSON + populated timings" \
    bash -c '
out=$(.venv/bin/python workers/bin/vapt-web-probe \
    --target 127.0.0.1 --url "http://127.0.0.1:65533/x" \
    --classes "open_redirect,path_traversal" 2>&1)
echo "$out" | .venv/bin/python -c "import sys, json; d = json.loads(sys.stdin.read()); assert d[\"concurrency\"] == 4, d; assert len(d[\"timings\"]) == 2, d" \
    || { echo "smoke run json shape bad: $out" | head -c 500; exit 1; }
echo "ok"
'

echo
echo "[29] 2026-10-28 Speedup Fix 2 — dead-base circuit breaker"
check "_dead_bases cache + _is_base_dead + _record_base_timeout + ledger events" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_dead_bases: dict\[str, dict\[str, int\]\]" "$f" || { echo "_dead_bases cache missing"; exit 1; }
grep -q "_DEAD_BASE_THRESHOLD" "$f" || { echo "threshold constant missing"; exit 1; }
grep -q "def _is_base_dead" "$f" || { echo "_is_base_dead helper missing"; exit 1; }
grep -q "def _record_base_timeout" "$f" || { echo "_record_base_timeout helper missing"; exit 1; }
grep -q "def _record_base_ok" "$f" || { echo "_record_base_ok helper missing"; exit 1; }
grep -q "\"webvuln.dead_base\"" "$f" || { echo "dead_base ledger event missing"; exit 1; }
grep -q "\"webvuln.dead_base_skip\"" "$f" || { echo "dead_base_skip ledger event missing"; exit 1; }
echo "ok: circuit breaker wired + 2 ledger events"
'

echo
echo "[30] 2026-10-28 Speedup Fix 3 — probe dedup across admin/generic tiers"
check "_admin_planned_tool_url set + dedup checks + ledger event" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_admin_planned_tool_url: set" "$f" || { echo "dedup set missing"; exit 1; }
grep -q "_admin_planned_tool_url.add" "$f" || { echo "admin tier does not populate set"; exit 1; }
grep -q "_dedup_skipped" "$f" || { echo "generic tier does not skip-track"; exit 1; }
grep -q "\"webvuln.probe_dedup_skipped\"" "$f" || { echo "dedup ledger event missing"; exit 1; }
echo "ok: dedup across tiers + ledger"
'

echo
echo "[31] 2026-10-28 Speedup Fix 4 — pre-HEAD check on admin wordlist"
check "HEAD pre-filter + alive/dead path sets + ledger event" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_alive_paths: set" "$f" || { echo "_alive_paths set missing"; exit 1; }
grep -q "_dead_paths: set" "$f" || { echo "_dead_paths set missing"; exit 1; }
grep -q "_req_head.head" "$f" || { echo "HEAD call missing"; exit 1; }
grep -q "\"webvuln.admin_prehead\"" "$f" || { echo "prehead ledger event missing"; exit 1; }
grep -q "(_base, _path) in _dead_paths" "$f" || { echo "skip-on-dead check missing"; exit 1; }
echo "ok: pre-HEAD filter wired + ledger"
'

echo
echo "[32] 2026-10-28 — weak_cred_probe_dispatched ledger dedup (once per run)"
check "_wcp_logged set guards the webvuln.weak_cred_probe_dispatched event" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_wcp_logged: set\[str\] = set()" "$f" || { echo "_wcp_logged guard set missing"; exit 1; }
grep -q "scope.run_id not in _wcp_logged" "$f" || { echo "guard check missing"; exit 1; }
grep -q "_wcp_logged.add(scope.run_id)" "$f" || { echo "guard add missing"; exit 1; }
echo "ok: _wcp_logged guards the summary event"
'

echo
echo "[33] 2026-10-28 — weak_cred_probe skips /register and /signup forms"
check "signup-URL skip filter + webvuln.weak_cred_probe_skipped_signup event" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_SIGNUP_HINTS" "$f" || { echo "_SIGNUP_HINTS tuple missing"; exit 1; }
grep -q "\"/register\"" "$f" || { echo "/register hint missing"; exit 1; }
grep -q "\"/signup\"" "$f" || { echo "/signup hint missing"; exit 1; }
grep -q "\"webvuln.weak_cred_probe_skipped_signup\"" "$f" || { echo "skip ledger event missing"; exit 1; }
echo "ok: register/signup paths skip the weak_cred dispatcher"
'

echo
echo "[34] 2026-10-28 — Recon-agent URL auto-correct (schema-confusion recovery)"
check "recon_agent_recover_url helper + autocorrect ledger event" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "^def recon_agent_recover_url" "$f" || { echo "recon_agent_recover_url helper missing"; exit 1; }
grep -q "^def _url_in_text" "$f" || { echo "_url_in_text helper missing"; exit 1; }
grep -q "\"webvuln.recon_agent.propose_autocorrect\"" "$f" || { echo "autocorrect ledger event missing"; exit 1; }
grep -q "recon_agent_recover_url(" "$f" || { echo "helper not wired into propose branch"; exit 1; }
echo "ok: autocorrect wired + helper is importable"
'

echo
echo "[35] 2026-10-28 — recon_agent URL recovery is importable + decision tree is sound"
check "recon_agent_recover_url returns the right URL/source for schema-confusion shapes" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_orch.graph.engagement import recon_agent_recover_url, _url_in_text

# param-as-literal-url schema confusion
step = {"tool_id": "ssti_detect", "param": "url",
        "rationale": "Confirm SSTI on http://172.25.188.23:5000/admin/offer."}
u, src, p = recon_agent_recover_url(step, "172.25.188.23")
assert u == "http://172.25.188.23:5000/admin/offer", f"got {u}"
assert src == "rationale", f"got src {src}"
assert p == "", f"param should be stripped, got {p!r}"

# URL in param field (model stuffed it there)
step = {"tool_id": "csp_check", "param": "http://172.25.188.23:5000/x",
        "rationale": "check csp"}
u, src, p = recon_agent_recover_url(step, "172.25.188.23")
assert u == "http://172.25.188.23:5000/x", f"got {u}"
assert src == "param", f"got src {src}"
assert p == "", f"param should be cleared, got {p!r}"

# Off-scope URL in rationale → no recovery
step = {"tool_id": "ssti_detect", "rationale": "ssti on http://evil.com/x"}
u, src, p = recon_agent_recover_url(step, "172.25.188.23")
assert u == "" and src == "", f"off-scope should not recover, got {u}/{src}"

# Real field name must be preserved
step = {"tool_id": "sqli_detect", "param": "username",
        "rationale": "sqli on http://172.25.188.23:5000/auth/login"}
u, src, p = recon_agent_recover_url(step, "172.25.188.23")
assert p == "username", f"real field name should survive, got {p!r}"

# Trailing punctuation stripped
assert _url_in_text("hit http://x/y.") == "http://x/y"
assert _url_in_text("hit http://x/y, next") == "http://x/y"
print("decision tree + punctuation strip ok")
'

echo
echo "[37] 2026-10-28 — phases.scan_action catches broker ValueError (bloghub crash fix)"
check "scan_action + execute_scan_after_approval wrap broker in try/except" \
    bash -c '
f=packages/agents/vapt_agents/phases.py
grep -q "broker raised" "$f" || { echo "scan_action does not log broker raised"; exit 1; }
awk "/^def scan_action/,/^def execute_scan_after_approval/" "$f" | grep -q "except Exception as e" \
    || { echo "scan_action is not wrapped in try/except"; exit 1; }
awk "/^def execute_scan_after_approval/,/^def _candidates_from/" "$f" | grep -q "except Exception as e" \
    || { echo "execute_scan_after_approval is not wrapped"; exit 1; }
echo "ok: both entry points swallow broker exceptions"
'

echo
echo "[38] 2026-10-28 — scan_action broker-raise returns non-executed outcome (not raise)"
check "scan_action with raising broker returns executed=False" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from datetime import UTC, datetime
import vapt_persistence.db as dbmod
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Project, Run
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_harness import GovernedHarness
from vapt_tools import REGISTRY
from vapt_agents import phases
from vapt_agents.runscope import RunScope
import tempfile, os
with tempfile.TemporaryDirectory() as tmp:
    init_engine(f"sqlite:///{tmp}/t.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    class _Raise:
        def execute(self, tid, args):
            raise ValueError(f"{tid} needs comma-separated urls")
    scope = RunScope(run_id=r.id, testing_mode=TestingMode.BLACK_BOX, target="example.com",
                     domains=["example.com"], ip_cidrs=[],
                     allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                     signed_profile=True)
    harness = GovernedHarness(REGISTRY, broker=_Raise())
    step = phases.scan_action(s, scope, harness, tool_id="http_probe", args={}, task_id="x")
    assert step.outcome.executed is False, "broker raise must leave executed=False"
    assert "broker raised" in step.outcome.reason, f"reason missing: {step.outcome.reason}"
    s.close()
print("ok: broker raise handled")
'

echo
echo "[39] 2026-10-28 — planner _args_from_step passes urls/url through"
check "planner accepts URL args from the LLM" \
    env PYTHONPATH="$PYPATH" "$VENV" -c '
from vapt_agents.planner import _args_from_step
# urls as nested args dict
a = _args_from_step("dom_xss_probe", {"args": {"urls": "http://x/y,http://x/z"}})
assert a.get("urls") == "http://x/y,http://x/z", f"urls not passed through: {a}"
# urls as top-level string
a = _args_from_step("idor_probe", {"urls": "http://x/order/1"})
assert a.get("urls") == "http://x/order/1", f"top-level urls dropped: {a}"
# target still never passes through
a = _args_from_step("http_probe", {"target": "evil.com"})
assert "target" not in a, f"target leaked: {a}"
print("ok: urls allowed, target still blocked")
'

echo
echo "[40] 2026-10-28 — scan node auto-fills urls for URL-requiring tools"
check "scan.auto_filled_urls + scan.skip_no_urls ledger events + _URL_REQUIRED_TOOLS set" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
grep -q "_URL_REQUIRED_TOOLS" "$f" || { echo "_URL_REQUIRED_TOOLS set missing"; exit 1; }
grep -q "\"scan.auto_filled_urls\"" "$f" || { echo "auto_filled_urls event missing"; exit 1; }
grep -q "\"scan.skip_no_urls\"" "$f" || { echo "skip_no_urls event missing"; exit 1; }
grep -q "phases.discovered_endpoint_urls" "$f" || { echo "discovered_endpoint_urls not called"; exit 1; }
echo "ok: scan auto-fill wired"
'

echo
echo "[36] 2026-10-28 — stale 10.60.71.165:5002 comment reference removed"
check "engagement.py no longer references the dead gateway host" \
    bash -c '
f=services/orchestrator/vapt_orch/graph/engagement.py
if grep -q "10\.60\.71\.165:5002" "$f"; then
    echo "stale host reference still present"
    exit 1
fi
grep -q "10\.60\.71\.110:4000" "$f" || { echo "comment should reference current host"; exit 1; }
echo "ok: comment updated"
'

echo
echo "────────────────────────────────────────"
echo "Summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "✅ All offline checks passed." || echo "❌ $FAIL check(s) failed."
exit "$FAIL"
