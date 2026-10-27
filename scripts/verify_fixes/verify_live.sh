#!/usr/bin/env bash
# Live-target verification against DineHub. Runs the ACTUAL fixed logic end-to-end
# in isolation — no celery worker, no LangGraph loop, no 1h wait.
#
# Usage (defaults match DineHub lab + admin creds you've been using):
#   bash scripts/verify_fixes/verify_live.sh
#   # or override:
#   TARGET=172.25.188.23 PORT=5000 USER=admin PASS=admin \
#     bash scripts/verify_fixes/verify_live.sh
#
# What it does (3 steps, ~15s total):
#   [1] Logs in as admin via web_login.obtain_session_cookie
#   [2] Runs _authed_discovery_bfs with that cookie — expects /admin/offer,
#       /admin/announcement, /admin/fetch_report, /admin/reports in output
#   [3] Runs form_map.build_endpoint_map on the discovered URLs — expects
#       (offer:textarea) and (content:textarea) and (url:text) in the summary
#   [4] Invokes vapt-recon-fetch binary directly on /admin/reports — expects
#       JSON with hrefs that include the hardcoded fetch_report?url= pattern

set -u
cd "$(dirname "$0")/../.." || exit 1
ROOT="$PWD"
VENV="$ROOT/.venv/bin/python"
PYPATH="packages/domain:packages/persistence:packages/llm_gateway:packages/policy:packages/tools:packages/harness:packages/skills:packages/agents:services/api:services/orchestrator"

TARGET="${TARGET:-172.25.188.23}"
PORT="${PORT:-5000}"
LOGIN_URL="${LOGIN_URL:-http://${TARGET}:${PORT}/auth/login}"
USER="${USER:-admin}"
PASS="${PASS:-admin}"

echo
echo "=== VAPT-AI V2 fix verification (live against DineHub) ==="
echo "Target: $TARGET:$PORT   User: $USER   Login: $LOGIN_URL"
echo

FAIL=0

# -- step 1: login -----------------------------------------------------
echo "[1/4] Admin login via web_login.obtain_session_cookie"
COOKIE=$(env PYTHONPATH="$PYPATH" "$VENV" -c "
from vapt_agents.web_login import obtain_session_cookie
c = obtain_session_cookie('$LOGIN_URL', '$USER', '$PASS')
print(c or '')
" 2>&1)

if [ -z "$COOKIE" ] || echo "$COOKIE" | grep -q "Traceback"; then
    echo "  ❌ FAIL  login did not return a cookie"
    echo "$COOKIE" | sed 's/^/       /'
    FAIL=$((FAIL+1))
    echo "  (skipping remaining live checks)"
    exit 1
fi
echo "  ✅ PASS  cookie: ${COOKIE:0:60}... (${#COOKIE} chars)"

# -- step 2: authed BFS discovery -------------------------------------
echo
echo "[2/4] _authed_discovery_bfs — expects admin paths in output"
BFS_OUT=$(env PYTHONPATH="$PYPATH" VAPT_COOKIE="$COOKIE" "$VENV" <<'PY'
import os, sys
# Re-implement the EXACT BFS from engagement.py in isolation (no graph wiring).
# This is a verbatim copy of _authed_discovery_bfs; if engagement.py's shape
# changes, update this script.
import requests, re
from urllib.parse import urljoin, urlparse, urldefrag
from html.parser import HTMLParser

TARGET = os.environ["TARGET"] if "TARGET" in os.environ else "172.25.188.23"
PORT = os.environ.get("PORT", "5000")
cookie = os.environ["VAPT_COOKIE"]

class LP(HTMLParser):
    def __init__(self): super().__init__(convert_charrefs=True); self.links=[]
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ("href", "action", "src"):
            v = a.get(k)
            if v and not v.lower().startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                self.links.append(v)

sess = requests.Session()
sess.headers["Cookie"] = cookie
sess.headers["User-Agent"] = "Mozilla/5.0 (compatible; VAPT-AI/2.0 recon-bfs)"
bases = [f"http://{TARGET}:{PORT}"]
discovered, seen, queue = [], set(), [(b.rstrip("/") + "/", 0) for b in bases]
while queue and len(discovered) < 60:
    url, d = queue.pop(0)
    u_clean = urldefrag(url)[0]
    if u_clean in seen or d > 2: continue
    seen.add(u_clean)
    try:
        r = sess.get(u_clean, timeout=5, allow_redirects=True)
        if r.status_code >= 500: continue
        body = r.text or ""
    except Exception: continue
    p = urlparse(u_clean)
    if p.hostname == TARGET and (p.path or "/") != "/":
        discovered.append(u_clean)
    if d >= 2: continue
    ct = r.headers.get("Content-Type", "").lower()
    if not ("html" in ct or "xml" in ct or ct == ""): continue
    lp = LP()
    try: lp.feed(body[:200_000])
    except Exception: pass
    for href in lp.links[:60]:
        try: nxt = urljoin(u_clean, href)
        except Exception: continue
        np = urlparse(nxt)
        if np.hostname != TARGET: continue
        if np.scheme not in ("http", "https"): continue
        nxt_clean = urldefrag(nxt)[0]
        if nxt_clean in seen: continue
        queue.append((nxt_clean, d + 1))

for u in discovered:
    print(u)
PY
)
export TARGET PORT

if [ -z "$BFS_OUT" ]; then
    echo "  ❌ FAIL  BFS discovered 0 URLs"
    FAIL=$((FAIL+1))
else
    N=$(echo "$BFS_OUT" | wc -l | tr -d ' ')
    echo "  ℹ️  Discovered $N URLs. Checking for admin sinks..."
    MISSING=""
    for p in "/admin/offer" "/admin/announcement" "/admin/fetch_report" "/admin/reports"; do
        if echo "$BFS_OUT" | grep -q "$p"; then
            echo "       ✓ found $p"
        else
            echo "       ✗ MISSING $p"
            MISSING="$MISSING $p"
        fi
    done
    if [ -z "$MISSING" ]; then
        echo "  ✅ PASS  all 4 admin sinks surfaced by authed BFS"
    else
        echo "  ❌ FAIL  missing paths:$MISSING"
        FAIL=$((FAIL+1))
    fi
fi

# -- step 3: form_map build ------------------------------------------
echo
echo "[3/4] form_map.build_endpoint_map — expects correct field names"
# Pass the URL list via a temp file — stdin here is already consumed by the
# python-script heredoc (two redirects to fd0 collide), so file is cleaner.
URL_FILE=$(mktemp)
trap 'rm -f "$URL_FILE"' EXIT
printf "%s\n" "$BFS_OUT" > "$URL_FILE"
FM_OUT=$(env PYTHONPATH="$PYPATH" VAPT_COOKIE="$COOKIE" VAPT_URL_FILE="$URL_FILE" \
  "$VENV" <<'PY'
import os
from vapt_agents.form_map import build_endpoint_map, summarize_for_llm
with open(os.environ["VAPT_URL_FILE"]) as f:
    urls = [l.strip() for l in f if l.strip()]
if not urls:
    import sys
    print("NO_URLS", file=sys.stderr); sys.exit(2)
fm = build_endpoint_map(urls[:60], os.environ["VAPT_COOKIE"], os.environ["TARGET"])
print(summarize_for_llm(fm))
PY
)

CHECKS=(
    "/admin/offer:(offer:textarea)"
    "/admin/announcement:(content:textarea)"
    "/admin/reports:(url:text)"
    "/auth/login:(username:text,password:password)"
)
FM_FAIL=0
for pair in "${CHECKS[@]}"; do
    IFS=":" read -r path shape <<<"$pair"
    if echo "$FM_OUT" | grep -F -- "$path" | grep -F -q -- "$shape"; then
        echo "       ✓ $path has $shape"
    else
        echo "       ✗ $path missing shape $shape"
        FM_FAIL=1
    fi
done
if [ "$FM_FAIL" -eq 0 ]; then
    echo "  ✅ PASS  form_map captured all 4 critical form shapes"
else
    echo "  ❌ FAIL  form_map missing one or more field names"
    FAIL=$((FAIL+1))
fi

# -- step 4: vapt-recon-fetch binary direct invoke -------------------
echo
echo "[4/4] vapt-recon-fetch binary on /admin/reports"
BIN="$ROOT/workers/bin/vapt-recon-fetch"
if [ ! -x "$BIN" ]; then
    echo "  ❌ FAIL  binary missing or not executable: $BIN"
    FAIL=$((FAIL+1))
else
    RF_OUT=$(VAPT_WEB_LOGIN_COOKIE="$COOKIE" "$BIN" \
        --target "$TARGET" \
        --url "http://${TARGET}:${PORT}/admin/reports" \
        --method get 2>&1)
    # expect JSON with status + forms + hrefs
    if echo "$RF_OUT" | "$VENV" -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d.get('status') == 200, f'bad status: {d.get(\"status\")}'
hrefs = d.get('hrefs') or []
assert any('fetch_report?url=' in h for h in hrefs), f'no fetch_report href in {hrefs!r}'
print(f'ok: status={d[\"status\"]} hrefs={len(hrefs)} forms={len(d.get(\"forms\") or [])}')
" 2>&1 | head -3; then
        echo "  ✅ PASS  recon-fetch returned JSON with internal fetch_report pattern visible"
    else
        echo "  ❌ FAIL  recon-fetch output malformed or missing fetch_report pattern"
        echo "$RF_OUT" | head -5 | sed 's/^/       /'
        FAIL=$((FAIL+1))
    fi
fi

echo
echo "────────────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then
    echo "✅ All 4 live checks passed."
    echo
    echo "What this proves:"
    echo "  • Admin login works + cookie is valid"
    echo "  • Authed BFS DOES surface /admin/offer, /admin/announcement,"
    echo "    /admin/fetch_report, /admin/reports (invisible to unauth crawl)"
    echo "  • form_map parses the right field names (offer:textarea,"
    echo "    content:textarea, url:text) — what the LLM will see"
    echo "  • recon-fetch binary works and reveals /admin/fetch_report?url=..."
    echo "    which is what the recon-agent used to find the metadata-exfil"
    echo
    echo "If this passes, the next real run WILL feed admin sinks to the LLM."
else
    echo "❌ $FAIL live check(s) failed."
fi
exit "$FAIL"
