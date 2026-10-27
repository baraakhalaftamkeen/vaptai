#!/usr/bin/env bash
# Dev helper (the device blocks writing a file literally named "Makefile", so the
# same commands live here). Usage: ./scripts/dev.sh <target>
set -euo pipefail
cd "$(dirname "$0")/.."

# Auto-activate the project's venv so `celery`/`uvicorn`/`pytest`/etc. are on PATH
# whether or not the parent shell had the venv active. Fail-fast with a clear
# error if neither VIRTUAL_ENV is set nor .venv/ exists — missing dependencies
# otherwise surface as `command not found` deep inside a child service, which is
# how the 2026-10-24 "beat: celery: command not found" failure happened.
if [ -z "${VIRTUAL_ENV:-}" ]; then
  if [ -f .venv/bin/activate ]; then
    # shellcheck disable=SC1091
    . .venv/bin/activate
  else
    echo "error: no VIRTUAL_ENV and no .venv/ in $(pwd)" >&2
    echo "       create one with: python -m venv .venv && .venv/bin/pip install -r requirements/dev.txt" >&2
    exit 1
  fi
fi

# Load .env so migrate/api/worker all share the same settings (Alembic reads the
# DB URL from the environment, not from .env directly).
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

export PYTHONPATH="packages/domain:packages/persistence:packages/llm_gateway:packages/policy:packages/tools:packages/harness:packages/skills:packages/agents:services/api:services/orchestrator"

case "${1:-help}" in
  install) pip install -r requirements/dev.txt ;;
  test)    pytest ;;
  lint)    ruff check . ;;
  api)     uvicorn vapt_api.main:app --reload --port 8000 ;;
  worker)  celery -A vapt_orch.celery_app.celery_app worker --loglevel=info -Q runs ;;
  beat)    celery -A vapt_orch.celery_app.celery_app beat --loglevel=info ;;
  web)     (cd apps/web && npm run dev) ;;
  migrate) (cd migrations && alembic upgrade head) ;;
  llm)     shift; python scripts/test_llm.py "$@" ;;
  eval-planner) shift; python scripts/eval_planner.py "$@" ;;
  revision) (cd migrations && alembic revision --autogenerate -m "${2:-change}") ;;
  compose-up)   (cd infra && docker compose up --build) ;;
  compose-down) (cd infra && docker compose down) ;;

  # One-shot "start everything" for local dev. Spawns api + worker + beat + web
  # in parallel, prefixes each line with a colored service tag, writes per-service
  # logs to $VAPT_DEV_LOGS (default ~/.cache/vapt-ai-v2/logs/), and tears every
  # child down together on Ctrl-C. Each service is just this same script invoked
  # as a child, so there's no behavior drift vs. starting them individually.
  #
  # Usage:
  #   ./scripts/dev.sh up            # api + worker + beat + web
  #   SKIP_WEB=1 ./scripts/dev.sh up # same minus the Next.js dev server
  #   SKIP_BEAT=1 ./scripts/dev.sh up
  up|dev|all)
    LOGDIR="${VAPT_DEV_LOGS:-$HOME/.cache/vapt-ai-v2/logs}"
    mkdir -p "$LOGDIR"
    # SIGPIPE from a dead tee shouldn't kill the subshell under set -e.
    set +e
    # ANSI color per service — pick colors with enough contrast against both
    # light and dark terminal themes.
    _api_c=36    # cyan
    _work_c=32   # green
    _beat_c=33   # yellow
    _web_c=35    # magenta
    _prefix() {
      # Reads stdin, prefixes each line with a bracketed tag. The `\x1b` escapes
      # work in bash with echo -e (used indirectly via sed's s command below).
      local color="$1" tag="$2"
      awk -v c="$color" -v t="$tag" '{
        printf "\033[%sm[%s]\033[0m %s\n", c, t, $0; fflush();
      }'
    }
    pids=()
    _start() {
      local tag="$1" color="$2" log="$3"; shift 3
      ( "$@" ) >"$LOGDIR/$log" 2>&1 &
      local pid=$!
      pids+=("$pid")
      # Tail the log in another background subshell so we can prefix output live.
      ( tail -n 0 -F "$LOGDIR/$log" 2>/dev/null | _prefix "$color" "$tag" ) &
      pids+=("$!")
      printf "  started %-7s pid=%s  log=%s\n" "$tag" "$pid" "$LOGDIR/$log"
    }
    # Trap first so a failed start also tears things down cleanly. The guard
    # flag prevents the shutdown from printing/killing three times when both
    # INT and TERM fire (shell delivers INT to the whole pgid on Ctrl-C, then
    # the EXIT trap runs on the way out, then any child death triggers it too).
    _STOPPING=""
    _stop_all() {
      [ -n "$_STOPPING" ] && return
      _STOPPING=1
      echo ""
      echo "stopping all services..."
      # Clear the EXIT trap so our own exit doesn't re-enter the handler.
      trap - EXIT
      # Kill the whole process group — children, grandchildren (uvicorn's reloader,
      # celery's prefork pool, npm's node proc tree). `kill 0` targets the current
      # process group.
      kill 0 2>/dev/null
      wait 2>/dev/null
      exit 0
    }
    trap _stop_all INT TERM EXIT
    echo "─────────────────────────────────────────────────────────"
    echo "  VAPT-AI dev stack"
    echo "  logs: $LOGDIR"
    _start "api "  "$_api_c"  api.log    "$0" api
    _start "work"  "$_work_c" worker.log "$0" worker
    if [ -z "${SKIP_BEAT:-}" ]; then
      _start "beat" "$_beat_c" beat.log   "$0" beat
    else
      echo "  skipped beat     (SKIP_BEAT set)"
    fi
    if [ -z "${SKIP_WEB:-}" ]; then
      _start "web "  "$_web_c"  web.log    "$0" web
    else
      echo "  skipped web      (SKIP_WEB set)"
    fi
    echo ""
    echo "  api:  http://localhost:8000   web:  http://localhost:3000"
    echo "  Ctrl-C to stop everything"
    echo "─────────────────────────────────────────────────────────"
    # Wait on whichever child dies first so a crashed service doesn't go unnoticed.
    # `wait -n` returns when ANY child exits; we then tear down the rest.
    wait -n
    _stop_all
    ;;

  *) echo "targets: install test lint api worker beat web migrate revision llm eval-planner compose-up compose-down up|dev|all" ;;
esac
