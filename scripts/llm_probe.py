"""Minimal, dependency-free probe of the LLM endpoint.

Standard library only — no venv or packages needed, so it works even when the
project's dependencies aren't installed. It reads .env from the repo root, so the
key lives in one place instead of being exported by hand each time.

    python3 scripts/llm_probe.py
    python3 scripts/llm_probe.py --base-url http://host:4000 --model gpt-oss-20b

Key lookup order: --api-key-env NAME, then LLM_KEY, then OPENAI_API_KEY.
For the full gateway test (structured output, the thing the agents depend on), use
    bash scripts/dev.sh llm ...
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, '#' comments, optional quotes.
    Does not overwrite variables already set in the environment."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def call(base: str, path: str, headers: dict, payload=None, timeout: int = 90):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def fail(msg: str) -> int:
    print(f"\nFAILED — {msg}\n", file=sys.stderr)
    return 1


def main() -> int:
    load_dotenv(ROOT / ".env")

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--base-url",
        default=os.environ.get("VAPT_LLM_BASE_URL", "http://10.60.71.110:4000"),
    )
    ap.add_argument("--model", default=os.environ.get("VAPT_LLM_MODEL", "gpt-oss-20b"))
    ap.add_argument("--api-key-env", default="")
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args()

    # Resolve the key without ever printing it.
    names = [args.api_key_env] if args.api_key_env else ["LLM_KEY", "OPENAI_API_KEY"]
    key, key_name = "", ""
    for n in names:
        if n and os.environ.get(n):
            key, key_name = os.environ[n], n
            break
    if not key:
        return fail(
            "no API key found. Set one of "
            + ", ".join(n for n in names if n)
            + " in .env or the environment, e.g.\n"
            "  echo \"LLM_KEY=sk-...\" >> .env"
        )

    base = args.base_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    print(f"Server : {base}")
    print(f"Model  : {args.model}")
    print(f"Key    : from ${key_name} (…{key[-4:]})\n")

    # --- 1. list models -------------------------------------------------------
    print("[1/2] GET /v1/models")
    status, raw = call(base, "/v1/models", headers, timeout=20)
    if status is None:
        return fail(f"cannot reach the server — {raw}")
    print(f"  status {status}")
    if status in (401, 403):
        return fail(f"the server rejected the key.\n  server said: {raw.strip()[:400]}")
    if status != 200:
        return fail(f"unexpected HTTP {status}\n  body: {raw.strip()[:400]}")

    try:
        ids = [m.get("id") for m in json.loads(raw).get("data", [])]
    except Exception:
        return fail(f"could not parse the model list: {raw.strip()[:300]}")
    print(f"  OK — {len(ids)} model(s)")
    for name in ids:
        print(f"    - {name}{'   <-- target' if name == args.model else ''}")
    if args.model not in ids:
        print(f"  WARNING: {args.model!r} is not in the list; the chat call may 404.")

    # --- 2. chat round trip ---------------------------------------------------
    print("\n[2/2] POST /v1/chat/completions")
    start = time.time()
    status, raw = call(
        base,
        "/v1/chat/completions",
        headers,
        {
            "model": args.model,
            "messages": [{"role": "user", "content": "Reply with exactly the word pong."}],
            "max_tokens": 64,
            "temperature": 0,
        },
        timeout=args.timeout,
    )
    elapsed = time.time() - start
    if status is None:
        return fail(f"cannot reach the server — {raw}")
    print(f"  status {status}")
    if status != 200:
        return fail(f"HTTP {status}\n  body: {raw.strip()[:400]}")

    try:
        body = json.loads(raw)
        content = body["choices"][0]["message"].get("content")
    except Exception:
        return fail(f"unexpected response shape: {raw.strip()[:300]}")

    print(f"  OK — responded in {elapsed:.2f}s")
    print(f"  response_model {body.get('model')}")
    print(f"  content {content!r}")
    u = body.get("usage") or {}
    if u:
        print(
            f"  tokens prompt={u.get('prompt_tokens')} "
            f"completion={u.get('completion_tokens')} total={u.get('total_tokens')}"
        )

    print("\nConnection test PASSED.")
    print(
        "Wire the platform to it by setting in .env:\n"
        f"  VAPT_LLM_PROVIDER=openai\n"
        f"  VAPT_LLM_BASE_URL={base}/v1\n"
        f"  VAPT_LLM_MODEL={args.model}\n"
        f"  VAPT_LLM_API_KEY_ENV={key_name}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
