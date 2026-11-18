#!/usr/bin/env python3
"""XBOW benchmark evaluation runner for VAPT-AI v2.

Deploys each XBOW benchmark (Docker CTF challenge), runs the VAPT-AI web
engagement pipeline against it, and grades the result by checking whether
the injected flag appears in the findings or report.

Usage (from repo root, services running):
    # First, get your session cookie from the browser or login:
    export VAPT_SESSION_COOKIE="<your vapt_session cookie value>"

    # Run all benchmarks:
    python scripts/eval_xbow.py

    # Run specific benchmarks:
    python scripts/eval_xbow.py XBEN-001-24 XBEN-002-24

    # Run a range:
    python scripts/eval_xbow.py --range 1-10

    # Dry-run (deploy + check reachability only):
    python scripts/eval_xbow.py --dry-run XBEN-001-24

    # Resume from where you left off (skip completed):
    python scripts/eval_xbow.py --resume

Environment variables:
    VAPT_API_URL          API base (default: http://localhost:8000)
    VAPT_SESSION_COOKIE   Session cookie value (from browser or /api/v2/auth/session)
    VAPT_ADMIN_USER       Admin username for auto-login (default: admin)
    VAPT_ADMIN_PASSWORD   Admin password for auto-login
    XBOW_BENCHMARKS_DIR   Path to benchmarks/ dir
    XBOW_RESULTS_DIR      Where to write results (default: ./xbow-eval-results)
    XBOW_TIMEOUT          Per-benchmark timeout in seconds (default: 600)
    XBOW_TESTING_MODE     black_box | gray_box | white_box (default: black_box)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_URL = os.environ.get("VAPT_API_URL", "http://localhost:8000")
BENCHMARKS_DIR = Path(os.environ.get(
    "XBOW_BENCHMARKS_DIR",
    os.path.expanduser("~/security-labs/xbow-validation-benchmarks/benchmarks"),
))
RESULTS_DIR = Path(os.environ.get("XBOW_RESULTS_DIR", "./xbow-eval-results"))
TIMEOUT_S = int(os.environ.get("XBOW_TIMEOUT", "600"))
TESTING_MODE = os.environ.get("XBOW_TESTING_MODE", "black_box")
POLL_INTERVAL = 10  # seconds between completion checks


@dataclass
class BenchmarkResult:
    xben_id: str
    host_url: str = ""
    engagement_id: str = ""
    run_id: str = ""
    run_status: str = ""
    findings_count: int = 0
    confirmed_count: int = 0
    flag_expected: str = ""
    flag_found: bool = False
    flag_in_findings: bool = False
    flag_in_report: bool = False
    vuln_detected: bool = False
    elapsed_s: float = 0.0
    error: str = ""
    grade: str = ""  # PASS_FULL, PASS_PARTIAL, FAIL, ERROR, TIMEOUT


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------
class APIClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self._authenticated = False

    def authenticate(self) -> bool:
        cookie = os.environ.get("VAPT_SESSION_COOKIE", "")
        if cookie:
            self.session.cookies.set("vapt_session", cookie)
            try:
                r = self.session.get(f"{self.base}/api/v2/auth/me", timeout=5)
                if r.status_code == 200:
                    me = r.json()
                    print(f"  Authenticated as: {me.get('username', '?')}")
                    self._authenticated = True
                    return True
            except Exception:
                pass

        user = os.environ.get("VAPT_ADMIN_USER", "admin")
        password = os.environ.get("VAPT_ADMIN_PASSWORD", "")
        if password:
            try:
                r = self.session.post(
                    f"{self.base}/api/v2/auth/session",
                    json={"username": user, "password": password},
                    timeout=5,
                )
                if r.status_code == 200:
                    print(f"  Logged in as: {user}")
                    self._authenticated = True
                    return True
                print(f"  Login failed ({r.status_code}): {r.text[:100]}")
            except Exception as e:
                print(f"  Login error: {e}")

        print("  ERROR: No valid authentication. Set VAPT_SESSION_COOKIE or VAPT_ADMIN_PASSWORD.")
        return False

    def get(self, path: str, **kw) -> requests.Response:
        return self.session.get(f"{self.base}{path}", **kw)

    def post(self, path: str, **kw) -> requests.Response:
        return self.session.post(f"{self.base}{path}", **kw)


# ---------------------------------------------------------------------------
# Benchmark deploy/teardown
# ---------------------------------------------------------------------------
def compute_flag(xben_id: str) -> str:
    """Read the flag from the benchmark's .env, falling back to SHA256 derivation."""
    env_path = BENCHMARKS_DIR / xben_id / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("FLAG="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                if val:
                    return val
    import hashlib
    upper = xben_id.upper().replace("-", "-")
    h = hashlib.sha256(upper.encode()).hexdigest()
    return f"FLAG{{{h}}}"


def parse_host_port(docker_compose_path: Path) -> int:
    """Parse the host port from a benchmark's docker-compose.yml."""
    text = docker_compose_path.read_text()
    # Find port mappings in the main service (not db/helper services)
    # Patterns: "127.0.0.1:8081:80", "5000:5000", "80", "8000:80"
    port_lines = []
    in_ports = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "ports:":
            in_ports = True
            continue
        if in_ports and stripped.startswith("-"):
            port_lines.append(stripped.lstrip("- ").strip('"').strip("'"))
            in_ports = False
        elif in_ports and not stripped.startswith("-"):
            in_ports = False

    for port_spec in port_lines:
        parts = port_spec.split(":")
        if len(parts) == 3:
            # host_ip:host_port:container_port
            return int(parts[1])
        elif len(parts) == 2:
            # host_port:container_port
            return int(parts[0])
        elif len(parts) == 1:
            # Just container_port (Docker maps to same port on host)
            return int(parts[0])
    return 80  # fallback


def deploy_benchmark(xben_id: str) -> tuple[bool, str, int]:
    """Build and run a benchmark. Returns (ok, error_msg, host_port)."""
    bench_dir = BENCHMARKS_DIR / xben_id
    if not bench_dir.exists():
        return False, f"benchmark dir not found: {bench_dir}", 0

    compose_file = bench_dir / "docker-compose.yml"
    host_port = parse_host_port(compose_file)

    # Build
    print(f"  Building {xben_id}...")
    proc = subprocess.run(
        ["make", "build"],
        cwd=str(bench_dir),
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        return False, f"build failed: {proc.stderr[:200]}", 0

    # Run
    print(f"  Starting {xben_id} (port {host_port})...")
    proc = subprocess.run(
        ["docker", "compose", "up", "-d", "--wait"],
        cwd=str(bench_dir),
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        return False, f"docker up failed: {proc.stderr[:200]}", host_port

    # Wait for healthcheck
    time.sleep(3)
    return True, "", host_port


def teardown_benchmark(xben_id: str) -> None:
    """Stop and remove a benchmark's containers."""
    bench_dir = BENCHMARKS_DIR / xben_id
    subprocess.run(
        ["docker", "compose", "down", "-v", "--remove-orphans"],
        cwd=str(bench_dir),
        capture_output=True, text=True, timeout=60,
    )


def check_reachable(url: str, retries: int = 5, delay: float = 3.0) -> bool:
    """Check if the benchmark URL is reachable."""
    for i in range(retries):
        try:
            r = requests.get(url, timeout=10, allow_redirects=True)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        if i < retries - 1:
            time.sleep(delay)
    return False


# ---------------------------------------------------------------------------
# VAPT-AI engagement lifecycle
# ---------------------------------------------------------------------------
def create_engagement(api: APIClient, xben_id: str, target_url: str, port: int) -> str | None:
    """Create an engagement for this benchmark. Returns engagement_id or None."""
    scope = {
        "domains": ["localhost", "127.0.0.1"],
        "ip_cidrs": ["127.0.0.1/32"],
        "url_paths": [target_url],
        "exclusions": [],
        "allowed_ports": str(port),
        "allowed_action_classes": [
            "p0_passive", "p1_low_impact", "p2_intrusive",
        ],
        "allow_exploitation": True,
        "poc_playbook": "http_evidence",
        "data_sensitivity": "standard",
    }
    body = {
        "name": f"XBOW Eval: {xben_id}",
        "testing_mode": TESTING_MODE,
        "target_type": "web",
        "target_description": f"XBOW benchmark {xben_id} - CTF challenge on {target_url}",
        "scope": scope,
    }
    try:
        r = api.post("/api/v2/engagements", json=body, timeout=10)
        if r.status_code == 201:
            data = r.json()
            return data["id"]
        print(f"  Engagement creation failed ({r.status_code}): {r.text[:200]}")
    except Exception as e:
        print(f"  Engagement creation error: {e}")
    return None


def create_run(api: APIClient, engagement_id: str) -> str | None:
    """Create an auto-approve run. Returns run_id or None."""
    body = {
        "engagement_id": engagement_id,
        "auto_approve": True,
    }
    try:
        r = api.post("/api/v2/runs", json=body, timeout=10)
        if r.status_code == 201:
            data = r.json()
            return data["id"]
        print(f"  Run creation failed ({r.status_code}): {r.text[:200]}")
    except Exception as e:
        print(f"  Run creation error: {e}")
    return None


def poll_run(api: APIClient, run_id: str, timeout_s: int = TIMEOUT_S) -> str:
    """Poll until the run completes or times out. Returns final status."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = api.get(f"/api/v2/runs/{run_id}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                st = data.get("status", "unknown")
                phase = data.get("phase", "?")
                if st in ("completed", "failed", "cancelled"):
                    return st
                print(f"    ... {st}/{phase} ({int(deadline - time.time())}s remaining)")
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)
    return "timeout"


def get_findings(api: APIClient, run_id: str) -> list[dict]:
    """Get all findings for a run."""
    try:
        r = api.get(f"/api/v2/runs/{run_id}/findings", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []


def get_report(api: APIClient, run_id: str) -> dict | None:
    """Get the report for a run."""
    try:
        r = api.get(f"/api/v2/runs/{run_id}/report", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def get_report_html(api: APIClient, run_id: str) -> str:
    """Get the HTML report content."""
    try:
        r = api.get(f"/api/v2/runs/{run_id}/report/html", timeout=10)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------
def grade_benchmark(result: BenchmarkResult, findings: list[dict],
                    report: dict | None, report_html: str) -> None:
    """Grade a benchmark result by checking for the flag and vuln detection."""
    flag = result.flag_expected.lower()
    result.findings_count = len(findings)
    result.confirmed_count = sum(
        1 for f in findings if f.get("status") == "confirmed"
    )

    # Check findings for flag
    for f in findings:
        blob = json.dumps(f).lower()
        if flag in blob:
            result.flag_in_findings = True
            result.flag_found = True
        if f.get("status") in ("confirmed", "candidate"):
            result.vuln_detected = True

    # Check report for flag
    if report:
        report_blob = json.dumps(report).lower()
        if flag in report_blob:
            result.flag_in_report = True
            result.flag_found = True

    if report_html:
        if flag in report_html.lower():
            result.flag_in_report = True
            result.flag_found = True

    # Determine grade
    if result.error:
        result.grade = "ERROR"
    elif result.run_status == "timeout":
        result.grade = "TIMEOUT"
    elif result.flag_found:
        result.grade = "PASS_FULL"
    elif result.vuln_detected:
        result.grade = "PASS_PARTIAL"
    else:
        result.grade = "FAIL"


# ---------------------------------------------------------------------------
# Results I/O
# ---------------------------------------------------------------------------
def save_result(result: BenchmarkResult) -> None:
    """Save individual benchmark result to disk."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"{result.xben_id}.json"
    path.write_text(json.dumps({
        "xben_id": result.xben_id,
        "host_url": result.host_url,
        "engagement_id": result.engagement_id,
        "run_id": result.run_id,
        "run_status": result.run_status,
        "findings_count": result.findings_count,
        "confirmed_count": result.confirmed_count,
        "flag_expected": result.flag_expected,
        "flag_found": result.flag_found,
        "flag_in_findings": result.flag_in_findings,
        "flag_in_report": result.flag_in_report,
        "vuln_detected": result.vuln_detected,
        "elapsed_s": round(result.elapsed_s, 1),
        "error": result.error,
        "grade": result.grade,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2))


def load_completed() -> set[str]:
    """Load set of already-completed benchmark IDs from results dir."""
    done = set()
    if RESULTS_DIR.exists():
        for f in RESULTS_DIR.glob("XBEN-*.json"):
            try:
                data = json.loads(f.read_text())
                if data.get("grade") in ("PASS_FULL", "PASS_PARTIAL", "FAIL"):
                    done.add(data["xben_id"])
            except Exception:
                pass
    return done


def print_summary(results: list[BenchmarkResult]) -> None:
    """Print a summary table of all results."""
    print("\n" + "=" * 80)
    print("XBOW BENCHMARK EVALUATION RESULTS")
    print("=" * 80)
    print(f"{'ID':<16} {'Grade':<14} {'Status':<12} {'Findings':<10} {'Flag':<6} {'Time':>8}")
    print("-" * 80)

    grades = {"PASS_FULL": 0, "PASS_PARTIAL": 0, "FAIL": 0, "ERROR": 0, "TIMEOUT": 0}
    for r in sorted(results, key=lambda x: x.xben_id):
        flag_mark = "Y" if r.flag_found else ("~" if r.vuln_detected else "N")
        time_str = f"{r.elapsed_s:.0f}s"
        print(f"{r.xben_id:<16} {r.grade:<14} {r.run_status:<12} "
              f"{r.confirmed_count}/{r.findings_count:<6} {flag_mark:<6} {time_str:>8}")
        grades[r.grade] = grades.get(r.grade, 0) + 1

    total = len(results)
    print("-" * 80)
    print(f"Total: {total}")
    print(f"  PASS (Full):    {grades['PASS_FULL']:>3}  ({grades['PASS_FULL']/total*100:.1f}%)" if total else "")
    print(f"  PASS (Partial): {grades['PASS_PARTIAL']:>3}  ({grades['PASS_PARTIAL']/total*100:.1f}%)" if total else "")
    print(f"  FAIL:           {grades['FAIL']:>3}  ({grades['FAIL']/total*100:.1f}%)" if total else "")
    print(f"  ERROR:          {grades['ERROR']:>3}" if total else "")
    print(f"  TIMEOUT:        {grades['TIMEOUT']:>3}" if total else "")
    if total:
        success = grades["PASS_FULL"] + grades["PASS_PARTIAL"]
        print(f"\nOverall: {success}/{total} ({success/total*100:.1f}%) detected a vulnerability")
        print(f"Flag capture: {grades['PASS_FULL']}/{total} ({grades['PASS_FULL']/total*100:.1f}%)")


def save_summary(results: list[BenchmarkResult]) -> None:
    """Save summary JSON."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    grades = {}
    for r in results:
        grades[r.grade] = grades.get(r.grade, 0) + 1
    total = len(results)
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "testing_mode": TESTING_MODE,
        "grades": grades,
        "success_rate": (grades.get("PASS_FULL", 0) + grades.get("PASS_PARTIAL", 0)) / total if total else 0,
        "flag_capture_rate": grades.get("PASS_FULL", 0) / total if total else 0,
        "results": [
            {
                "xben_id": r.xben_id,
                "grade": r.grade,
                "findings": r.findings_count,
                "confirmed": r.confirmed_count,
                "flag_found": r.flag_found,
                "elapsed_s": round(r.elapsed_s, 1),
            }
            for r in sorted(results, key=lambda x: x.xben_id)
        ],
    }
    (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, indent=2))


# ---------------------------------------------------------------------------
# Main eval loop
# ---------------------------------------------------------------------------
def run_benchmark(api: APIClient, xben_id: str, dry_run: bool = False) -> BenchmarkResult:
    """Run the full eval cycle for one benchmark."""
    result = BenchmarkResult(xben_id=xben_id)
    result.flag_expected = compute_flag(xben_id)
    t0 = time.time()

    print(f"\n{'='*60}")
    print(f"[{xben_id}] Starting evaluation")
    print(f"  Expected flag: {result.flag_expected[:20]}...")

    # 1. Deploy
    ok, err, port = deploy_benchmark(xben_id)
    if not ok:
        result.error = err
        result.grade = "ERROR"
        print(f"  DEPLOY FAILED: {err}")
        return result

    target_url = f"http://localhost:{port}"
    result.host_url = target_url
    print(f"  Target: {target_url}")

    # 2. Check reachability
    if not check_reachable(target_url):
        result.error = "target unreachable after deploy"
        result.grade = "ERROR"
        print(f"  UNREACHABLE: {target_url}")
        teardown_benchmark(xben_id)
        return result

    print(f"  Reachable: OK")

    if dry_run:
        result.grade = "DRY_RUN"
        print(f"  DRY RUN - skipping engagement")
        teardown_benchmark(xben_id)
        result.elapsed_s = time.time() - t0
        return result

    # 3. Create engagement
    eng_id = create_engagement(api, xben_id, target_url, port)
    if not eng_id:
        result.error = "failed to create engagement"
        result.grade = "ERROR"
        teardown_benchmark(xben_id)
        return result
    result.engagement_id = eng_id
    print(f"  Engagement: {eng_id}")

    # 4. Create auto-approve run
    run_id = create_run(api, eng_id)
    if not run_id:
        result.error = "failed to create run"
        result.grade = "ERROR"
        teardown_benchmark(xben_id)
        return result
    result.run_id = run_id
    print(f"  Run: {run_id} (auto-approve)")

    # 5. Poll for completion
    print(f"  Waiting for completion (timeout {TIMEOUT_S}s)...")
    run_status = poll_run(api, run_id)
    result.run_status = run_status
    print(f"  Run status: {run_status}")

    # 6. Collect results
    findings = get_findings(api, run_id)
    report = get_report(api, run_id)
    report_html = get_report_html(api, run_id)

    # 7. Grade
    grade_benchmark(result, findings, report, report_html)
    result.elapsed_s = time.time() - t0

    # 8. Save detailed findings for analysis
    details_dir = RESULTS_DIR / xben_id
    details_dir.mkdir(parents=True, exist_ok=True)
    if findings:
        (details_dir / "findings.json").write_text(json.dumps(findings, indent=2))
    if report:
        (details_dir / "report.json").write_text(json.dumps(report, indent=2))
    if report_html:
        (details_dir / "report.html").write_text(report_html)

    # 9. Teardown
    print(f"  Tearing down {xben_id}...")
    teardown_benchmark(xben_id)

    grade_symbol = {"PASS_FULL": "[PASS]", "PASS_PARTIAL": "[PARTIAL]",
                    "FAIL": "[FAIL]", "ERROR": "[ERROR]", "TIMEOUT": "[TIMEOUT]"}
    print(f"  Result: {grade_symbol.get(result.grade, result.grade)} "
          f"({result.confirmed_count}/{result.findings_count} findings, {result.elapsed_s:.0f}s)")

    return result


def list_benchmarks() -> list[str]:
    """List all available XBEN benchmark IDs, sorted."""
    ids = []
    for d in BENCHMARKS_DIR.iterdir():
        if d.is_dir() and d.name.startswith("XBEN-") and (d / "docker-compose.yml").exists():
            ids.append(d.name)
    return sorted(ids)


def parse_range(spec: str) -> list[str]:
    """Parse a range like '1-10' or '5' into XBEN IDs."""
    ids = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            for i in range(int(start), int(end) + 1):
                ids.append(f"XBEN-{i:03d}-24")
        else:
            ids.append(f"XBEN-{int(part):03d}-24")
    return ids


def main() -> int:
    global TIMEOUT_S, TESTING_MODE
    parser = argparse.ArgumentParser(description="XBOW benchmark eval for VAPT-AI")
    parser.add_argument("benchmarks", nargs="*", help="Specific XBEN IDs to run")
    parser.add_argument("--range", "-r", help="Range of benchmarks (e.g. 1-10, 5, 1-5,10-15)")
    parser.add_argument("--dry-run", action="store_true", help="Deploy and check only, no scan")
    parser.add_argument("--resume", action="store_true", help="Skip already-completed benchmarks")
    parser.add_argument("--timeout", type=int, default=TIMEOUT_S, help="Per-benchmark timeout (s)")
    parser.add_argument("--mode", default=TESTING_MODE, choices=["black_box", "gray_box", "white_box"])
    parser.add_argument("--benchmark", help="Single benchmark ID to evaluate")
    parser.add_argument("--run-id", help="Existing run ID to evaluate (skip deploy/scan)")
    args = parser.parse_args()

    TIMEOUT_S = args.timeout
    TESTING_MODE = args.mode

    # Determine which benchmarks to run
    if args.benchmarks:
        targets = args.benchmarks
    elif args.range:
        targets = parse_range(args.range)
    else:
        targets = list_benchmarks()

    # Validate
    available = set(list_benchmarks())
    missing = [t for t in targets if t not in available]
    if missing:
        print(f"WARNING: Benchmarks not found: {missing}")
        targets = [t for t in targets if t in available]

    if not targets:
        print("No benchmarks to run.")
        return 1

    # Resume support
    if args.resume:
        completed = load_completed()
        skipped = [t for t in targets if t in completed]
        targets = [t for t in targets if t not in completed]
        if skipped:
            print(f"Resuming: skipping {len(skipped)} already-completed benchmarks")
        if not targets:
            print("All benchmarks already completed.")
            return 0

    print(f"XBOW Benchmark Evaluation")
    print(f"  Benchmarks:    {len(targets)}")
    print(f"  Testing mode:  {TESTING_MODE}")
    print(f"  Timeout:       {TIMEOUT_S}s per benchmark")
    print(f"  Results dir:   {RESULTS_DIR}")
    print(f"  API:           {API_URL}")

    # Authenticate
    api = APIClient(API_URL)
    if not args.dry_run:
        if not api.authenticate():
            return 1

    # Run each benchmark
    results: list[BenchmarkResult] = []
    for i, xben_id in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] ", end="")
        try:
            result = run_benchmark(api, xben_id, dry_run=args.dry_run)
        except KeyboardInterrupt:
            print("\nInterrupted! Saving partial results...")
            break
        except Exception as e:
            result = BenchmarkResult(xben_id=xben_id, error=str(e), grade="ERROR")
            print(f"  EXCEPTION: {e}")
            teardown_benchmark(xben_id)

        results.append(result)
        save_result(result)

    # Summary
    if results:
        print_summary(results)
        save_summary(results)
        print(f"\nResults saved to: {RESULTS_DIR}/")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
