"""Tool broker: executes an authorized action in a constrained subprocess.

Shell is disabled (argv array, never a command string). A stable idempotency key is
derived from run/task/tool/target/args so queue retries or graph replay reuse it.
In beta this runs the tool locally with a timeout; the isolation story (Docker
workers, egress deny) lands with the Week 2 execution slice.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime

from vapt_domain.schemas import ToolResult

from . import throttle
from .registry import ToolRegistry, ToolSpec

# How much of a tool's stdout to keep for the result normalizer to parse. Tools that emit a
# machine-readable report (e.g. wapiti `-f json`, nuclei/semgrep JSON) write the WHOLE document
# to stdout, often tens-to-hundreds of KB, and a report cut mid-document is invalid — the parser
# then finds no findings at all. So keep enough to hold a full report. This is only the in-memory
# parse buffer; persisted findings are bounded downstream by the per-tool normalizers.
_STDOUT_PARSE_CAP = 5_000_000
_STDERR_CAP = 20_000


def action_digest(tool_id: str, profile_id: str, target_ref: str, args: dict) -> str:
    blob = json.dumps(
        {"tool": tool_id, "profile": profile_id, "target": target_ref, "args": args},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode()).hexdigest()


def idempotency_key(run_id: str, task_id: str, digest: str) -> str:
    return hashlib.sha256(f"{run_id}:{task_id}:{digest}".encode()).hexdigest()


class ToolBroker:
    def __init__(self, registry: ToolRegistry):
        self._registry = registry

    def is_available(self, tool_id: str, args: dict) -> bool:
        """Is this tool's binary resolvable (PATH or an explicit VAPT_*_BIN override)?
        Lets a caller skip forcing a human approval for a tool that would only no-op."""
        try:
            spec = self._registry.get(tool_id)
            argv = spec.build_argv(args)
        except Exception:
            return False
        return shutil.which(argv[0]) is not None

    def execute(self, tool_id: str, args: dict) -> ToolResult:
        spec: ToolSpec = self._registry.get(tool_id)
        argv = spec.build_argv(args)  # validates args, raises on anything option-like
        started = datetime.now(UTC)

        if shutil.which(argv[0]) is None:
            # Tool binary absent in this environment: report unknown, do not fake success.
            finished = datetime.now(UTC)
            return ToolResult(
                outcome="unknown",
                exit_code=None,
                started_at=started,
                finished_at=finished,
                tool_version=spec.version,
                observations=[{"note": f"binary {argv[0]!r} not installed"}],
            )

        # Per-target politeness: give the host a short breather since the previous tool
        # finished, and a longer cooldown if the previous one was heavy (e.g. nikto/nmap_vuln).
        # Fail-open — if Redis is unreachable or no host is derivable this is a no-op.
        throttle.wait_turn(args)

        # Clock the wall-time of just the subprocess so the throttle's "heavy tool" heuristic
        # is based on the tool's own duration, not the pre-run housekeeping.
        proc_started = datetime.now(UTC)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=spec.timeout_s,
                shell=False,  # never a shell
                check=False,
                # No controlling stdin: a tool that tries to prompt (e.g. a sudo password)
                # gets EOF and fails fast instead of hanging the worker on the terminal.
                stdin=subprocess.DEVNULL,
            )
            finished = datetime.now(UTC)
            observations = [{"stdout": proc.stdout[:_STDOUT_PARSE_CAP], "stderr": proc.stderr[:_STDERR_CAP]}]
            return ToolResult(
                outcome="ok" if proc.returncode in spec.ok_exit_codes else "failed",
                exit_code=proc.returncode,
                started_at=started,
                finished_at=finished,
                tool_version=spec.version,
                observations=observations,
            )
        except subprocess.TimeoutExpired:
            finished = datetime.now(UTC)
            return ToolResult(
                outcome="failed",
                exit_code=None,
                started_at=started,
                finished_at=finished,
                tool_version=spec.version,
                observations=[{"note": "timeout"}],
            )
        finally:
            # Record completion (even for timeout / failure) so a hung tool triggers the
            # heavy-tool cooldown — exactly the DineHub case where arjun kept hanging because
            # the preceding nikto wedged the dev server.
            elapsed = (datetime.now(UTC) - proc_started).total_seconds()
            throttle.record_finish(args, elapsed)
