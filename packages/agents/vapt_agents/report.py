"""Evidence-linked assessment report builder (plan §8, BAR-28).

Consolidates what V1 split across report_gen*.py / export.py into one place. `gather`
reads the run's findings, their observations (evidence), and the ledger-derived coverage
gaps; `render_html` produces a self-contained, print-ready HTML document (so "Save as
PDF" works everywhere), and `try_pdf` renders a real PDF when WeasyPrint is installed.

All dynamic text — finding titles, observation detail, tool names — originates from
tool output and is therefore UNTRUSTED: everything is HTML-escaped before embedding, so
a crafted scanner string can never inject markup into the report.
"""
from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_persistence.models import (
    Engagement,
    Finding,
    FindingObservation,
    Project,
    Run,
    RunEvent,
)

# Soft import — the skill library is advisory metadata, not a hard dependency.
# If vapt_skills fails to load (bad SKILL.md in CI, missing dir), the report
# still renders — just without the per-finding framework-tag chips. Same
# fail-safe pattern the planner uses for format_skill_hints.
try:
    from vapt_skills import framework_refs_for_tools as _framework_refs_for_tools
except Exception:                                                   # pragma: no cover
    _framework_refs_for_tools = None  # type: ignore[assignment]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
    "low": "#047857", "info": "#475569",
}
# Ledger event kinds that represent something the run could NOT cover.
_GAP_KINDS = {"action.denied", "action.blocked"}


@dataclass
class ReportData:
    run_id: str
    engagement_name: str
    project_name: str
    testing_mode: str
    target_type: str
    generated_at: str
    findings_by_sev: dict[str, list[dict]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    status_counts: dict[str, int] = field(default_factory=dict)
    coverage_gaps: list[str] = field(default_factory=list)


def gather(db: Session, run_id: str) -> ReportData:
    run = db.get(Run, run_id)
    eng = db.get(Engagement, run.engagement_id) if run else None
    proj = db.get(Project, eng.project_id) if eng else None

    findings = db.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all()
    by_sev: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    status_counts: dict[str, int] = {}
    for f in findings:
        obs = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == f.id)
        ).scalars().all()
        sev = f.severity if f.severity in by_sev else "info"
        # Phase B — framework-tag enrichment. Union MITRE/CWE/OWASP tags from
        # every skill whose `tools_available` names a tool that produced an
        # observation on this finding. Deterministic, deduplicated, per-finding.
        # Degrades silently to empty lists when vapt_skills isn't importable.
        source_tools = sorted({o.source_tool for o in obs if o.source_tool})
        if _framework_refs_for_tools and source_tools:
            try:
                refs = _framework_refs_for_tools(source_tools)
            except Exception:                                       # pragma: no cover
                refs = {"mitre_attack": [], "cwe": [], "owasp": []}
        else:
            refs = {"mitre_attack": [], "cwe": [], "owasp": []}
        by_sev[sev].append({
            "title": f.title,
            "status": f.status,
            "severity": sev,
            "description": f.description or "",
            "observations": [{"source_tool": o.source_tool, "detail": o.detail or {}} for o in obs],
            "framework_refs": refs,
        })
        status_counts[f.status] = status_counts.get(f.status, 0) + 1

    gaps: list[str] = []
    events = db.execute(
        select(RunEvent).where(RunEvent.run_id == run_id).order_by(RunEvent.seq)
    ).scalars().all()
    # action.executed events carry only the digest; map digest -> tool via action.proposed
    # so a failed/unavailable tool can be named in the gap.
    tool_by_digest: dict[str, str] = {}
    for ev in events:
        p = ev.payload or {}
        if ev.kind == "action.proposed" and p.get("tool"):
            tool_by_digest[str(p.get("digest", ""))] = str(p["tool"])

    seen_exec_gap: set[tuple[str, str]] = set()
    for ev in events:
        payload = ev.payload or {}
        if ev.kind in _GAP_KINDS and payload.get("reason"):
            gaps.append(str(payload["reason"]))
        elif payload.get("skipped"):
            gaps.append(str(payload["skipped"]))
        elif ev.kind == "action.executed" and payload.get("outcome") in ("failed", "unknown"):
            # A tool that ran but produced no usable result: a real coverage gap the
            # report must not hide. Deduped per (tool, outcome) so a PoC retried across
            # several findings shows once.
            tool = tool_by_digest.get(str(payload.get("digest", "")), "a tool")
            outcome = str(payload.get("outcome"))
            dedup = (tool, outcome)
            if dedup in seen_exec_gap:
                continue
            seen_exec_gap.add(dedup)
            if outcome == "unknown":
                reason = "unavailable (binary not installed)"
            else:
                code = payload.get("exit_code")
                reason = f"ran but did not complete (exit {code})" if code is not None else \
                    "ran but did not complete"
            gaps.append(f"{tool}: {reason}")

    counts = {
        "total": len(findings),
        "confirmed": status_counts.get("confirmed", 0),
        "candidate": status_counts.get("candidate", 0),
        "inconclusive": status_counts.get("inconclusive", 0),
    }
    for s in SEVERITY_ORDER:
        counts[s] = len(by_sev[s])

    return ReportData(
        run_id=run_id,
        engagement_name=(eng.name if eng else "—"),
        project_name=(proj.name if proj else "—"),
        testing_mode=(eng.testing_mode if eng else "—"),
        target_type=(eng.target_type if eng else "—"),
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        findings_by_sev=by_sev,
        counts=counts,
        status_counts=status_counts,
        coverage_gaps=gaps,
    )


def findings_brief(db: Session, run_id: str, *, limit: int = 60) -> str:
    """A compact, grounded list of this run's real findings for the reporting/remediation
    prompts — so the model writes ONLY about what was actually found, never invented
    CVEs/ports/services. Empty when there is nothing of note."""
    data = gather(db, run_id)
    lines: list[str] = []
    for sev in SEVERITY_ORDER:
        for f in data.findings_by_sev.get(sev, []):
            if f["status"] in ("confirmed", "candidate"):
                lines.append(f"- [{sev}/{f['status']}] {f['title']}")
                if len(lines) >= limit:
                    return "\n".join(lines)
    return "\n".join(lines)


def _e(s) -> str:
    return html.escape(str(s), quote=True)


def _evidence_line(obs: dict) -> str:
    d = obs.get("detail", {}) or {}
    bits = []
    if d.get("file"):
        loc = _e(d["file"]) + (f":{_e(d['line'])}" if d.get("line") else "")
        bits.append(loc)
    if d.get("rule"):
        bits.append("rule " + _e(d["rule"]))
    if d.get("advisory"):
        bits.append(_e(d["advisory"]))
    if d.get("port"):
        bits.append("port " + _e(d["port"]))
    extra = " · ".join(bits)
    return f'<span class="tool">{_e(obs.get("source_tool", "tool"))}</span>{(" " + extra) if extra else ""}'


def render_html(data: ReportData, *, summary: str = "", remediation: str = "",
                title: str = "Assessment report") -> str:
    c = data.counts
    sev_cards = "".join(
        f'<div class="sev"><span class="dot" style="background:{_SEV_COLOR[s]}"></span>'
        f'<span class="n">{c.get(s, 0)}</span><span class="lbl">{s}</span></div>'
        for s in SEVERITY_ORDER
    )

    sections = []
    for s in SEVERITY_ORDER:
        items = data.findings_by_sev.get(s, [])
        if not items:
            continue
        rows = []
        for f in items:
            ev = "".join(f'<li>{_evidence_line(o)}</li>' for o in f["observations"]) or \
                "<li class='muted'>no linked evidence</li>"
            # Framework-tag chips — rendered inline below the title when the skill
            # library mapped any MITRE/CWE/OWASP tags via `_framework_refs_for_tools`.
            # Each tag is tool-sourced data (frontmatter YAML the loader validated),
            # not model output, so it's safe to render without escaping the slug
            # formatter — but we html-escape anyway (defense in depth).
            refs = f.get("framework_refs") or {}
            chips = []
            for tag in refs.get("mitre_attack", [])[:6]:
                chips.append(f'<span class="chip chip-mitre">MITRE {_e(tag)}</span>')
            for tag in refs.get("cwe", [])[:6]:
                chips.append(f'<span class="chip chip-cwe">{_e(tag)}</span>')
            for tag in refs.get("owasp", [])[:4]:
                chips.append(f'<span class="chip chip-owasp">OWASP {_e(tag)}</span>')
            chips_html = f'<div class="chips">{"".join(chips)}</div>' if chips else ""
            rows.append(
                f'<div class="finding">'
                f'<div class="fhead"><span class="badge" style="background:{_SEV_COLOR[s]}">{_e(s)}</span>'
                f'<span class="status">{_e(f["status"])}</span>'
                f'<span class="ftitle">{_e(f["title"])}</span></div>'
                f'{chips_html}'
                f'{("<p class=fdesc>" + _e(f["description"]) + "</p>") if f["description"] else ""}'
                f'<ul class="evidence">{ev}</ul></div>'
            )
        sections.append(f'<h2>{_e(s.title())} ({len(items)})</h2>' + "".join(rows))
    findings_html = "".join(sections) or "<p class='muted'>No findings recorded.</p>"

    gaps_html = (
        "<ul class='gaps'>" + "".join(f"<li>{_e(g)}</li>" for g in data.coverage_gaps) + "</ul>"
        if data.coverage_gaps else "<p class='muted'>No coverage gaps recorded.</p>"
    )
    summary_html = f"<p>{_e(summary)}</p>" if summary else \
        "<p class='muted'>No executive summary was generated (model offline).</p>"
    remediation_html = f"<p>{_e(remediation)}</p>" if remediation else \
        "<p class='muted'>No remediation guidance was generated (model offline).</p>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)} — {_e(data.engagement_name)}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 14px/1.6 -apple-system, "Segoe UI", Roboto, sans-serif; color:#0f172a;
         background:#fff; margin:0; padding:40px; max-width:900px; margin:0 auto; }}
  header {{ border-bottom:2px solid #0f172a; padding-bottom:16px; margin-bottom:24px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h2 {{ font-size:15px; margin:28px 0 10px; padding-bottom:4px; border-bottom:1px solid #e2e8f0; }}
  .meta {{ color:#475569; font-size:12px; }}
  .mono {{ font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; }}
  .sevrow {{ display:flex; gap:18px; flex-wrap:wrap; margin:18px 0; }}
  .sev {{ display:flex; align-items:center; gap:6px; }}
  .sev .dot {{ width:10px; height:10px; border-radius:50%; display:inline-block; }}
  .sev .n {{ font-weight:700; font-size:16px; }}
  .sev .lbl {{ color:#475569; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  .finding {{ border:1px solid #e2e8f0; border-radius:8px; padding:12px 14px; margin:8px 0; }}
  .fhead {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .badge {{ color:#fff; font-size:10px; text-transform:uppercase; letter-spacing:.05em;
            padding:2px 7px; border-radius:4px; }}
  .status {{ font-size:11px; color:#475569; text-transform:uppercase; letter-spacing:.04em; }}
  .ftitle {{ font-weight:600; }}
  .fdesc {{ color:#334155; margin:8px 0 6px; }}
  .evidence {{ margin:6px 0 0; padding-left:18px; font-size:12.5px; }}
  .evidence .tool {{ font-family: ui-monospace, monospace; background:#f1f5f9;
                     padding:1px 5px; border-radius:3px; }}
  .muted {{ color:#94a3b8; }}
  .gaps li {{ color:#334155; }}
  .chips {{ margin:6px 0 4px; display:flex; gap:5px; flex-wrap:wrap; }}
  .chip {{ display:inline-block; font-size:10.5px; font-family: ui-monospace, monospace;
           padding:1px 7px; border-radius:10px; border:1px solid transparent;
           letter-spacing:.02em; }}
  .chip-mitre {{ background:#eef2ff; color:#3730a3; border-color:#c7d2fe; }}
  .chip-cwe   {{ background:#fef3c7; color:#92400e; border-color:#fde68a; }}
  .chip-owasp {{ background:#fce7f3; color:#9d174d; border-color:#fbcfe8; }}
  .cols {{ display:grid; grid-template-columns:1fr 1fr; gap:24px; }}
  footer {{ margin-top:40px; padding-top:14px; border-top:1px solid #e2e8f0;
            color:#94a3b8; font-size:11px; }}
  @media print {{ body {{ padding:0; }} .finding {{ break-inside:avoid; }} }}
</style></head>
<body>
  <header>
    <h1>{_e(title)}</h1>
    <div class="meta">
      {_e(data.engagement_name)} · {_e(data.project_name)} ·
      {_e(data.testing_mode)} / {_e(data.target_type)} ·
      run <span class="mono">{_e(data.run_id[:8])}</span> · generated {_e(data.generated_at)}
    </div>
  </header>

  <div class="sevrow">{sev_cards}</div>
  <div class="meta">
    {c.get("total", 0)} findings · {c.get("confirmed", 0)} confirmed ·
    {c.get("candidate", 0)} candidate · {c.get("inconclusive", 0)} inconclusive
  </div>

  <h2>Executive summary</h2>{summary_html}

  <div class="cols">
    <div><h2>Remediation</h2>{remediation_html}</div>
    <div><h2>Coverage gaps</h2>{gaps_html}</div>
  </div>

  <h2>Findings</h2>{findings_html}

  <footer>
    Draft report. Findings are evidence-linked; a candidate becomes confirmed only after
    independent validation. Generated by the VAPT-AI reporting agent — review before release.
  </footer>
</body></html>"""


def build_and_store(db: Session, run_id: str, *, summary: str = "", remediation: str = "",
                    generated_by: str = "reporting-agent", title: str = "Assessment report"):
    """Gather the run's findings, render the HTML report, and persist a new draft Report
    row. Returns the Report. A re-run creates a new draft; a reviewer signs off a specific
    report via the API, and finals are never overwritten."""
    from vapt_persistence.models import Report

    data = gather(db, run_id)
    content = render_html(data, summary=summary, remediation=remediation, title=title)
    report = Report(
        run_id=run_id, fmt="html", status="draft", title=title,
        summary=summary or "", remediation=remediation or "", content=content,
        stats={"counts": data.counts, "coverage_gaps": data.coverage_gaps},
        generated_by=generated_by,
    )
    db.add(report)
    db.flush()
    return report


def try_pdf(html_str: str) -> bytes | None:
    """Render the report HTML to PDF with WeasyPrint if it is installed; otherwise None
    (the HTML is print-ready, so the browser's Save-as-PDF is the fallback)."""
    try:
        from weasyprint import HTML  # type: ignore

        return HTML(string=html_str).write_pdf()
    except Exception:
        return None
