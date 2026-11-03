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


_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 33" width="140" height="26">'
    '<path d="M 48.69 23.84 L 54.17 29.39 L 67.73 29.39 C 67.73 29.39 62.11 23.49 55.68 16.93 Z '
    'M 39.39 13.91 L 46.11 7.27 L 45.91 7.07 C 36.92 -1.49 30.46 -0.63 23.83 5.93 L 0.04 29.45 '
    'L 14.61 29.45 L 34.88 9.44 L 39.39 13.9 Z" fill="#C10230"/>'
    '<path d="M 55.15 0.8 L 34.88 20.7 L 30.37 16.24 L 23.65 22.88 C 23.72 22.94 23.79 23.01 '
    '23.85 23.08 C 32.88 32.01 39.3 30.78 45.93 24.22 L 69.71 0.8 L 55.14 0.8 Z M 21.06 6.31 '
    'L 15.58 0.76 L 2.02 0.76 C 2.02 0.76 7.64 6.66 14.07 13.22 Z" fill="#F99D1C"/>'
    '<text x="76" y="13" font-family="Arial,Helvetica,sans-serif" font-size="12" '
    'font-weight="700" fill="#0f172a">Tamkeen</text>'
    '<text x="76" y="27" font-family="Arial,Helvetica,sans-serif" font-size="12" '
    'font-weight="700" fill="#0f172a">Technologies</text></svg>'
)

import re as _re

def _group_key(title: str) -> str:
    key = title
    key = _re.sub(r"\s+at\s+https?://.*$", "", key, flags=_re.IGNORECASE)
    key = _re.sub(r"\s+at\s+/\S.*$", "", key, flags=_re.IGNORECASE)
    key = _re.sub(r"\s+on\s+parameter\s+'[^']*'", "", key, flags=_re.IGNORECASE)
    key = _re.sub(r"\s*\([^)]*\)\s*$", "", key)
    return key.strip() or title


def _parse_remediation(raw: str) -> str:
    if not raw or not raw.strip():
        return "<p class='muted'>No remediation guidance was generated.</p>"

    table_rows: list[dict[str, str]] = []
    for m in _re.finditer(
        r"\*{0,2}(critical|high|medium|low|info)\*{0,2}"
        r"\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*(?:\||$)",
        raw, _re.IGNORECASE,
    ):
        table_rows.append({
            "severity": m.group(1).strip().lower(),
            "finding": _re.sub(r"\*{1,2}", "", m.group(2)).strip(),
            "fix": _re.sub(r"\*{1,2}", "", m.group(3)).strip(),
            "detail": _re.sub(r"\*{1,2}", "", m.group(4)).strip().rstrip("|").strip(),
        })

    summary_m = _re.search(r"\*{0,2}Summary\*{0,2}\s*(.+?)$", raw, _re.IGNORECASE)
    summary_text = _re.sub(r"\*{1,2}", "", summary_m.group(1)).strip() if summary_m else ""

    steps: list[str] = []
    for m in _re.finditer(r"(?:^|\|)\s*\d+\.\s*([^|]+)", raw):
        step = _re.sub(r"\*{1,2}", "", m.group(1)).strip()
        if step and len(step) > 10:
            steps.append(step)

    if not table_rows and not steps:
        return f"<p>{_e(raw)}</p>"

    parts: list[str] = []
    if table_rows:
        parts.append(
            '<table class="rem-table"><thead><tr>'
            '<th>Severity</th><th>Finding</th><th>Immediate Fix</th><th>Long-Term</th>'
            '</tr></thead><tbody>'
        )
        for r in table_rows:
            sev = r["severity"]
            color = _SEV_COLOR.get(sev, "#475569")
            parts.append(
                f'<tr><td><span class="badge" style="background:{color}">{_e(sev)}</span></td>'
                f'<td>{_e(r["finding"])}</td>'
                f'<td>{_e(r["fix"])}</td>'
                f'<td>{_e(r["detail"])}</td></tr>'
            )
        parts.append("</tbody></table>")

    if steps:
        parts.append('<div class="rem-steps"><h3>Recommended Actions</h3><ol>')
        for s in steps:
            parts.append(f'<li>{_e(s)}</li>')
        parts.append("</ol></div>")

    if summary_text:
        parts.append(f'<div class="rem-summary"><p>{_e(summary_text)}</p></div>')

    return "".join(parts) if parts else f"<p>{_e(raw)}</p>"


def render_html(data: ReportData, *, summary: str = "", remediation: str = "",
                title: str = "Assessment report",
                report_status: str = "draft") -> str:
    c = data.counts
    sev_cards = "".join(
        f'<div class="sev"><span class="dot" style="background:{_SEV_COLOR[s]}"></span>'
        f'<span class="n">{c.get(s, 0)}</span><span class="lbl">{s}</span></div>'
        for s in SEVERITY_ORDER
    )

    all_findings: list[dict] = []
    for s in SEVERITY_ORDER:
        for f in data.findings_by_sev.get(s, []):
            all_findings.append(f)

    groups: list[tuple[str, str, list[dict]]] = []
    group_map: dict[str, list[dict]] = {}
    group_order: list[str] = []
    for f in all_findings:
        k = _group_key(f["title"])
        if k not in group_map:
            group_map[k] = []
            group_order.append(k)
        group_map[k].append(f)
    for k in group_order:
        items = group_map[k]
        best_sev = "info"
        for f in items:
            if SEVERITY_ORDER.index(f["severity"]) < SEVERITY_ORDER.index(best_sev):
                best_sev = f["severity"]
        groups.append((k, best_sev, items))

    findings_html_parts: list[str] = []
    for gkey, gsev, gitems in groups:
        color = _SEV_COLOR.get(gsev, "#475569")
        count = len(gitems)
        if count == 1:
            f = gitems[0]
            findings_html_parts.append(_render_finding(f))
        else:
            findings_html_parts.append(
                f'<div class="finding-group">'
                f'<div class="group-header">'
                f'<span class="group-accent" style="background:{color}"></span>'
                f'<span class="badge" style="background:{color}">{_e(gsev)}</span>'
                f'<span class="group-title">{_e(gkey)}</span>'
                f'<span class="group-count">{count} finding{"s" if count > 1 else ""}</span>'
                f'</div>'
                f'<div class="group-items">'
            )
            for f in gitems:
                findings_html_parts.append(_render_finding(f, nested=True))
            findings_html_parts.append("</div></div>")

    findings_html = "".join(findings_html_parts) or "<p class='muted'>No findings recorded.</p>"

    summary_html = f"<p>{_e(summary)}</p>" if summary else \
        "<p class='muted'>No executive summary was generated (model offline).</p>"
    remediation_html = _parse_remediation(remediation)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)} — {_e(data.engagement_name)}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; margin:0; padding:0; }}
  body {{ font: 13px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         color:#0f172a; background:#fff; }}
  p {{ margin:0 0 6px; }}

  .container {{ max-width:820px; margin:0 auto; padding:24px 32px; }}
  .report-header {{ background:#0f172a; color:#fff; padding:18px 0;
                    print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .report-header .container {{ display:flex; align-items:center; justify-content:space-between;
         padding-top:0; padding-bottom:0; }}
  .report-header .hdr-left {{ display:flex; align-items:center; gap:16px; }}
  .report-header .hdr-logo {{ flex-shrink:0; }}
  .report-header h1 {{ font-size:16px; margin:0; font-weight:700; color:#fff; line-height:1.3; }}
  .report-header .hdr-meta {{ font-size:10px; color:#94a3b8; margin-top:1px; line-height:1.4; }}
  .hdr-badge {{ font-size:9px; text-transform:uppercase; letter-spacing:.06em; font-weight:700;
         padding:4px 10px; border-radius:3px; white-space:nowrap;
         print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .hdr-badge-draft {{ background:rgba(255,255,255,.12); color:#e2e8f0; border:1px solid rgba(255,255,255,.2); }}
  .hdr-badge-final {{ background:#047857; color:#fff; }}

  h2 {{ font-size:12px; font-weight:700; margin:20px 0 8px; padding-bottom:4px;
       border-bottom:1.5px solid #cbd5e1; text-transform:uppercase;
       letter-spacing:.05em; color:#334155; }}
  h3 {{ font-size:12px; font-weight:600; margin:10px 0 4px; color:#475569; }}
  .meta {{ color:#64748b; font-size:11px; }}
  .mono {{ font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; font-size:0.92em; }}

  /* Severity row */
  .sevrow {{ display:flex; gap:16px; flex-wrap:wrap; margin:14px 0 6px; padding:10px 16px;
            background:#f8fafc; border-radius:6px; border:1px solid #e2e8f0;
            print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .sev {{ display:flex; align-items:center; gap:5px; }}
  .sev .dot {{ width:8px; height:8px; border-radius:50%; display:inline-block;
              print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .sev .n {{ font-weight:700; font-size:15px; }}
  .sev .lbl {{ color:#64748b; font-size:10px; text-transform:uppercase; letter-spacing:.04em; }}

  /* Summary box */
  .summary-box {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px;
                  padding:12px 16px; margin:6px 0; }}
  .summary-box p {{ margin:0; font-size:13px; line-height:1.55; }}

  /* Findings */
  .finding {{ border:1px solid #e2e8f0; border-radius:6px; padding:8px 12px; margin:5px 0;
             page-break-inside:avoid; }}
  .fhead {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }}
  .badge {{ color:#fff; font-size:9px; text-transform:uppercase; letter-spacing:.05em;
            padding:1px 6px; border-radius:3px; font-weight:700;
            print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .status {{ font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:.04em; }}
  .ftitle {{ font-weight:600; font-size:12px; }}
  .fdesc {{ color:#334155; margin:4px 0; font-size:12px; }}
  .evidence {{ margin:4px 0 0; padding-left:16px; font-size:11px; }}
  .evidence li {{ margin:1px 0; }}
  .evidence .tool {{ font-family: ui-monospace, Consolas, monospace; background:#f1f5f9;
                     padding:0 4px; border-radius:2px; font-size:10px; }}
  .muted {{ color:#94a3b8; }}
  .chips {{ margin:4px 0 2px; display:flex; gap:4px; flex-wrap:wrap; }}
  .chip {{ display:inline-block; font-size:9px; font-family: ui-monospace, monospace;
           padding:0 6px; border-radius:8px; border:1px solid transparent; }}
  .chip-mitre {{ background:#eef2ff; color:#3730a3; border-color:#c7d2fe; }}
  .chip-cwe   {{ background:#fef3c7; color:#92400e; border-color:#fde68a; }}
  .chip-owasp {{ background:#fce7f3; color:#9d174d; border-color:#fbcfe8; }}

  /* Finding groups */
  .finding-group {{ border:1px solid #e2e8f0; border-radius:6px; margin:6px 0;
                    overflow:hidden; page-break-inside:avoid; }}
  .group-header {{ display:flex; align-items:center; gap:8px; padding:8px 12px;
                   background:#f8fafc; border-bottom:1px solid #e2e8f0; position:relative;
                   print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .group-accent {{ position:absolute; left:0; top:0; bottom:0; width:3px;
                  print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .group-title {{ font-weight:600; font-size:12px; flex:1; }}
  .group-count {{ font-size:10px; color:#475569; background:#e2e8f0; padding:1px 8px;
                  border-radius:10px; font-weight:600; white-space:nowrap;
                  print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .group-items {{ padding-left:10px; border-left:2px solid #e2e8f0; margin-left:10px; }}
  .group-items .finding {{ border-radius:4px; margin:4px 6px 4px 0; }}

  /* Remediation table */
  .rem-table {{ width:100%; border-collapse:collapse;
               border:1px solid #e2e8f0; border-radius:6px; overflow:hidden;
               margin:8px 0; font-size:11px; page-break-inside:auto; }}
  .rem-table th {{ background:#f1f5f9; text-align:left; padding:6px 10px; font-size:10px;
                  text-transform:uppercase; letter-spacing:.04em; color:#475569;
                  border-bottom:1.5px solid #cbd5e1; font-weight:700;
                  print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .rem-table td {{ padding:7px 10px; border-bottom:1px solid #f1f5f9; vertical-align:top; }}
  .rem-table tr:last-child td {{ border-bottom:none; }}
  .rem-table tr {{ page-break-inside:avoid; }}
  .rem-steps {{ margin:10px 0; }}
  .rem-steps ol {{ padding-left:18px; margin:4px 0; }}
  .rem-steps li {{ margin:3px 0; color:#334155; font-size:12px; }}
  .rem-summary {{ background:#fffbeb; border:1px solid #fde68a; border-radius:6px;
                  padding:8px 14px; margin:10px 0;
                  print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .rem-summary p {{ margin:0; color:#92400e; font-size:12px; }}

  footer {{ margin-top:24px; padding:10px 0; border-top:1.5px solid #cbd5e1;
            color:#94a3b8; font-size:10px; display:flex; align-items:center;
            justify-content:space-between; }}
  @media print {{
    body {{ font-size:11px; }}
    .container {{ padding:16px 24px; }}
    .report-header {{ padding:14px 0; }}
    h2 {{ margin:14px 0 6px; }}
  }}
  @page {{ size:A4; margin:12mm 10mm; }}
</style></head>
<body>
  <div class="report-header">
    <div class="container">
      <div class="hdr-left">
        <div class="hdr-logo">{_LOGO_SVG}</div>
        <div>
          <h1>{_e(title)}</h1>
          <div class="hdr-meta">
            {_e(data.engagement_name)} &middot; {_e(data.project_name)} &middot;
            {_e(data.testing_mode)} / {_e(data.target_type)} &middot;
            run <span class="mono">{_e(data.run_id[:8])}</span>
          </div>
        </div>
      </div>
      <div class="hdr-badge {'hdr-badge-final' if report_status == 'final' else 'hdr-badge-draft'}">{'FINAL' if report_status == 'final' else 'DRAFT'} &middot; {_e(data.generated_at)}</div>
    </div>
  </div>

  <div class="container">
    <div class="sevrow">{sev_cards}</div>
    <div class="meta">
      {c.get("total", 0)} findings &middot; {c.get("confirmed", 0)} confirmed &middot;
      {c.get("candidate", 0)} candidate &middot; {c.get("inconclusive", 0)} inconclusive
    </div>

    <h2>Executive Summary</h2>
    <div class="summary-box">{summary_html}</div>

    <h2>Remediation Guidance</h2>
    {remediation_html}

    <h2>Findings</h2>
    {findings_html}

    <footer>
      <span>{'Signed-off report.' if report_status == 'final' else 'Draft &mdash; review before release.'}
        Generated by VAPT-AI.</span>
      <span>{_LOGO_SVG}</span>
    </footer>
  </div>
</body></html>"""


def _render_finding(f: dict, nested: bool = False) -> str:
    s = f["severity"]
    ev = "".join(f'<li>{_evidence_line(o)}</li>' for o in f["observations"]) or \
        "<li class='muted'>no linked evidence</li>"
    refs = f.get("framework_refs") or {}
    chips = []
    for tag in refs.get("mitre_attack", [])[:6]:
        chips.append(f'<span class="chip chip-mitre">MITRE {_e(tag)}</span>')
    for tag in refs.get("cwe", [])[:6]:
        chips.append(f'<span class="chip chip-cwe">{_e(tag)}</span>')
    for tag in refs.get("owasp", [])[:4]:
        chips.append(f'<span class="chip chip-owasp">OWASP {_e(tag)}</span>')
    chips_html = f'<div class="chips">{"".join(chips)}</div>' if chips else ""
    return (
        f'<div class="finding">'
        f'<div class="fhead"><span class="badge" style="background:{_SEV_COLOR[s]}">{_e(s)}</span>'
        f'<span class="status">{_e(f["status"])}</span>'
        f'<span class="ftitle">{_e(f["title"])}</span></div>'
        f'{chips_html}'
        f'{("<p class=fdesc>" + _e(f["description"]) + "</p>") if f["description"] else ""}'
        f'<ul class="evidence">{ev}</ul></div>'
    )


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
