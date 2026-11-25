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
_MODE_LABEL = {"black_box": "Black Box", "gray_box": "Gray Box", "white_box": "White Box"}
_TYPE_LABEL = {"web": "Web Application", "network": "Network Infrastructure", "source": "Source Code"}
_SEV_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
    "low": "#047857", "info": "#475569",
}
# Ledger event kinds that represent something the run could NOT cover.
_GAP_KINDS = {"action.denied", "action.blocked"}


_CVSS_FROM_SEV = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0,
}


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
    domains: list[str] = field(default_factory=list)
    target_description: str = ""
    run_started: str = ""
    run_ended: str = ""
    overall_risk: str = "info"


def _extract_cvss(obs: list, severity: str) -> float:
    """Extract CVSS score from observation details, or approximate from severity."""
    for o in obs:
        d = o.detail if hasattr(o, "detail") else (o.get("detail") if isinstance(o, dict) else {})
        if isinstance(d, dict):
            cvss = d.get("cvss") or d.get("cvss_score") or d.get("cvss_base_score")
            if cvss is not None:
                try:
                    return float(cvss)
                except (ValueError, TypeError):
                    pass
    return _CVSS_FROM_SEV.get(severity, 0.0)


def gather(db: Session, run_id: str) -> ReportData:
    from vapt_persistence.models import ScopeVersion
    run = db.get(Run, run_id)
    eng = db.get(Engagement, run.engagement_id) if run else None
    proj = db.get(Project, eng.project_id) if eng else None

    domains: list[str] = []
    target_description = ""
    if eng:
        target_description = eng.target_description or ""
        sv = db.execute(
            select(ScopeVersion)
            .where(ScopeVersion.engagement_id == eng.id)
            .order_by(ScopeVersion.version.desc())
            .limit(1)
        ).scalar_one_or_none()
        if sv and sv.scope:
            domains = sv.scope.get("domains", []) or []

    run_started = ""
    run_ended = ""
    if run:
        run_started = run.created_at.strftime("%Y-%m-%d %H:%M UTC") if run.created_at else ""
        run_ended = run.updated_at.strftime("%Y-%m-%d %H:%M UTC") if run.updated_at else ""

    findings = db.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all()
    by_sev: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    status_counts: dict[str, int] = {}
    for f in findings:
        obs = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == f.id)
        ).scalars().all()
        sev = f.severity if f.severity in by_sev else "info"
        source_tools = sorted({o.source_tool for o in obs if o.source_tool})
        if _framework_refs_for_tools and source_tools:
            try:
                refs = _framework_refs_for_tools(source_tools)
            except Exception:                                       # pragma: no cover
                refs = {"mitre_attack": [], "cwe": [], "owasp": []}
        else:
            refs = {"mitre_attack": [], "cwe": [], "owasp": []}
        cvss_score = _extract_cvss(obs, sev)
        by_sev[sev].append({
            "title": f.title,
            "status": f.status,
            "severity": sev,
            "description": f.description or "",
            "observations": [{"source_tool": o.source_tool, "detail": o.detail or {}} for o in obs],
            "framework_refs": refs,
            "cvss": cvss_score,
            "target_url": f.target_url or "",
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

    overall_risk = "info"
    for s in SEVERITY_ORDER:
        if by_sev.get(s):
            overall_risk = s
            break

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
        domains=domains,
        target_description=target_description,
        run_started=run_started,
        run_ended=run_ended,
        overall_risk=overall_risk,
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


def findings_detail_brief(db: Session, run_id: str, *, limit: int = 60) -> str:
    """A richer findings list for the deep-analysis LLM — includes observation details
    (tool names, accounts, delegation types, certificate info) so the LLM can reason
    about chaining and decide what follow-up tools to run."""
    data = gather(db, run_id)
    lines: list[str] = []
    for sev in SEVERITY_ORDER:
        for f in data.findings_by_sev.get(sev, []):
            if f["status"] not in ("confirmed", "candidate"):
                continue
            parts = [f"- [{sev}] {f['title']}"]
            for obs in f.get("observations", [])[:3]:
                tool = obs.get("source_tool", "")
                detail = obs.get("detail", {}) or {}
                extras = []
                for k in ("account", "delegation_type", "target_host",
                          "template", "esc_type", "hash_type", "port"):
                    if detail.get(k):
                        extras.append(f"{k}={detail[k]}")
                excerpt = detail.get("excerpt", "")
                if excerpt and not extras:
                    extras.append(excerpt[:150])
                if tool or extras:
                    parts.append(f"  source={tool} {' '.join(extras)}".rstrip())
            lines.append("\n".join(parts))
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


def _parse_attack_paths(raw: str) -> str:
    if not raw or not raw.strip():
        return "<p class='muted'>No attack-path analysis was generated.</p>"
    paragraphs = [p.strip() for p in raw.split("\n\n") if p.strip()]
    if not paragraphs:
        paragraphs = [p.strip() for p in raw.split("\n") if p.strip()]
    parts: list[str] = []
    for p in paragraphs:
        escaped = _e(p)
        if p.startswith("##") or p.startswith("**Path"):
            parts.append(f"<h3>{_e(p.lstrip('#* '))}</h3>")
        elif p.startswith("- ") or p.startswith("* "):
            items = [_e(line.lstrip("-* ").strip()) for line in p.split("\n") if line.strip()]
            parts.append("<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>")
        elif " → " in p or " -> " in p:
            parts.append(f"<p class='attack-chain'>{escaped}</p>")
        else:
            parts.append(f"<p>{escaped}</p>")
    return "\n".join(parts)


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


def render_html(data: ReportData, *, summary: str = "", attack_paths: str = "",
                remediation: str = "", title: str = "Assessment report",
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
    attack_paths_html = _parse_attack_paths(attack_paths)
    remediation_html = _parse_remediation(remediation)

    gaps_html = ""
    if data.coverage_gaps:
        gap_items = "".join(f"<li>{_e(g)}</li>" for g in data.coverage_gaps)
        gaps_html = f'<ul class="gap-list">{gap_items}</ul>'
    else:
        gaps_html = "<p class='muted'>No coverage gaps recorded.</p>"

    risk_color = _SEV_COLOR.get(data.overall_risk, "#475569")
    mode_label = _MODE_LABEL.get(data.testing_mode, data.testing_mode)
    type_label = _TYPE_LABEL.get(data.target_type, data.target_type)
    domains_str = ", ".join(_e(d) for d in data.domains[:10]) if data.domains else "—"

    risk_matrix_html = _render_risk_matrix(data)

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

  /* TOC */
  .toc {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px;
          padding:14px 20px; margin:16px 0; page-break-after:avoid; }}
  .toc h2 {{ border:none; margin:0 0 8px; padding:0; }}
  .toc ol {{ padding-left:18px; margin:0; }}
  .toc li {{ margin:3px 0; font-size:12px; color:#334155; }}
  .toc a {{ color:#1e40af; text-decoration:none; }}
  .toc a:hover {{ text-decoration:underline; }}

  h2 {{ font-size:12px; font-weight:700; margin:20px 0 8px; padding-bottom:4px;
       border-bottom:1.5px solid #cbd5e1; text-transform:uppercase;
       letter-spacing:.05em; color:#334155; }}
  h3 {{ font-size:12px; font-weight:600; margin:10px 0 4px; color:#475569; }}
  .meta {{ color:#64748b; font-size:11px; }}
  .mono {{ font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; font-size:0.92em; }}

  /* Engagement info table */
  .info-table {{ width:100%; border-collapse:collapse; margin:8px 0; font-size:12px; }}
  .info-table td {{ padding:5px 10px; border-bottom:1px solid #f1f5f9; vertical-align:top; }}
  .info-table td:first-child {{ font-weight:600; color:#475569; width:160px; white-space:nowrap; }}

  /* Severity row */
  .sevrow {{ display:flex; gap:16px; flex-wrap:wrap; margin:14px 0 6px; padding:10px 16px;
            background:#f8fafc; border-radius:6px; border:1px solid #e2e8f0;
            print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .sev {{ display:flex; align-items:center; gap:5px; }}
  .sev .dot {{ width:8px; height:8px; border-radius:50%; display:inline-block;
              print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .sev .n {{ font-weight:700; font-size:15px; }}
  .sev .lbl {{ color:#64748b; font-size:10px; text-transform:uppercase; letter-spacing:.04em; }}

  /* Overall risk badge */
  .risk-badge {{ display:inline-block; color:#fff; font-size:11px; font-weight:700;
                 text-transform:uppercase; letter-spacing:.06em; padding:3px 12px;
                 border-radius:4px; margin-left:8px;
                 print-color-adjust:exact; -webkit-print-color-adjust:exact; }}

  /* Risk matrix */
  .risk-matrix {{ margin:10px 0; overflow-x:auto; }}
  .risk-matrix table {{ border-collapse:collapse; font-size:10px; min-width:400px; }}
  .risk-matrix th, .risk-matrix td {{ padding:6px 10px; border:1px solid #e2e8f0; text-align:center;
                                      print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .risk-matrix th {{ background:#f1f5f9; font-weight:700; color:#475569; text-transform:uppercase;
                     letter-spacing:.04em; }}
  .risk-matrix .rm-label {{ text-align:right; font-weight:600; color:#475569; background:#f8fafc; }}
  .rm-crit {{ background:#fef2f2; }}
  .rm-high {{ background:#fff7ed; }}
  .rm-med {{ background:#fffbeb; }}
  .rm-low {{ background:#f0fdf4; }}
  .rm-info {{ background:#f8fafc; }}
  .rm-count {{ font-weight:700; font-size:13px; }}

  /* Summary box */
  .summary-box {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px;
                  padding:12px 16px; margin:6px 0; }}
  .summary-box p {{ margin:0; font-size:13px; line-height:1.55; }}

  /* Methodology */
  .methodology {{ background:#fafaf9; border:1px solid #e7e5e4; border-radius:6px;
                  padding:12px 16px; margin:6px 0; font-size:12px; color:#44403c; }}
  .methodology p {{ margin:0 0 6px; }}
  .methodology ol {{ padding-left:18px; margin:4px 0 8px; }}
  .methodology li {{ margin:3px 0; }}
  .methodology .phase-label {{ font-weight:600; color:#292524; }}

  /* Findings */
  .finding {{ border:1px solid #e2e8f0; border-radius:6px; padding:8px 12px; margin:5px 0;
             page-break-inside:avoid; }}
  .fhead {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }}
  .badge {{ color:#fff; font-size:9px; text-transform:uppercase; letter-spacing:.05em;
            padding:1px 6px; border-radius:3px; font-weight:700;
            print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .status {{ font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:.04em; }}
  .ftitle {{ font-weight:600; font-size:12px; }}
  .cvss-pill {{ font-size:9px; font-weight:700; color:#fff; padding:1px 6px; border-radius:3px;
                font-family: ui-monospace, monospace;
                print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
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

  /* Coverage gaps */
  .gap-list {{ padding-left:18px; margin:6px 0; font-size:12px; }}
  .gap-list li {{ margin:3px 0; color:#64748b; }}

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

  .attack-paths {{ background:#f0f9ff; border:1px solid #bae6fd; border-radius:6px;
                   padding:10px 14px; margin:10px 0;
                   print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
  .attack-paths p {{ margin:0 0 6px; color:#0c4a6e; font-size:12px; }}
  .attack-paths h3 {{ font-size:12px; font-weight:600; color:#075985; margin:8px 0 4px; }}
  .attack-paths ul {{ padding-left:18px; margin:4px 0; }}
  .attack-paths li {{ margin:3px 0; color:#0c4a6e; font-size:12px; }}
  .attack-chain {{ font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
                   font-size:11px; background:#e0f2fe; padding:4px 8px; border-radius:4px;
                   word-break:break-all; color:#0369a1; }}

  footer {{ margin-top:24px; padding:12px 0; border-top:1.5px solid #cbd5e1;
            color:#94a3b8; font-size:10px; display:flex; align-items:center;
            justify-content:space-between; }}
  .footer-left {{ display:flex; flex-direction:column; gap:2px; }}

  .section {{ page-break-before:auto; }}
  .section-break {{ page-break-before:always; }}

  @media print {{
    body {{ font-size:11px; }}
    .container {{ padding:16px 24px; }}
    .report-header {{ padding:14px 0; }}
    h2 {{ margin:14px 0 6px; }}
    .toc {{ page-break-after:always; }}
    .section-break {{ page-break-before:always; }}
  }}
  @page {{ size:A4; margin:12mm 10mm; }}
  @page :first {{ margin-top:0; }}
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
            {_e(mode_label)} / {_e(type_label)} &middot;
            run <span class="mono">{_e(data.run_id[:8])}</span>
          </div>
        </div>
      </div>
      <div class="hdr-badge {'hdr-badge-final' if report_status == 'final' else 'hdr-badge-draft'}">{'FINAL' if report_status == 'final' else 'DRAFT'} &middot; {_e(data.generated_at)}</div>
    </div>
  </div>

  <div class="container">
    <!-- Table of Contents -->
    <div class="toc">
      <h2 style="border:none; margin:0 0 8px; padding:0;">Table of Contents</h2>
      <ol>
        <li><a href="#engagement-info">Engagement Information</a></li>
        <li><a href="#exec-summary">Executive Summary</a></li>
        <li><a href="#risk-matrix">Risk Matrix</a></li>
        <li><a href="#methodology">Methodology</a></li>
        <li><a href="#findings">Findings</a> ({c.get('total', 0)})</li>
        <li><a href="#attack-paths">Attack Paths &amp; Kill Chains</a></li>
        <li><a href="#remediation">Remediation Guidance</a></li>
        <li><a href="#coverage-gaps">Coverage Gaps</a> ({len(data.coverage_gaps)})</li>
      </ol>
    </div>

    <!-- 1. Engagement Information -->
    <h2 id="engagement-info">Engagement Information</h2>
    <table class="info-table">
      <tr><td>Engagement</td><td>{_e(data.engagement_name)}</td></tr>
      <tr><td>Project</td><td>{_e(data.project_name)}</td></tr>
      <tr><td>Testing Mode</td><td>{_e(mode_label)}</td></tr>
      <tr><td>Target Type</td><td>{_e(type_label)}</td></tr>
      <tr><td>In-Scope Domains</td><td><span class="mono">{domains_str}</span></td></tr>
      {f'<tr><td>Target Description</td><td>{_e(data.target_description)}</td></tr>' if data.target_description else ''}
      <tr><td>Run ID</td><td><span class="mono">{_e(data.run_id)}</span></td></tr>
      {f'<tr><td>Scan Started</td><td>{_e(data.run_started)}</td></tr>' if data.run_started else ''}
      {f'<tr><td>Scan Ended</td><td>{_e(data.run_ended)}</td></tr>' if data.run_ended else ''}
      <tr><td>Report Generated</td><td>{_e(data.generated_at)}</td></tr>
      <tr><td>Report Status</td><td>{'Final' if report_status == 'final' else 'Draft'}</td></tr>
      <tr><td>Overall Risk</td><td><span class="risk-badge" style="background:{risk_color}">{_e(data.overall_risk)}</span></td></tr>
    </table>

    <!-- 2. Executive Summary -->
    <h2 id="exec-summary" class="section-break">Executive Summary</h2>
    <div class="sevrow">{sev_cards}</div>
    <div class="meta">
      {c.get("total", 0)} findings &middot; {c.get("confirmed", 0)} confirmed &middot;
      {c.get("candidate", 0)} candidate &middot; {c.get("inconclusive", 0)} inconclusive
    </div>
    <div class="summary-box">{summary_html}</div>

    <!-- 3. Risk Matrix -->
    <h2 id="risk-matrix">Risk Matrix</h2>
    {risk_matrix_html}

    <!-- 4. Methodology -->
    <h2 id="methodology" class="section-break">Methodology</h2>
    <div class="methodology">
      <p>This assessment was conducted using VAPT-AI, an AI-driven vulnerability assessment
      and penetration testing platform. The methodology follows industry standards including
      OWASP Testing Guide, PTES, and NIST SP 800-115.</p>
      <ol>
        <li><span class="phase-label">Reconnaissance &amp; Discovery:</span>
          Automated asset enumeration, port scanning (nmap), and service fingerprinting
          to map the attack surface.</li>
        <li><span class="phase-label">Vulnerability Scanning:</span>
          Multi-engine scanning using nuclei (template-based), wapiti (web crawler),
          and specialized detectors for common vulnerability classes.</li>
        <li><span class="phase-label">Authentication Testing:</span>
          {'Authenticated scanning with provided credentials and session management analysis.'
           if data.testing_mode != 'black_box' else
           'Unauthenticated black-box testing with automated self-registration where possible.'}</li>
        <li><span class="phase-label">Vulnerability Validation:</span>
          AI-assisted triage to confirm findings, eliminate false positives, and assess
          real-world exploitability. Each finding is classified as confirmed, candidate,
          or inconclusive.</li>
        <li><span class="phase-label">Attack Path Analysis:</span>
          Chaining of confirmed vulnerabilities to identify multi-step attack scenarios
          and assess aggregate risk.</li>
        <li><span class="phase-label">Reporting &amp; Remediation:</span>
          Findings are mapped to MITRE ATT&amp;CK, CWE, and OWASP frameworks with
          prioritized remediation guidance.</li>
      </ol>
      <p>All testing was conducted within the authorized scope. Intrusive actions (P2+) required
      explicit human approval before execution.</p>
    </div>

    <!-- 5. Findings -->
    <h2 id="findings" class="section-break">Findings</h2>
    {findings_html}

    <!-- 6. Attack Paths -->
    <h2 id="attack-paths" class="section-break">Attack Paths &amp; Kill Chains</h2>
    <div class="attack-paths">{attack_paths_html}</div>

    <!-- 7. Remediation -->
    <h2 id="remediation">Remediation Guidance</h2>
    {remediation_html}

    <!-- 8. Coverage Gaps -->
    <h2 id="coverage-gaps">Coverage Gaps</h2>
    {gaps_html}

    <footer>
      <div class="footer-left">
        <span>{'Signed-off report.' if report_status == 'final' else 'Draft &mdash; review before release.'}
          Generated by VAPT-AI.</span>
        <span>Tamkeen Technologies &middot; Confidential</span>
      </div>
      <span>{_LOGO_SVG}</span>
    </footer>
  </div>
</body></html>"""


def _render_risk_matrix(data: ReportData) -> str:
    c = data.counts
    statuses = ["confirmed", "candidate", "inconclusive"]
    status_labels = {"confirmed": "Confirmed", "candidate": "Candidate", "inconclusive": "Inconclusive"}
    rm_cls = {"critical": "rm-crit", "high": "rm-high", "medium": "rm-med",
              "low": "rm-low", "info": "rm-info"}

    counts_by: dict[tuple[str, str], int] = {}
    for sev in SEVERITY_ORDER:
        for f in data.findings_by_sev.get(sev, []):
            key = (sev, f["status"])
            counts_by[key] = counts_by.get(key, 0) + 1

    header = "".join(f"<th>{status_labels.get(st, st)}</th>" for st in statuses)
    rows = []
    for sev in SEVERITY_ORDER:
        cells = []
        for st in statuses:
            n = counts_by.get((sev, st), 0)
            cells.append(f'<td class="{rm_cls.get(sev, "")}"><span class="rm-count">{n}</span></td>')
        color = _SEV_COLOR.get(sev, "#475569")
        rows.append(
            f'<tr><td class="rm-label">'
            f'<span class="badge" style="background:{color}">{_e(sev)}</span> '
            f'CVSS {_CVSS_FROM_SEV.get(sev, 0.0):.1f}+</td>{"".join(cells)}'
            f'<td style="font-weight:700">{c.get(sev, 0)}</td></tr>'
        )

    return (
        '<div class="risk-matrix"><table>'
        f'<tr><th>Severity / CVSS</th>{header}<th>Total</th></tr>'
        f'{"".join(rows)}'
        f'<tr style="background:#f1f5f9; font-weight:700"><td>Total</td>'
        + "".join(
            f'<td>{sum(counts_by.get((s, st), 0) for s in SEVERITY_ORDER)}</td>'
            for st in statuses
        )
        + f'<td>{c.get("total", 0)}</td></tr>'
        '</table></div>'
    )


def _cvss_color(score: float) -> str:
    if score >= 9.0:
        return _SEV_COLOR["critical"]
    if score >= 7.0:
        return _SEV_COLOR["high"]
    if score >= 4.0:
        return _SEV_COLOR["medium"]
    if score > 0:
        return _SEV_COLOR["low"]
    return _SEV_COLOR["info"]


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

    cvss = f.get("cvss", 0.0)
    cvss_html = ""
    if cvss > 0:
        cvss_html = (f'<span class="cvss-pill" style="background:{_cvss_color(cvss)}">'
                     f'CVSS {cvss:.1f}</span>')

    return (
        f'<div class="finding">'
        f'<div class="fhead"><span class="badge" style="background:{_SEV_COLOR[s]}">{_e(s)}</span>'
        f'{cvss_html}'
        f'<span class="status">{_e(f["status"])}</span>'
        f'<span class="ftitle">{_e(f["title"])}</span></div>'
        f'{chips_html}'
        f'{("<p class=fdesc>" + _e(f["description"]) + "</p>") if f["description"] else ""}'
        f'<ul class="evidence">{ev}</ul></div>'
    )


def build_and_store(db: Session, run_id: str, *, summary: str = "",
                    attack_paths: str = "", remediation: str = "",
                    generated_by: str = "reporting-agent", title: str = "Assessment report"):
    """Gather the run's findings, render the HTML report, and persist a new draft Report
    row. Returns the Report. A re-run creates a new draft; a reviewer signs off a specific
    report via the API, and finals are never overwritten."""
    from vapt_persistence.models import Report

    data = gather(db, run_id)
    content = render_html(data, summary=summary, attack_paths=attack_paths,
                          remediation=remediation, title=title)
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
