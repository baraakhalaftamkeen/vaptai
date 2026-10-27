"""Retest comparison (plan §5, BAR-29).

Compare a run's confirmed findings against a prior run's to show what a fix cycle
changed: fixed (was confirmed, no longer), still-open (confirmed in both), and new
(confirmed now, not before). Findings are matched by their deterministic title, which
analyzers and normalizers produce stably for the same issue (e.g.
"py.sqli at app/db.py:12", "Open port 22 (ssh)")."""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_persistence.models import Finding


def _confirmed_titles(db: Session, run_id: str) -> dict[str, dict]:
    rows = db.execute(
        select(Finding).where(Finding.run_id == run_id, Finding.status == "confirmed")
    ).scalars().all()
    # Keep one entry per title (latest wins); carry severity for display.
    return {f.title: {"title": f.title, "severity": f.severity} for f in rows}


@dataclass
class RetestResult:
    current_run_id: str
    prior_run_id: str
    fixed: list[dict] = field(default_factory=list)
    still_open: list[dict] = field(default_factory=list)
    new: list[dict] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {"fixed": len(self.fixed), "still_open": len(self.still_open), "new": len(self.new)}


def compare_runs(db: Session, current_run_id: str, prior_run_id: str) -> RetestResult:
    cur = _confirmed_titles(db, current_run_id)
    prior = _confirmed_titles(db, prior_run_id)
    res = RetestResult(current_run_id=current_run_id, prior_run_id=prior_run_id)
    for title, f in prior.items():
        (res.still_open if title in cur else res.fixed).append(f)
    for title, f in cur.items():
        if title not in prior:
            res.new.append(f)
    return res
