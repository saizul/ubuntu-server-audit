"""The audit score: a severity-weighted share of passed checks."""

from __future__ import annotations

from dataclasses import dataclass

from ubuntu_server_audit.model import AuditReport, Finding, Severity, Status

#: Credit per status: a warning earns half the weight.
CREDIT = {Status.PASS: 1.0, Status.WARN: 0.5, Status.FAIL: 0.0}
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


@dataclass(frozen=True)
class Score:
    score: int
    grade: str
    scored: int
    total: int
    skipped_needs_root: int
    earned: float
    possible: float

    @property
    def coverage(self) -> float:
        return self.scored / self.total if self.total else 0.0


def compute(findings: list[Finding]) -> Score:
    """``score = 100 * sum(weight * credit) / sum(weight)`` over pass/warn/fail findings.

    Weights: critical 10, high 6, medium 3, low 1, info 0. Skipped, not applicable, informational and errored
    checks do not count, so a normal-user run scores fewer checks (see ``coverage``).
    """
    earned = possible = 0.0
    scored = 0
    for f in findings:
        if not f.status.scored or f.severity is Severity.INFO:
            continue
        scored += 1
        possible += f.severity.weight
        earned += f.severity.weight * CREDIT[f.status]
    value = round(100 * earned / possible) if possible else 100
    grade = next(g for limit, g in GRADES if value >= limit)
    skipped = sum(1 for f in findings if f.status is Status.SKIPPED and f.skipped_reason == "needs root")
    applicable = sum(1 for f in findings if f.status is not Status.NOT_APPLICABLE and f.severity is not Severity.INFO)
    return Score(value, grade, scored, applicable, skipped, round(earned, 1), round(possible, 1))


def score_report(report: AuditReport) -> Score:
    return compute(report.findings)


def worst_failure(findings: list[Finding]) -> Severity | None:
    fails = [f.severity for f in findings if f.status is Status.FAIL]
    return min(fails, key=lambda s: s.rank) if fails else None
