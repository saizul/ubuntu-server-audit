"""Helpers shared by the report writers."""

from __future__ import annotations

from ubuntu_server_audit.model import CATEGORIES, SEVERITY_RANK, AuditReport, Finding, Status

STATUS_ORDER = {
    Status.FAIL: 0,
    Status.WARN: 1,
    Status.ERROR: 2,
    Status.SKIPPED: 3,
    Status.INFO: 4,
    Status.PASS: 5,
    Status.NOT_APPLICABLE: 6,
}


def grouped(report: AuditReport) -> list[tuple[str, list[Finding]]]:
    out: dict[str, list[Finding]] = {}
    for f in report.findings:
        out.setdefault(f.category, []).append(f)
    return [(CATEGORIES.get(cat, cat), items) for cat, items in out.items()]


def actionable(report: AuditReport) -> list[Finding]:
    """FAIL and WARN findings, most severe first."""
    items = [f for f in report.findings if f.actionable]
    return sorted(items, key=lambda f: (STATUS_ORDER[f.status], SEVERITY_RANK[f.severity], f.id))


def uptime_text(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    days, rest = divmod(int(seconds), 86400)
    return f"{days}d {rest // 3600}h"
