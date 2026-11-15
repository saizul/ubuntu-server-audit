"""Markdown report."""

from __future__ import annotations

from ubuntu_server_audit.model import STATUS_LABEL, AuditReport
from ubuntu_server_audit.report.common import actionable, grouped, uptime_text
from ubuntu_server_audit.scoring import compute


def md(text: object) -> str:
    value = "" if text is None else str(text)
    value = value.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    value = value.replace("<", "&lt;").replace(">", "&gt;")
    for ch in "`*_[]":
        value = value.replace(ch, "\\" + ch)
    return value


def render_markdown(report: AuditReport) -> str:
    score = compute(report.findings)
    h = report.host
    lines = [
        f"# Server audit: {md(h.hostname)}",
        "",
        f"**Score {score.score}/100 (grade {score.grade})** from {score.scored} scored checks.",
        "",
        f"- OS: {md(h.os_name or '?')}, kernel {md(h.kernel or '?')}, uptime {uptime_text(h.uptime_s)}",
        f"- Run as: {md(h.user or '?')}"
        + ("" if h.is_root and h.user == "root" else " (root)" if h.is_root else " (not root, some checks skipped)"),
        f"- Date: {md(report.started_at)}, ubuntu-server-audit {md(report.tool_version)}",
        "",
    ]
    if score.skipped_needs_root:
        lines += [
            f"> {score.skipped_needs_root} check(s) were skipped (needs root). Run with sudo for full results.",
            "",
        ]
    todo = actionable(report)
    if todo:
        lines += ["## Fix first", "", "| Severity | ID | Problem | Fix |", "| --- | --- | --- | --- |"]
        for f in todo:
            lines.append(f"| {f.severity.value} | {f.id} | {md(f.summary)} | {md(f.fix)} |")
        lines.append("")
    lines += ["## All checks", ""]
    for title, findings in grouped(report):
        lines += [
            f"### {md(title)}",
            "",
            "| Status | ID | Check | Severity | Result |",
            "| --- | --- | --- | --- | --- |",
        ]
        for f in findings:
            status = STATUS_LABEL[f.status] + (" (needs root)" if f.skipped_reason == "needs root" else "")
            if f.partial and f.status.scored:
                status += " (partial)"
            lines.append(f"| {status} | {f.id} | {md(f.title)} | {f.severity.value} | {md(f.summary)} |")
        lines.append("")
    details = [f for f in report.findings if f.evidence and f.status.value in ("fail", "warn", "error", "info")]
    if details:
        lines += ["## Evidence", ""]
        for f in details:
            lines += [f"**{f.id} {md(f.title)}**", ""]
            lines += [f"- {md(e)}" for e in f.evidence[:30]]
            lines.append("")
    return "\n".join(lines) + "\n"
