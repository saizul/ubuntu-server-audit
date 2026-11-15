"""Plain-text report for the terminal."""

from __future__ import annotations

from ubuntu_server_audit.model import STATUS_LABEL, AuditReport, Finding, Status
from ubuntu_server_audit.report.common import actionable, grouped, uptime_text
from ubuntu_server_audit.scoring import compute

COLORS = {
    Status.PASS: "32",
    Status.WARN: "33",
    Status.FAIL: "31",
    Status.ERROR: "35",
    Status.SKIPPED: "90",
    Status.INFO: "36",
    Status.NOT_APPLICABLE: "90",
}


def _label(f: Finding, color: bool) -> str:
    text = STATUS_LABEL[f.status]
    padded = f"[{text}]".ljust(7)
    return f"\033[{COLORS[f.status]}m{padded}\033[0m" if color else padded


def _clean(text: str) -> str:
    """Remove control characters (data from the system is printed as-is otherwise)."""
    return "".join(ch if ch == "\n" or ch >= " " else "?" for ch in text)


def render_text(report: AuditReport, *, color: bool = False, verbose: bool = False) -> str:
    score = compute(report.findings)
    h = report.host
    lines = [
        _clean(
            f"ubuntu-server-audit {report.tool_version}  {h.hostname}  {h.os_name or '?'}  kernel {h.kernel or '?'}  "
            f"uptime {uptime_text(h.uptime_s)}"
        ),
        _clean(f"running as {h.user or '?'}{' (root)' if h.is_root else ' (not root: some checks are skipped)'}"),
        "",
    ]
    for title, findings in grouped(report):
        lines.append(title)
        for f in findings:
            extra = ""
            if f.status is Status.SKIPPED and f.skipped_reason:
                extra = f" - skipped ({f.skipped_reason})"
            elif f.partial and f.status.scored:
                extra = " (partial)"
            lines.append(f"  {_label(f, color)} {f.id:<8} {_clean(f.title)}{extra}")
            if f.summary and (f.status is not Status.PASS or verbose) and f.status is not Status.SKIPPED:
                lines.append(f"           {_clean(f.summary)}")
            if verbose or f.actionable:
                for item in f.evidence[: (20 if verbose else 6)]:
                    lines.append(f"             - {_clean(item)}")
        lines.append("")
    todo = actionable(report)
    if todo:
        lines.append("Fix first:")
        for f in todo[:15]:
            fix = _clean(f.fix).replace("\n", "\n" + " " * 17)
            lines.append(f"  {f.severity.value.upper():<8} {f.id:<8} {fix}")
        lines.append("")
    counts = report.counts()
    lines.append(
        f"Score {score.score}/100 (grade {score.grade}) from {score.scored} scored checks; "
        f"{counts['fail']} fail, {counts['warn']} warn, {counts['pass']} pass, {counts['skipped']} skipped, "
        f"{counts['n/a']} n/a, {counts['error']} error"
    )
    if score.skipped_needs_root:
        lines.append(f"{score.skipped_needs_root} check(s) skipped (needs root): run with sudo for full results.")
    return "\n".join(lines) + "\n"
