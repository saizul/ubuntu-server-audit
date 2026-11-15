"""Self-contained HTML report (no scripts, no external resources)."""

from __future__ import annotations

from html import escape

from ubuntu_server_audit.model import STATUS_LABEL, AuditReport, Finding
from ubuntu_server_audit.report.common import actionable, grouped, uptime_text
from ubuntu_server_audit.scoring import compute

CSS = """
:root{--bg:#fff;--fg:#1d2330;--muted:#5d6676;--line:#e3e6eb;--card:#f6f7f9;--fail:#b42318;--warn:#b54708;
--pass:#067647;--info:#175cd3;--skip:#667085}
@media (prefers-color-scheme:dark){:root{--bg:#11141a;--fg:#e6e8ec;--muted:#9aa3b2;--line:#2a2f39;--card:#1a1e26;
--fail:#f97066;--warn:#fdb022;--pass:#47cd89;--info:#84adff;--skip:#98a2b3}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--fg)}main{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:32px 0 10px}.muted{color:var(--muted)}
.score{display:flex;gap:16px;align-items:center;margin:18px 0}.ring{width:96px;height:96px;border-radius:50%;
display:grid;place-items:center;font-size:28px;font-weight:700;border:8px solid var(--line)}
.A,.B{border-color:var(--pass)}.C,.D{border-color:var(--warn)}.F{border-color:var(--fail)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:7px 8px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.s{font-weight:700;font-size:12px;white-space:nowrap}.fail{color:var(--fail)}.warn{color:var(--warn)}
.pass{color:var(--pass)}.info{color:var(--info)}.skipped,.na{color:var(--skip)}.error{color:var(--fail)}
details{margin-top:4px}summary{cursor:pointer;color:var(--muted);font-size:13px}
ul.ev{margin:4px 0 0;padding-left:18px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.fix{font-size:13px;white-space:pre-wrap}.banner{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:10px 14px}footer{margin-top:40px;font-size:12px;color:var(--muted)}
"""


def _cls(f: Finding) -> str:
    return "na" if f.status.value == "n/a" else f.status.value


def _status(f: Finding) -> str:
    text = STATUS_LABEL[f.status]
    if f.skipped_reason:
        text += f" ({f.skipped_reason})"
    elif f.partial and f.status.scored:
        text += " (partial)"
    return f'<span class="s {_cls(f)}">{escape(text)}</span>'


def _details(f: Finding) -> str:
    parts = []
    if f.evidence:
        items = "".join(f"<li>{escape(e)}</li>" for e in f.evidence[:40])
        parts.append(f'<details><summary>evidence ({len(f.evidence)})</summary><ul class="ev">{items}</ul></details>')
    if f.partial_reason:
        parts.append(f'<div class="muted">{escape(f.partial_reason)}</div>')
    return "".join(parts)


def render_html(report: AuditReport) -> str:
    score = compute(report.findings)
    h = report.host
    counts = report.counts()
    out = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">',
        f"<title>Server audit: {escape(h.hostname)}</title><style>{CSS}</style></head><body><main>",
        f"<h1>Server audit: {escape(h.hostname)}</h1>",
        f'<p class="muted">{escape(h.os_name or "?")} &middot; kernel {escape(h.kernel or "?")} &middot; uptime '
        f"{escape(uptime_text(h.uptime_s))} &middot; {escape(report.started_at)}</p>",
        '<div class="score">',
        f'<div class="ring {score.grade}">{score.score}</div>',
        f"<div><b>Grade {score.grade}</b><br>{score.scored} scored checks: {counts['fail']} fail, "
        f'{counts["warn"]} warn, {counts["pass"]} pass<br><span class="muted">{counts["skipped"]} skipped, '
        f"{counts['n/a']} not applicable, {counts['error']} error</span></div></div>",
    ]
    if not h.is_root:
        out.append(
            f'<p class="banner">Run as <b>{escape(h.user or "a normal user")}</b>: '
            f"{score.skipped_needs_root} check(s) were skipped (needs root). Run with sudo for full results.</p>"
        )
    todo = actionable(report)
    if todo:
        out.append(
            "<h2>Fix first</h2><table><thead><tr><th>Severity</th><th>Check</th><th>Problem</th><th>Fix</th>"
            "</tr></thead><tbody>"
        )
        for f in todo:
            out.append(
                f"<tr><td>{escape(f.severity.value)}</td><td>{escape(f.id)}</td><td>{escape(f.summary)}</td>"
                f'<td class="fix">{escape(f.fix)}</td></tr>'
            )
        out.append("</tbody></table>")
    for title, findings in grouped(report):
        out.append(
            f"<h2>{escape(title)}</h2><table><thead><tr><th>Status</th><th>ID</th><th>Check</th>"
            "<th>Severity</th><th>Result</th></tr></thead><tbody>"
        )
        for f in findings:
            out.append(
                f"<tr><td>{_status(f)}</td><td>{escape(f.id)}</td><td>{escape(f.title)}</td>"
                f"<td>{escape(f.severity.value)}</td><td>{escape(f.summary)}{_details(f)}</td></tr>"
            )
        out.append("</tbody></table>")
    out.append(
        f"<footer>ubuntu-server-audit {escape(report.tool_version)}, read-only audit</footer></main></body></html>"
    )
    return "\n".join(out) + "\n"
