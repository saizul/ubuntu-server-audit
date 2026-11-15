"""Report writers."""

from __future__ import annotations

from pathlib import Path

from ubuntu_server_audit.model import AuditReport
from ubuntu_server_audit.report.html_report import render_html
from ubuntu_server_audit.report.json_report import render_json
from ubuntu_server_audit.report.markdown import render_markdown
from ubuntu_server_audit.report.text import render_text

FORMATS = ("text", "json", "markdown", "html")
EXTENSIONS = {"text": "txt", "json": "json", "markdown": "md", "html": "html"}


def render(report: AuditReport, fmt: str, *, color: bool = False, verbose: bool = False) -> str:
    if fmt == "text":
        return render_text(report, color=color, verbose=verbose)
    if fmt == "json":
        return render_json(report)
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    raise ValueError(f"unknown format: {fmt}")


def write_reports(report: AuditReport, formats: list[str], outdir: Path, basename: str = "server-audit") -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    paths = []
    for fmt in formats:
        path = outdir / f"{basename}.{EXTENSIONS[fmt]}"
        path.write_text(render(report, fmt, verbose=True), encoding="utf-8")
        paths.append(path)
    return paths


__all__ = ["EXTENSIONS", "FORMATS", "render", "write_reports"]
