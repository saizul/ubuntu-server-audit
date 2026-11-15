"""JSON report (schema 1)."""

from __future__ import annotations

import json
from typing import Any

from ubuntu_server_audit.model import AuditReport
from ubuntu_server_audit.scoring import compute

SCHEMA_VERSION = 1


def to_dict(report: AuditReport) -> dict[str, Any]:
    score = compute(report.findings)
    h = report.host
    return {
        "tool": "ubuntu-server-audit",
        "version": report.tool_version,
        "schema": SCHEMA_VERSION,
        "started_at": report.started_at,
        "duration_s": report.duration_s,
        "host": {
            "hostname": h.hostname,
            "os": h.os_name,
            "os_id": h.os_id,
            "os_version": h.os_version,
            "kernel": h.kernel,
            "uptime_s": h.uptime_s,
            "user": h.user,
            "is_root": h.is_root,
        },
        "score": {
            "score": score.score,
            "grade": score.grade,
            "scored_checks": score.scored,
            "applicable_checks": score.total,
            "skipped_needs_root": score.skipped_needs_root,
            "earned": score.earned,
            "possible": score.possible,
        },
        "counts": report.counts(),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "status": f.status.value,
                "status_text": f.status_text,
                "summary": f.summary,
                "evidence": f.evidence,
                "fix": f.fix,
                "references": list(f.references),
                "needs_root": f.needs_root,
                "partial": f.partial,
                "partial_reason": f.partial_reason or None,
                "skipped_reason": f.skipped_reason or None,
                "duration_ms": f.duration_ms,
            }
            for f in report.findings
        ],
    }


def render_json(report: AuditReport) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"
