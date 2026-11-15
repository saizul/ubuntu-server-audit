"""Run selected checks from Python and act on the results.

sudo python3 examples/library_usage.py
"""

from __future__ import annotations

import os

from ubuntu_server_audit import AuditContext, Status, all_checks, compute_score, run_audit, select_checks
from ubuntu_server_audit.system import RealFileSystem, SubprocessRunner


def main() -> int:
    ctx = AuditContext(SubprocessRunner(), RealFileSystem(), is_root=os.geteuid() == 0)
    checks = select_checks(all_checks(), only=["ssh", "firewall", "UPD-*"])
    report = run_audit(ctx, checks)
    for finding in report.findings:
        if finding.status in (Status.FAIL, Status.WARN):
            print(f"{finding.id} [{finding.severity.value}] {finding.summary}")
            print(f"    fix: {finding.fix}")
        elif finding.status is Status.SKIPPED:
            print(f"{finding.id} {finding.status_text}")
    score = compute_score(report.findings)
    print(f"score {score.score}/100 ({score.grade}), {score.scored} checks scored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
