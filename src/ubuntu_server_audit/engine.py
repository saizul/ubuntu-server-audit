"""Run checks, turning every exception into a result. The audit never crashes on one check."""

from __future__ import annotations

import contextlib
import fnmatch
import getpass
import logging
import socket
import time
from datetime import datetime, timezone

from ubuntu_server_audit._version import __version__
from ubuntu_server_audit.context import AuditContext, NeedsRoot, NotApplicable
from ubuntu_server_audit.model import AuditReport, Finding, HostInfo, Outcome, Status
from ubuntu_server_audit.parsers import parse_os_release
from ubuntu_server_audit.registry import Check, all_checks

log = logging.getLogger("ubuntu_server_audit")


def select_checks(checks: list[Check], only: list[str] | None = None, skip: list[str] | None = None) -> list[Check]:
    """Filter by check ID or category; shell-style wildcards work (``SSH-*``)."""

    def matches(c: Check, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(c.spec.id.lower(), p.lower()) or c.spec.category == p.lower() for p in patterns)

    out = [c for c in checks if not only or matches(c, only)]
    return [c for c in out if not skip or not matches(c, skip)]


def run_check(check: Check, ctx: AuditContext) -> Finding:
    spec = check.spec
    finding = Finding(
        id=spec.id,
        title=spec.title,
        category=spec.category,
        severity=spec.severity,
        status=Status.SKIPPED,
        summary="",
        evidence=[],
        fix=spec.fix,
        references=spec.references,
        needs_root=spec.needs_root,
    )
    if spec.needs_root and not ctx.is_root:
        finding.skipped_reason = "needs root"
        finding.summary = "Run as root to include this check."
        return finding
    started = time.perf_counter()
    try:
        outcome: Outcome = check.fn(ctx)
    except NeedsRoot as exc:
        finding.status, finding.skipped_reason = Status.SKIPPED, "needs root"
        finding.summary = f"Run as root to include this check ({exc.reason})."
    except NotApplicable as exc:
        finding.status, finding.summary = Status.NOT_APPLICABLE, exc.reason
    except PermissionError as exc:
        if ctx.is_root:
            finding.status, finding.summary = Status.ERROR, f"permission denied even as root: {exc}"
        else:
            finding.status, finding.skipped_reason = Status.SKIPPED, "needs root"
            finding.summary = f"Run as root to include this check ({exc})."
    except Exception as exc:  # a bug or an unexpected system: report it, keep auditing
        log.debug("check %s failed", spec.id, exc_info=True)
        finding.status, finding.summary = Status.ERROR, f"{type(exc).__name__}: {exc}"
    else:
        finding.status = outcome.status
        finding.summary = outcome.summary
        finding.evidence = list(outcome.evidence)
        finding.partial = outcome.partial
        finding.partial_reason = outcome.partial_reason
        if outcome.fix:
            finding.fix = outcome.fix
    finding.duration_ms = round((time.perf_counter() - started) * 1000, 1)
    return finding


def host_info(ctx: AuditContext) -> HostInfo:
    info = HostInfo(is_root=ctx.is_root)
    release = ctx.try_read("/etc/os-release")
    if release.ok:
        data = parse_os_release(release.text or "")
        info.os_name = data.get("PRETTY_NAME", "")
        info.os_id = data.get("ID", "")
        info.os_version = data.get("VERSION_ID", "")
    hostname = ctx.try_read("/proc/sys/kernel/hostname")
    info.hostname = (hostname.text or "").strip() if hostname.ok else socket.gethostname()
    kernel = ctx.try_read("/proc/sys/kernel/osrelease")
    info.kernel = (kernel.text or "").strip() if kernel.ok else ""
    uptime = ctx.try_read("/proc/uptime")
    if uptime.ok and uptime.text:
        with contextlib.suppress(ValueError, IndexError):
            info.uptime_s = float(uptime.text.split()[0])
    try:
        info.user = getpass.getuser()
    except Exception:  # no passwd entry in some containers
        info.user = ""
    return info


def run_audit(ctx: AuditContext, checks: list[Check] | None = None) -> AuditReport:
    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    t0 = time.perf_counter()
    checks = checks if checks is not None else all_checks()
    findings = [run_check(c, ctx) for c in checks]
    return AuditReport(
        host=host_info(ctx),
        findings=findings,
        started_at=started_at,
        duration_s=round(time.perf_counter() - t0, 2),
        tool_version=__version__,
    )
