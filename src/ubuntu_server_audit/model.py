"""Findings, severities and statuses."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self]

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self]


SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
SEVERITY_WEIGHT = {Severity.CRITICAL: 10, Severity.HIGH: 6, Severity.MEDIUM: 3, Severity.LOW: 1, Severity.INFO: 0}


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "n/a"
    ERROR = "error"

    def __str__(self) -> str:
        return self.value

    @property
    def scored(self) -> bool:
        return self in (Status.PASS, Status.WARN, Status.FAIL)


STATUS_LABEL = {
    Status.PASS: "PASS",
    Status.WARN: "WARN",
    Status.FAIL: "FAIL",
    Status.INFO: "INFO",
    Status.SKIPPED: "SKIP",
    Status.NOT_APPLICABLE: "N/A",
    Status.ERROR: "ERROR",
}

CATEGORIES = {
    "ssh": "SSH",
    "firewall": "Firewall and network",
    "updates": "Updates",
    "kernel": "Kernel",
    "accounts": "Users and files",
    "web": "Web server and PHP",
    "database": "Databases",
    "housekeeping": "Housekeeping",
}


@dataclass
class Outcome:
    """What a check function returns."""

    status: Status
    summary: str
    evidence: list[str] = field(default_factory=list)
    #: True when some data could not be read (usually: run as root for full results).
    partial: bool = False
    partial_reason: str = ""
    fix: str | None = None


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    category: str
    severity: Severity
    fix: str
    needs_root: bool = False
    references: tuple[str, ...] = ()
    description: str = ""


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: Severity
    status: Status
    summary: str
    evidence: list[str]
    fix: str
    references: tuple[str, ...] = ()
    needs_root: bool = False
    partial: bool = False
    partial_reason: str = ""
    skipped_reason: str = ""
    duration_ms: float = 0.0

    @property
    def status_text(self) -> str:
        if self.status is Status.SKIPPED and self.skipped_reason:
            return f"skipped ({self.skipped_reason})"
        if self.partial and self.status.scored:
            return f"{self.status.value} (partial)"
        return self.status.value

    @property
    def actionable(self) -> bool:
        return self.status in (Status.FAIL, Status.WARN)


@dataclass
class HostInfo:
    hostname: str = ""
    os_name: str = ""
    os_id: str = ""
    os_version: str = ""
    kernel: str = ""
    is_root: bool = False
    user: str = ""
    uptime_s: float | None = None


@dataclass
class AuditReport:
    host: HostInfo
    findings: list[Finding]
    started_at: str = ""
    duration_s: float = 0.0
    tool_version: str = ""

    def by_status(self, status: Status) -> list[Finding]:
        return [f for f in self.findings if f.status is status]

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for f in self.findings:
            out[f.status.value] += 1
        return out
