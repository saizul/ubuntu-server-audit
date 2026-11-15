"""The audit context: everything a check may use, with caching and permission handling."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TypeVar

from ubuntu_server_audit.system import CommandResult, CommandRunner, FileStat, FileSystem

T = TypeVar("T")

DEFAULT_WEB_ROOTS = ("/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html")


class NeedsRoot(Exception):
    """Raised by a check that cannot produce a result without root privileges."""

    def __init__(self, reason: str = "needs root") -> None:
        super().__init__(reason)
        self.reason = reason


class NotApplicable(Exception):
    """Raised by a check whose subject is not installed or not present."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class ReadResult:
    text: str | None
    error: str | None = None  # "missing", "denied" or an error message

    @property
    def ok(self) -> bool:
        return self.text is not None

    @property
    def denied(self) -> bool:
        return self.error == "denied"


@dataclass
class AuditOptions:
    web_roots: list[str] = field(default_factory=lambda: list(DEFAULT_WEB_ROOTS))
    max_walk_entries: int = 200_000
    max_listed: int = 25
    disk_warn_percent: int = 80
    disk_fail_percent: int = 90
    journal_warn_bytes: int = 2 * 1024**3
    apt_lists_max_age_days: int = 7
    command_timeout: float = 60.0


@dataclass
class AuditContext:
    runner: CommandRunner
    fs: FileSystem
    is_root: bool
    options: AuditOptions = field(default_factory=AuditOptions)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    _commands: dict[tuple[str, ...], CommandResult] = field(default_factory=dict, repr=False)
    _memo: dict[str, Any] = field(default_factory=dict, repr=False)

    # commands -------------------------------------------------------------------------------------------------
    def run(self, *argv: str, timeout: float | None = None) -> CommandResult:
        key = tuple(argv)
        if key not in self._commands:
            self._commands[key] = self.runner.run(list(argv), timeout=timeout or self.options.command_timeout)
        return self._commands[key]

    def has_command(self, name: str) -> bool:
        return self.runner.which(name) is not None

    # files ----------------------------------------------------------------------------------------------------
    def try_read(self, path: str) -> ReadResult:
        try:
            return ReadResult(self.fs.read_text(path))
        except FileNotFoundError:
            return ReadResult(None, "missing")
        except NotADirectoryError:
            return ReadResult(None, "missing")
        except PermissionError:
            return ReadResult(None, "denied")
        except IsADirectoryError:
            return ReadResult(None, "is a directory")
        except OSError as exc:
            return ReadResult(None, exc.strerror or str(exc))

    def read(self, path: str) -> str | None:
        """File contents, ``None`` if missing; :class:`NeedsRoot` if unreadable as a normal user."""
        result = self.try_read(path)
        if result.ok:
            return result.text
        if result.denied:
            if not self.is_root:
                raise NeedsRoot(f"cannot read {path}")
            raise PermissionError(f"permission denied: {path}")
        if result.error == "missing":
            return None
        raise OSError(f"{path}: {result.error}")

    def stat(self, path: str, follow_symlinks: bool = True) -> FileStat | None:
        try:
            return self.fs.stat(path, follow_symlinks=follow_symlinks)
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return self.fs.exists(path)

    def glob(self, pattern: str) -> list[str]:
        return self.fs.glob(pattern)

    # caching --------------------------------------------------------------------------------------------------
    def memo(self, key: str, fn: Callable[[], T]) -> T:
        """Compute ``fn()`` once per audit (exceptions are cached and re-raised too)."""
        if key not in self._memo:
            try:
                self._memo[key] = ("ok", fn())
            except Exception as exc:
                self._memo[key] = ("err", exc)
        kind, value = self._memo[key]
        if kind == "err":
            raise value
        return value
