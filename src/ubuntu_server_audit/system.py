"""Access to the machine: commands and files. Both are interfaces so tests can use fakes.

Nothing here raises on missing commands or timeouts; file reads raise the usual ``OSError`` subclasses
(``FileNotFoundError``, ``PermissionError``) and the audit context turns them into check results.
"""

from __future__ import annotations

import glob as _glob
import os
import shutil
import stat as _stat
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol

EXTRA_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DENIED_MARKERS = (
    "permission denied",
    "need to be root",
    "must be root",
    "must be run as root",
    "are you root",
    "operation not permitted",
    "access denied",
    "no hostkeys available",
    "authentication is required",
    "interactive authentication required",
)


@dataclass
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    #: "not_found", "timeout" or "os_error" when the command did not run to completion.
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0

    @property
    def missing(self) -> bool:
        return self.error == "not_found"

    @property
    def denied(self) -> bool:
        text = (self.stderr + " " + self.stdout[:500]).lower()
        return any(m in text for m in DENIED_MARKERS)

    def describe(self) -> str:
        cmd = " ".join(self.argv)
        if self.error == "not_found":
            return f"{cmd}: command not found"
        if self.error == "timeout":
            return f"{cmd}: timed out"
        if self.error:
            return f"{cmd}: {self.stderr.strip() or self.error}"
        msg = (self.stderr.strip() or self.stdout.strip()).splitlines()
        return f"{cmd}: exit {self.returncode}" + (f": {msg[0][:200]}" if msg else "")


class CommandRunner(Protocol):
    def run(self, argv: list[str] | tuple[str, ...], timeout: float = 30.0) -> CommandResult: ...

    def which(self, name: str) -> str | None: ...


class SubprocessRunner:
    """Runs commands without a shell, with ``LC_ALL=C`` and a timeout. Never raises."""

    def __init__(self, *, max_output: int = 20_000_000) -> None:
        self.max_output = max_output
        self.env = {
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
            "PATH": os.environ.get("PATH", "") + ":" + EXTRA_PATH,
            "SYSTEMD_PAGER": "",
            "PAGER": "cat",
        }

    def which(self, name: str) -> str | None:
        return shutil.which(name, path=self.env["PATH"])

    def run(self, argv: list[str] | tuple[str, ...], timeout: float = 30.0) -> CommandResult:
        argv = tuple(argv)
        exe = self.which(argv[0]) if not argv[0].startswith("/") else argv[0]
        if not exe or not os.path.exists(exe):
            return CommandResult(argv, None, error="not_found")
        try:
            proc = subprocess.run(
                [exe, *argv[1:]],
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                env=self.env,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(argv, None, error="timeout")
        except OSError as exc:
            return CommandResult(argv, None, stderr=str(exc), error="os_error")
        return CommandResult(
            argv,
            proc.returncode,
            proc.stdout[: self.max_output].decode("utf-8", errors="replace"),
            proc.stderr[: self.max_output].decode("utf-8", errors="replace"),
        )


@dataclass(frozen=True)
class FileStat:
    mode: int
    uid: int
    gid: int
    size: int = 0
    mtime: float = 0.0
    is_dir: bool = False
    is_file: bool = False
    is_link: bool = False

    @property
    def perms(self) -> int:
        return _stat.S_IMODE(self.mode)

    @property
    def world_writable(self) -> bool:
        return bool(self.mode & _stat.S_IWOTH)

    @property
    def group_writable(self) -> bool:
        return bool(self.mode & _stat.S_IWGRP)

    @property
    def sticky(self) -> bool:
        return bool(self.mode & _stat.S_ISVTX)

    @property
    def suid(self) -> bool:
        return bool(self.mode & _stat.S_ISUID)

    @property
    def sgid(self) -> bool:
        return bool(self.mode & _stat.S_ISGID)


@dataclass
class WalkStats:
    entries: int = 0
    errors: list[str] = field(default_factory=list)
    truncated: bool = False


class FileSystem(Protocol):
    def read_text(self, path: str, max_bytes: int = 4_000_000) -> str: ...

    def exists(self, path: str) -> bool: ...

    def is_dir(self, path: str) -> bool: ...

    def listdir(self, path: str) -> list[str]: ...

    def stat(self, path: str, follow_symlinks: bool = True) -> FileStat: ...

    def glob(self, pattern: str) -> list[str]: ...


def _from_os_stat(st: os.stat_result, is_link: bool = False) -> FileStat:
    return FileStat(
        mode=st.st_mode,
        uid=st.st_uid,
        gid=st.st_gid,
        size=st.st_size,
        mtime=st.st_mtime,
        is_dir=_stat.S_ISDIR(st.st_mode),
        is_file=_stat.S_ISREG(st.st_mode),
        is_link=is_link or _stat.S_ISLNK(st.st_mode),
    )


class RealFileSystem:
    """The local filesystem, read-only."""

    def read_text(self, path: str, max_bytes: int = 4_000_000) -> str:
        with open(path, "rb") as fh:
            return fh.read(max_bytes).decode("utf-8", errors="replace")

    def exists(self, path: str) -> bool:
        try:
            return os.path.lexists(path)
        except OSError:
            return False

    def is_dir(self, path: str) -> bool:
        try:
            return os.path.isdir(path)
        except OSError:
            return False

    def listdir(self, path: str) -> list[str]:
        return sorted(os.listdir(path))

    def stat(self, path: str, follow_symlinks: bool = True) -> FileStat:
        return _from_os_stat(os.stat(path, follow_symlinks=follow_symlinks))

    def glob(self, pattern: str) -> list[str]:
        try:
            return sorted(_glob.glob(pattern))
        except OSError:
            return []


def walk(
    fs: FileSystem,
    top: str,
    *,
    max_depth: int = 20,
    max_entries: int = 200_000,
    stats: WalkStats | None = None,
    skip: tuple[str, ...] = (),
) -> Iterator[tuple[str, FileStat]]:
    """Yield ``(path, stat)`` below ``top`` without following symlinks or crossing into ``skip`` prefixes.

    Unreadable directories are recorded in ``stats.errors`` and skipped; the walk never raises.
    """
    stats = stats if stats is not None else WalkStats()
    stack: list[tuple[str, int]] = [(top.rstrip("/") or "/", 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            names = fs.listdir(directory)
        except PermissionError:
            stats.errors.append(f"{directory}: permission denied")
            continue
        except OSError as exc:
            stats.errors.append(f"{directory}: {exc.strerror or exc}")
            continue
        for name in names:
            path = f"{directory.rstrip('/')}/{name}"
            if any(path == s or path.startswith(s.rstrip("/") + "/") for s in skip):
                continue
            stats.entries += 1
            if stats.entries > max_entries:
                stats.truncated = True
                return
            try:
                st = fs.stat(path, follow_symlinks=False)
            except OSError as exc:
                stats.errors.append(f"{path}: {exc.strerror or exc}")
                continue
            yield path, st
            if st.is_dir and not st.is_link and depth < max_depth:
                stack.append((path, depth + 1))


class HostRootFileSystem(RealFileSystem):
    """The host's filesystem mounted at ``root`` (for example ``/host`` inside a container).

    Paths are given as the host sees them and prefixed here. Absolute symlinks on the host resolve inside the
    container, which only matters for a few files outside the audited paths.
    """

    def __init__(self, root: str) -> None:
        self.root = root.rstrip("/") or "/"

    def _p(self, path: str) -> str:
        return self.root + path if path.startswith("/") else path

    def read_text(self, path: str, max_bytes: int = 4_000_000) -> str:
        return super().read_text(self._p(path), max_bytes)

    def exists(self, path: str) -> bool:
        return super().exists(self._p(path))

    def is_dir(self, path: str) -> bool:
        return super().is_dir(self._p(path))

    def listdir(self, path: str) -> list[str]:
        return super().listdir(self._p(path))

    def stat(self, path: str, follow_symlinks: bool = True) -> FileStat:
        return super().stat(self._p(path), follow_symlinks=follow_symlinks)

    def glob(self, pattern: str) -> list[str]:
        prefix = len(self.root)
        return [p[prefix:] for p in super().glob(self._p(pattern))]


class ChrootRunner(SubprocessRunner):
    """Runs the host's programs with ``chroot ROOT`` (needs root and CAP_SYS_CHROOT in the container)."""

    def __init__(self, root: str, **kwargs: int) -> None:
        super().__init__(**kwargs)
        self.root = root.rstrip("/")

    def which(self, name: str) -> str | None:
        for directory in EXTRA_PATH.split(":"):
            if os.path.exists(f"{self.root}{directory}/{name}"):
                return f"{directory}/{name}"
        return None

    def run(self, argv: list[str] | tuple[str, ...], timeout: float = 30.0) -> CommandResult:
        argv = tuple(argv)
        exe = argv[0] if argv[0].startswith("/") else self.which(argv[0])
        if not exe or not os.path.exists(self.root + exe):
            return CommandResult(argv, None, error="not_found")
        result = super().run(("chroot", self.root, exe, *argv[1:]), timeout=timeout)
        return CommandResult(argv, result.returncode, result.stdout, result.stderr, result.error)
