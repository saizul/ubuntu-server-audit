"""Fake command runner and fake filesystem for tests."""

from __future__ import annotations

import fnmatch
import posixpath
import stat as _stat
from dataclasses import dataclass, field

from ubuntu_server_audit.system import CommandResult, FileStat


def ok(stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult((), 0, stdout, stderr)


def fail(returncode: int = 1, stderr: str = "", stdout: str = "") -> CommandResult:
    return CommandResult((), returncode, stdout, stderr)


DENIED = fail(1, "Permission denied")


class FakeRunner:
    """Answers commands from a table; ``available`` lists the programs that "exist"."""

    def __init__(self, commands: dict[str, CommandResult | str] | None = None, available: set[str] | None = None):
        self.commands: dict[str, CommandResult] = {}
        self.available: set[str] = set(available or ())
        self.calls: list[str] = []
        for key, value in (commands or {}).items():
            self.set(key, value)

    def set(self, command: str, result: CommandResult | str) -> None:
        self.commands[command] = ok(result) if isinstance(result, str) else result
        self.available.add(command.split()[0])

    def remove(self, program: str) -> None:
        self.available.discard(program)
        self.commands = {k: v for k, v in self.commands.items() if k.split()[0] != program}

    def which(self, name: str) -> str | None:
        return f"/usr/bin/{name}" if name in self.available else None

    def run(self, argv, timeout: float = 30.0) -> CommandResult:
        key = " ".join(argv)
        self.calls.append(key)
        if argv[0] not in self.available and not argv[0].startswith("/"):
            return CommandResult(tuple(argv), None, error="not_found")
        result = self.commands.get(key)
        if result is None:
            if argv[0].startswith("/") and argv[0] not in self.available:
                return CommandResult(tuple(argv), None, error="not_found")
            return CommandResult(tuple(argv), 1, "", f"fake: no answer for {key!r}")
        return CommandResult(tuple(argv), result.returncode, result.stdout, result.stderr, result.error)


@dataclass
class Node:
    kind: str  # "file", "dir" or "link"
    content: str = ""
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    mtime: float = 0.0
    target: str = ""


@dataclass
class FakeFS:
    """An in-memory filesystem. Paths in ``denied`` cannot be read or listed, and nothing below them is reachable."""

    nodes: dict[str, Node] = field(default_factory=lambda: {"/": Node("dir", mode=0o755)})
    denied: set[str] = field(default_factory=set)
    broken: set[str] = field(default_factory=set)  # raise a generic OSError

    def _parents(self, path: str) -> None:
        parent = posixpath.dirname(path)
        while parent and parent not in self.nodes:
            self.nodes[parent] = Node("dir", mode=0o755)
            parent = posixpath.dirname(parent)

    def add_file(
        self, path: str, content: str = "", mode: int = 0o644, uid: int = 0, gid: int = 0, mtime: float = 0.0
    ) -> FakeFS:
        self._parents(path)
        self.nodes[path] = Node("file", content, mode, uid, gid, mtime)
        return self

    def add_dir(self, path: str, mode: int = 0o755, uid: int = 0, gid: int = 0, mtime: float = 0.0) -> FakeFS:
        self._parents(path)
        self.nodes[path] = Node("dir", mode=mode, uid=uid, gid=gid, mtime=mtime)
        return self

    def add_link(self, path: str, target: str) -> FakeFS:
        self._parents(path)
        self.nodes[path] = Node("link", mode=0o777, target=target)
        return self

    def deny(self, *paths: str) -> FakeFS:
        self.denied.update(paths)
        return self

    def remove(self, path: str) -> FakeFS:
        for key in [k for k in self.nodes if k == path or k.startswith(path.rstrip("/") + "/")]:
            del self.nodes[key]
        return self

    # --- FileSystem interface --------------------------------------------------------------------------------
    def _check_traverse(self, path: str) -> None:
        parent = posixpath.dirname(path)
        while parent and parent != "/":
            if parent in self.denied:
                raise PermissionError(13, "Permission denied", path)
            parent = posixpath.dirname(parent)
        if path in self.broken:
            raise OSError(5, "Input/output error", path)

    def _resolve(self, path: str, follow: bool = True) -> Node:
        self._check_traverse(path)
        node = self.nodes.get(path)
        if node is None:
            raise FileNotFoundError(2, "No such file or directory", path)
        hops = 0
        while follow and node.kind == "link":
            hops += 1
            if hops > 10:
                raise OSError(40, "Too many levels of symbolic links", path)
            target = (
                node.target if node.target.startswith("/") else posixpath.join(posixpath.dirname(path), node.target)
            )
            node = self.nodes.get(posixpath.normpath(target))
            if node is None:
                raise FileNotFoundError(2, "No such file or directory", path)
        return node

    def read_text(self, path: str, max_bytes: int = 4_000_000) -> str:
        node = self._resolve(path)
        if node.kind == "dir":
            raise IsADirectoryError(21, "Is a directory", path)
        if path in self.denied:
            raise PermissionError(13, "Permission denied", path)
        return node.content[:max_bytes]

    def exists(self, path: str) -> bool:
        try:
            self._resolve(path, follow=False)
            return True
        except OSError:
            return False

    def is_dir(self, path: str) -> bool:
        try:
            return self._resolve(path).kind == "dir"
        except OSError:
            return False

    def listdir(self, path: str) -> list[str]:
        node = self._resolve(path)
        if node.kind != "dir":
            raise NotADirectoryError(20, "Not a directory", path)
        if path in self.denied:
            raise PermissionError(13, "Permission denied", path)
        prefix = path.rstrip("/") + "/"
        return sorted({k[len(prefix) :].split("/")[0] for k in self.nodes if k.startswith(prefix) and k != path})

    def stat(self, path: str, follow_symlinks: bool = True) -> FileStat:
        node = self._resolve(path, follow=follow_symlinks)
        kind_bits = {"file": _stat.S_IFREG, "dir": _stat.S_IFDIR, "link": _stat.S_IFLNK}[node.kind]
        return FileStat(
            mode=kind_bits | node.mode,
            uid=node.uid,
            gid=node.gid,
            size=len(node.content),
            mtime=node.mtime,
            is_dir=node.kind == "dir",
            is_file=node.kind == "file",
            is_link=node.kind == "link",
        )

    def glob(self, pattern: str) -> list[str]:
        parts = pattern.split("/")
        out = []
        for path in self.nodes:
            segs = path.split("/")
            if len(segs) != len(parts):
                continue
            if any(s.startswith(".") and not p.startswith(".") for s, p in zip(segs, parts, strict=True)):
                continue  # like glob.glob, '*' does not match hidden files
            if all(fnmatch.fnmatchcase(s, p) for s, p in zip(segs, parts, strict=True)):
                try:
                    self._check_traverse(path)
                except OSError:
                    continue
                out.append(path)
        return sorted(out)


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _name(common_name: str) -> bytes:
    attribute = _der(0x30, _der(0x06, b"\x55\x04\x03") + _der(0x0C, common_name.encode()))
    return _der(0x30, _der(0x31, attribute))


def _der_time(moment) -> bytes:
    if 1950 <= moment.year < 2050:
        return _der(0x17, moment.strftime("%y%m%d%H%M%SZ").encode())
    return _der(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode())


def make_cert_der(common_name: str, not_before, not_after, issuer: str = "Test CA") -> bytes:
    """A structurally valid (unsigned) X.509 certificate for tests."""
    algorithm = _der(0x30, _der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b") + b"\x05\x00")
    tbs = _der(
        0x30,
        _der(0xA0, _der(0x02, b"\x02"))
        + _der(0x02, b"\x01\x23")
        + algorithm
        + _name(issuer)
        + _der(0x30, _der_time(not_before) + _der_time(not_after))
        + _name(common_name)
        + _der(0x30, algorithm + _der(0x03, b"\x00\x00")),
    )
    return _der(0x30, tbs + algorithm + _der(0x03, b"\x00" + b"\x01" * 300))


def make_pem(*certs: bytes) -> str:
    import base64
    import textwrap

    blocks = []
    for der in certs:
        body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
        blocks.append(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    return "".join(blocks)
