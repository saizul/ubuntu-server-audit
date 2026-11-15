"""A minimal nginx configuration reader: enough to find directives and their context.

It understands blocks, quoting, comments and ``include`` (with globs, relative to the main file's directory).
It does not evaluate variables, ``if`` or ``map``.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field

_TOKEN = re.compile(r"""\s*(?:("(?:\\.|[^"\\])*")|('(?:\\.|[^'\\])*')|([{};])|(#[^\n]*)|([^\s{};"'#]+))""")


@dataclass(frozen=True)
class Directive:
    name: str
    args: tuple[str, ...]
    context: tuple[str, ...]  # e.g. ("http", "server")
    file: str


@dataclass
class NginxConfig:
    directives: list[Directive] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def find(self, name: str) -> list[Directive]:
        return [d for d in self.directives if d.name == name]


def tokenize(text: str) -> list[str]:
    tokens = []
    pos = 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match or match.end() == pos:
            if text[pos:].strip() == "":
                break
            pos += 1
            continue
        pos = match.end()
        dq, sq, punct, comment, word = match.groups()
        if comment is not None:
            continue
        if dq is not None:
            tokens.append(dq[1:-1])
        elif sq is not None:
            tokens.append(sq[1:-1])
        elif punct is not None:
            tokens.append(punct)
        elif word is not None:
            tokens.append(word)
    return tokens


def split_dump(text: str) -> dict[str, str]:
    """Split ``nginx -T`` output into ``{path: contents}``."""
    files: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^# configuration file (.+):\s*$", line)
        if match:
            if current is not None:
                files[current] = "\n".join(lines)
            current, lines = match.group(1).strip(), []
            continue
        if current is not None:
            lines.append(line)
    if current is not None:
        files[current] = "\n".join(lines)
    return files


def load(
    main: str,
    read: Callable[[str], str | None],
    glob: Callable[[str], list[str]],
    *,
    max_files: int = 500,
) -> NginxConfig:
    """Parse ``main`` and everything it includes. ``read`` returns ``None`` (or raises) for unreadable files."""
    config = NginxConfig()
    prefix = posixpath.dirname(main)

    def parse_file(path: str, context: tuple[str, ...], depth: int) -> None:
        if len(config.files) >= max_files or depth > 20:
            config.errors.append(f"{path}: include limit reached")
            return
        try:
            text = read(path)
        except OSError as exc:
            config.errors.append(f"{path}: {exc}")
            return
        if text is None:
            config.errors.append(f"{path}: cannot read")
            return
        config.files.append(path)
        tokens = tokenize(text)
        stack = list(context)
        args: list[str] = []
        for token in tokens:
            if token == ";":
                if args:
                    name, rest = args[0], tuple(args[1:])
                    if name == "include" and rest:
                        pattern = rest[0] if rest[0].startswith("/") else posixpath.join(prefix, rest[0])
                        matches = glob(pattern) if any(c in pattern for c in "*?[") else [pattern]
                        for inc in sorted(matches):
                            parse_file(inc, tuple(stack), depth + 1)
                    else:
                        config.directives.append(Directive(name, rest, tuple(stack), path))
                args = []
            elif token == "{":
                stack.append(args[0] if args else "")
                if args:
                    config.directives.append(Directive(args[0], tuple(args[1:]), tuple(stack[:-1]), path))
                args = []
            elif token == "}":
                if len(stack) > len(context):
                    stack.pop()
                args = []
            else:
                args.append(token)

    parse_file(main, (), 0)
    return config


def load_from_dump(text: str) -> NginxConfig:
    """Parse ``nginx -T`` output (every file is in the dump, includes resolved against it)."""
    files = split_dump(text)
    if not files:
        return NginxConfig(errors=["no configuration files in nginx -T output"])
    main = next(iter(files))

    def read(path: str) -> str | None:
        return files.get(path)

    def glob(pattern: str) -> list[str]:
        return [p for p in files if fnmatch.fnmatchcase(p, pattern)]

    return load(main, read, glob)


def listens_with_tls(config: NginxConfig) -> bool:
    for d in config.find("listen"):
        if "ssl" in d.args or "quic" in d.args or any(a.endswith(":443") or a == "443" for a in d.args):
            return True
    return any(d.args and d.args[0] == "on" for d in config.find("ssl"))
