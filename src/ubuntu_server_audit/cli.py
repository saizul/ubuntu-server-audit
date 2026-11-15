"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import TextIO

from ubuntu_server_audit._version import __version__
from ubuntu_server_audit.context import DEFAULT_WEB_ROOTS, AuditContext, AuditOptions
from ubuntu_server_audit.engine import run_audit, select_checks
from ubuntu_server_audit.model import SEVERITY_RANK, Severity, Status
from ubuntu_server_audit.registry import all_checks
from ubuntu_server_audit.report import FORMATS, render, write_reports
from ubuntu_server_audit.scoring import compute
from ubuntu_server_audit.system import (
    ChrootRunner,
    CommandRunner,
    FileSystem,
    HostRootFileSystem,
    RealFileSystem,
    SubprocessRunner,
)

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def _formats(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for item in value.split(","):
            item = {"md": "markdown", "txt": "text", "htm": "html"}.get(item.strip().lower(), item.strip().lower())
            if not item:
                continue
            if item == "all":
                out.extend(f for f in FORMATS if f not in out)
            elif item in FORMATS:
                if item not in out:
                    out.append(item)
            else:
                raise ValueError(f"unknown format {item!r} (choose from {', '.join(FORMATS)}, all)")
    return out


def _list(values: list[str] | None) -> list[str]:
    return [v.strip() for value in values or [] for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ubuntu-server-audit",
        description="Read-only security and best-practice audit for Ubuntu 22.04/24.04 web servers. "
        "Run as root (sudo) for full results; as a normal user, checks that need root are skipped.",
        epilog="Exit codes: 0 ok, 1 --fail-under/--fail-on threshold reached, 2 error.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "-f",
        "--format",
        action="append",
        metavar="FMT",
        help="text, json, markdown (md), html or all; repeatable or comma-separated (default: text)",
    )
    p.add_argument("-o", "--output", type=Path, metavar="DIR", help="write report files into DIR")
    p.add_argument("--basename", default="server-audit", help="report file name prefix (default: server-audit)")
    p.add_argument("--only", action="append", metavar="IDS", help="run only these check IDs or categories (SSH-*, web)")
    p.add_argument("--skip", action="append", metavar="IDS", help="skip these check IDs or categories")
    p.add_argument(
        "--web-root",
        action="append",
        metavar="PATH",
        help=f"web root to scan for world-writable files, repeatable (default: {', '.join(DEFAULT_WEB_ROOTS)}"
        " plus nginx 'root' directives)",
    )
    p.add_argument(
        "--host-root",
        metavar="DIR",
        help="audit the host filesystem mounted at DIR (container use; commands run with chroot DIR)",
    )
    p.add_argument(
        "--max-files", type=int, default=200_000, metavar="N", help="stop file walks after N entries (default 200000)"
    )
    p.add_argument("--fail-under", type=int, metavar="SCORE", help="exit 1 when the score is below SCORE")
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity if s is not Severity.INFO],
        metavar="SEVERITY",
        help="exit 1 when a check of this severity or higher fails (critical, high, medium, low)",
    )
    p.add_argument("--require-root", action="store_true", help="exit 2 unless running as root")
    p.add_argument("--list-checks", action="store_true", help="list the checks and exit")
    p.add_argument(
        "--print-sysctl",
        action="store_true",
        help="print a /etc/sysctl.d/60-hardening.conf with the recommended values and exit",
    )
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colour in text output")
    p.add_argument("-v", "--verbose", action="store_true", help="show evidence for every check")
    p.add_argument("-q", "--quiet", action="store_true", help="no output on stdout (use with -o)")
    p.add_argument("--debug", action="store_true", help="debug logging on stderr")
    return p


def list_checks(out: TextIO) -> None:
    for c in all_checks():
        root = " (needs root)" if c.spec.needs_root else ""
        out.write(f"{c.spec.id:<8} {c.spec.severity.value:<8} {c.spec.category:<12} {c.spec.title}{root}\n")


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    runner: CommandRunner | None = None,
    fs: FileSystem | None = None,
    is_root: bool | None = None,
) -> int:
    stdout = stdout or sys.stdout
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING, format="%(levelname)s %(message)s", stream=sys.stderr
    )
    if args.list_checks:
        list_checks(stdout)
        return EXIT_OK
    if args.print_sysctl:
        from ubuntu_server_audit.kernel_values import sysctl_conf

        stdout.write(sysctl_conf())
        return EXIT_OK
    try:
        formats = _formats(args.format) or ["text"]
        if len(formats) > 1 and not args.output:
            raise ValueError("several formats need --output DIR")
        if args.max_files < 1:
            raise ValueError("--max-files must be positive")
        if args.fail_under is not None and not 0 <= args.fail_under <= 100:
            raise ValueError("--fail-under must be between 0 and 100")
        root = _is_root() if is_root is None else is_root
        if args.require_root and not root:
            raise ValueError("--require-root: run with sudo")
        checks = select_checks(all_checks(), _list(args.only), _list(args.skip))
        if not checks:
            raise ValueError("no checks selected (see --list-checks)")
        options = AuditOptions(max_walk_entries=args.max_files)
        if args.web_root:
            options.web_roots = [w.rstrip("/") or "/" for w in args.web_root]
        if args.host_root:
            if not os.path.isdir(os.path.join(args.host_root, "etc")):
                raise ValueError(f"--host-root {args.host_root}: no etc/ directory there")
            if not root:
                raise ValueError("--host-root needs root inside the container (chroot)")
            runner = runner or ChrootRunner(args.host_root)
            fs = fs or HostRootFileSystem(args.host_root)
        ctx = AuditContext(runner or SubprocessRunner(), fs or RealFileSystem(), root, options)
        report = run_audit(ctx, checks)
        if args.output:
            written = write_reports(report, formats, args.output, args.basename)
            if not args.quiet:
                color = args.color == "always" or (args.color == "auto" and stdout.isatty())
                stdout.write(render(report, "text", color=color, verbose=args.verbose))
                stdout.write("\nreports:\n" + "".join(f"  {p}\n" for p in written))
        elif not args.quiet:
            color = formats[0] == "text" and (args.color == "always" or (args.color == "auto" and stdout.isatty()))
            stdout.write(render(report, formats[0], color=color, verbose=args.verbose))
    except ValueError as exc:
        print(f"ubuntu-server-audit: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"ubuntu-server-audit: error: cannot write report: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("ubuntu-server-audit: interrupted", file=sys.stderr)
        return EXIT_ERROR
    score = compute(report.findings)
    if args.fail_under is not None and score.score < args.fail_under:
        return EXIT_FAIL
    if args.fail_on:
        limit = SEVERITY_RANK[Severity(args.fail_on)]
        if any(f.status is Status.FAIL and f.severity.rank <= limit for f in report.findings):
            return EXIT_FAIL
    return EXIT_OK
