"""Parsers for command output and configuration files. Pure functions, no I/O."""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field

# --- /etc/os-release ------------------------------------------------------------------------------------------


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        try:
            parts = shlex.split(value)
            value = parts[0] if parts else ""
        except ValueError:
            value = value.strip("\"'")
        out[key.strip()] = value
    return out


# --- sshd -----------------------------------------------------------------------------------------------------


def parse_sshd_t(text: str) -> dict[str, list[str]]:
    """``sshd -T`` output: lower-case keyword, then the value. Repeated keywords are collected."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        key, _, value = line.partition(" ")
        out.setdefault(key.lower(), []).append(value.strip())
    return out


@dataclass
class SshdConfigFile:
    options: dict[str, str] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    has_match: bool = False


def parse_sshd_config_lines(text: str) -> list[tuple[str, str]]:
    """``(keyword, value)`` pairs from an ``sshd_config`` file, keywords lower-cased."""
    pairs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(\S+)\s*(?:=\s*|\s+)(.*)$", line)
        if not match:
            continue
        pairs.append((match.group(1).lower(), match.group(2).strip().strip('"')))
    return pairs


# --- ss -------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Listener:
    proto: str
    address: str
    port: int
    process: str = ""

    @property
    def public(self) -> bool:
        return is_public_address(self.address)

    def __str__(self) -> str:
        addr = f"[{self.address}]" if ":" in self.address else self.address
        proc = f" ({self.process})" if self.process else ""
        return f"{self.proto} {addr}:{self.port}{proc}"


def is_public_address(address: str) -> bool:
    """True for wildcard and non-loopback addresses (what a remote host could reach)."""
    addr = address.split("%", 1)[0].strip("[]")
    if addr in ("*", "0.0.0.0", "::", ""):
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_loopback or ip.is_link_local)


_PROC = re.compile(r'users:\(\("([^"]+)"')


def parse_ss(text: str) -> list[Listener]:
    """Parse ``ss -H -tuln[p]`` output."""
    out: list[Listener] = []
    seen: set[tuple[str, str, int]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] in ("Netid", "State"):
            continue
        proto = parts[0]
        if proto not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        local = parts[4]
        host, sep, port = local.rpartition(":")
        if not sep or not port.isdigit():
            continue
        host = host.strip("[]")
        proc_match = _PROC.search(line)
        proto = proto.rstrip("6")
        key = (proto, host, int(port))
        if key in seen:
            continue
        seen.add(key)
        out.append(Listener(proto, host, int(port), proc_match.group(1) if proc_match else ""))
    return out


# --- ufw / nftables -------------------------------------------------------------------------------------------


@dataclass
class UfwStatus:
    active: bool
    incoming: str = ""
    outgoing: str = ""
    routed: str = ""
    rules: list[str] = field(default_factory=list)

    def allows_port(self, port: int, proto: str = "tcp") -> bool:
        for rule in self.rules:
            target = rule.split()[0] if rule.split() else ""
            if " ALLOW" not in f" {rule}" and "LIMIT" not in rule:
                continue
            spec, _, rule_proto = target.partition("/")
            if rule_proto and rule_proto != proto:
                continue
            for part in spec.split(","):
                if part.isdigit() and int(part) == port:
                    return True
                if ":" in part:
                    lo, _, hi = part.partition(":")
                    if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                        return True
            if spec.lower() == "anywhere" and "ALLOW IN" in rule:
                return True
        return False


def parse_ufw_status(text: str) -> UfwStatus:
    """``ufw status verbose``."""
    active = bool(re.search(r"^Status:\s*active", text, re.M))
    status = UfwStatus(active=active)
    match = re.search(r"^Default:\s*(.+)$", text, re.M)
    if match:
        for part in match.group(1).split(","):
            m = re.match(r"\s*(\w+)\s*\((\w+)\)", part)
            if m and m.group(2) in ("incoming", "outgoing", "routed"):
                setattr(status, m.group(2), m.group(1).lower())
    in_rules = False
    for line in text.splitlines():
        if line.startswith("--"):
            in_rules = True
            continue
        if in_rules and line.strip():
            status.rules.append(line.strip())
    return status


@dataclass
class NftInput:
    chains: int = 0
    policy_drop: bool = False
    rules: int = 0


def parse_nft_ruleset(text: str) -> NftInput:
    """Look for base chains on the ``input`` hook in ``nft list ruleset`` output."""
    result = NftInput()
    depth = 0
    in_input = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("chain ") and line.endswith("{"):
            in_input, depth = False, 1
            continue
        if not depth:
            continue
        if line.startswith("type filter hook input"):
            in_input = True
            result.chains += 1
            if re.search(r"policy\s+drop", line):
                result.policy_drop = True
            continue
        if line == "}":
            depth = 0
            in_input = False
            continue
        if in_input and line and not line.startswith("#"):
            result.rules += 1
    return result


def parse_fail2ban_jails(text: str) -> list[str]:
    match = re.search(r"Jail list:\s*(.*)$", text, re.M)
    if not match:
        return []
    return [j.strip() for j in match.group(1).split(",") if j.strip()]


# --- apt --------------------------------------------------------------------------------------------------------


def parse_apt_config(text: str) -> dict[str, str]:
    """``apt-config dump`` or apt.conf fragments: ``Key "value";`` lines (nested blocks flattened)."""
    out: dict[str, str] = {}
    stack: list[str] = []
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip() if not raw.strip().startswith("#") else ""
        if not line:
            continue
        for stmt in re.findall(r"[^;{}]+\{|\}|[^;{}]+;", line):
            stmt = stmt.strip()
            if stmt == "}":
                if stack:
                    stack.pop()
                continue
            if stmt.endswith("{"):
                stack.append(stmt[:-1].strip())
                continue
            stmt = stmt[:-1].strip()
            m = re.match(r'^(\S+)\s+"?(.*?)"?$', stmt)
            if not m:
                continue
            key = "::".join([*stack, m.group(1)])
            out[key] = m.group(2)
    return out


def parse_apt_check(text: str) -> tuple[int, int] | None:
    """``/usr/lib/update-notifier/apt-check`` prints ``updates;security`` on stderr."""
    match = re.search(r"(\d+);(\d+)", text)
    return (int(match.group(1)), int(match.group(2))) if match else None


def parse_apt_upgradable(text: str) -> tuple[list[str], list[str]]:
    """``apt list --upgradable``: (all packages, security packages)."""
    every, security = [], []
    for line in text.splitlines():
        if "/" not in line or "upgradable" not in line:
            continue
        name, _, rest = line.partition("/")
        suites = rest.split()[0] if rest.split() else ""
        every.append(name)
        if "-security" in suites:
            security.append(name)
    return every, security


# --- accounts ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PasswdEntry:
    name: str
    uid: int
    gid: int
    home: str
    shell: str


def parse_passwd(text: str) -> list[PasswdEntry]:
    out = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 7 or line.startswith("#"):
            continue
        try:
            out.append(PasswdEntry(parts[0], int(parts[2]), int(parts[3]), parts[5], parts[6]))
        except ValueError:
            continue
    return out


def parse_shadow_empty(text: str) -> list[str]:
    """Accounts whose password field is empty (anyone can log in without a password)."""
    out = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[0] and not line.startswith("#") and parts[1] == "":
            out.append(parts[0])
    return out


def sudoers_nopasswd(text: str) -> list[str]:
    """Rule lines that contain NOPASSWD (comments and Defaults lines ignored, continuations joined)."""
    joined = re.sub(r"\\\n", " ", text)
    out = []
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or (line.startswith("#") and not line.startswith(("#include", "#includedir"))):
            continue
        if line.startswith(("Defaults", "#include", "@include")):
            continue
        if "NOPASSWD" in line:
            out.append(re.sub(r"\s+", " ", line))
    return out


def sudoers_includes(text: str) -> tuple[list[str], list[str]]:
    """``(files, directories)`` named by ``@include``/``#include`` and ``@includedir``/``#includedir``."""
    files, dirs = [], []
    for raw in text.splitlines():
        m = re.match(r"^\s*[@#](include|includedir)\s+(\S+)", raw)
        if m:
            (dirs if m.group(1) == "includedir" else files).append(m.group(2))
    return files, dirs


def sudoers_dir_file_allowed(name: str) -> bool:
    """sudo skips files in an includedir that end in ``~`` or contain a ``.``."""
    return not (name.endswith("~") or "." in name)


# --- ini-style (PHP, MySQL, journald) --------------------------------------------------------------------------


def parse_ini(text: str, *, comment: str = ";#", dashes: bool = False) -> dict[str, dict[str, str]]:
    """Sections -> {key: value}; keys lower-cased, later values win. Keys before any section go to ``""``.

    With ``dashes`` (MySQL option files), ``bind-address`` and ``bind_address`` are the same key.
    """
    out: dict[str, dict[str, str]] = {"": {}}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in comment:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            out.setdefault(section, {})
            continue
        if line.startswith("!"):  # MySQL !include / !includedir
            continue
        key, sep, value = line.partition("=")
        key = key.strip().lower()
        if dashes:
            key = key.replace("-", "_")
        value = value.strip() if sep else ""
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            for c in comment:
                if f" {c}" in value:
                    value = value.split(f" {c}", 1)[0].strip()
        out.setdefault(section, {})[key] = value
    return out


def php_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    v = value.strip().strip("\"'").lower()
    if v in ("1", "on", "yes", "true", "stderr", "stdout"):
        return True
    if v in ("0", "off", "no", "false", "none", ""):
        return False
    return None


# --- redis ------------------------------------------------------------------------------------------------------


def parse_redis_conf(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        out.setdefault(key.lower(), []).append(value.strip())
    return out


# --- df, timedatectl, journald ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class DfRow:
    filesystem: str
    mount: str
    used_percent: int


def parse_df(text: str) -> list[DfRow]:
    """``df -P`` or ``df -P -i``: the use% column is the second to last."""
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        pct = parts[-2]
        if not pct.endswith("%") or not pct[:-1].isdigit():
            continue
        rows.append(DfRow(parts[0], parts[-1], int(pct[:-1])))
    return rows


def parse_key_values(text: str) -> dict[str, str]:
    """``KEY=value`` lines (``timedatectl show``, ``systemctl show``)."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


_UNITS = {"": 1, "B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}


def parse_size(text: str) -> int | None:
    """``1.2G``, ``512M``, ``8.0K``, ``123B`` -> bytes."""
    match = re.match(r"^\s*([\d.]+)\s*([BKMGTP]?)(?:i?B)?\s*$", text.strip(), re.I)
    if not match:
        return None
    try:
        return int(float(match.group(1)) * _UNITS[match.group(2).upper()])
    except (ValueError, KeyError):
        return None


def parse_journal_usage(text: str) -> int | None:
    match = re.search(r"take up ([\d.]+\s*[BKMGTP]?)", text)
    return parse_size(match.group(1)) if match else None


# --- cron -------------------------------------------------------------------------------------------------------

_CRON_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")


@dataclass(frozen=True)
class CronJob:
    source: str
    user: str
    command: str


def parse_crontab(text: str, source: str, *, system: bool, default_user: str = "root") -> list[CronJob]:
    """System crontabs (``/etc/crontab``, ``/etc/cron.d``) have a user field; user crontabs do not."""
    jobs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or _CRON_ENV.match(line):
            continue
        parts = line.split()
        if parts[0].startswith("@"):
            schedule_len = 1
        else:
            schedule_len = 5
        need = schedule_len + (2 if system else 1)
        if len(parts) < need:
            continue
        user = parts[schedule_len] if system else default_user
        command = " ".join(parts[schedule_len + (1 if system else 0) :])
        jobs.append(CronJob(source, user, command))
    return jobs


def command_paths(command: str) -> list[str]:
    """Absolute paths a cron command runs or reads (redirect targets are ignored)."""
    try:
        tokens = shlex.split(command, comments=False, posix=True)
    except ValueError:
        tokens = command.split()
    paths = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in (">", ">>", "2>", "2>>", "&>", "<", "1>"):
            skip_next = True
            continue
        if re.match(r"^\d?[<>]", token) or token.startswith("&>"):
            continue
        for part in re.split(r"[;&|`]+", token):
            part = part.strip("()")
            if part.startswith("/") and not part.startswith(("/dev/", "/proc/")) and part != "/":
                paths.append(part.split("=", 1)[-1] if "=" in part else part)
            elif "=/" in part:
                paths.append(part.split("=", 1)[1])
    return list(dict.fromkeys(paths))
