"""OpenSSH server: effective configuration from ``sshd -T``."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from ubuntu_server_audit.context import AuditContext, NeedsRoot, NotApplicable
from ubuntu_server_audit.model import Outcome, Severity, Status
from ubuntu_server_audit.parsers import parse_sshd_config_lines, parse_sshd_t
from ubuntu_server_audit.registry import check

MAN = "https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html"
SSHD_CONFIG = "/etc/ssh/sshd_config"

#: Defaults from sshd_config(5), used when reading the files instead of ``sshd -T``.
DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "kbdinteractiveauthentication": "yes",
    "permitemptypasswords": "no",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "logingracetime": "120",
    "usepam": "no",
    "pubkeyauthentication": "yes",
    "port": "22",
}
ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}

WEAK_CIPHERS = (
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
)
WEAK_MACS = (
    "hmac-md5",
    "hmac-md5-96",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-96",
    "hmac-sha1-96-etm@openssh.com",
    "hmac-ripemd160",
    "hmac-ripemd160@openssh.com",
    "hmac-ripemd160-etm@openssh.com",
    "umac-32@openssh.com",
)
WEAK_KEX = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-",
    "gss-gex-sha1-",
)
LEGACY = ("hmac-sha1", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-64-etm@openssh.com")


@dataclass
class SshdConfig:
    options: dict[str, str]
    source: str
    notes: list[str] = field(default_factory=list)
    partial: bool = False

    def get(self, key: str) -> str:
        return self.options.get(key, DEFAULTS.get(key, "")).lower()

    def evidence(self, *keys: str) -> list[str]:
        out = [f"{k} {self.options.get(k, DEFAULTS.get(k, '(unset)'))}" for k in keys]
        return [*out, f"source: {self.source}", *self.notes]


def _read_config_files(ctx: AuditContext) -> SshdConfig:
    """Fallback for normal users: read sshd_config and its Include files (first value wins, like sshd)."""
    options: dict[str, str] = {}
    notes: list[str] = []
    seen: set[str] = set()

    def read_file(path: str, depth: int = 0) -> None:
        if path in seen or depth > 10:
            return
        seen.add(path)
        result = ctx.try_read(path)
        if not result.ok:
            if result.denied:
                notes.append(f"{path}: permission denied")
            return
        in_match = False
        for key, value in parse_sshd_config_lines(result.text or ""):
            key = ALIASES.get(key, key)
            if key == "match":
                in_match = True
                notes.append("Match blocks are not evaluated when reading files")
                continue
            if in_match:
                continue
            if key == "include":
                for pattern in value.split():
                    pattern = pattern if pattern.startswith("/") else posixpath.join("/etc/ssh", pattern)
                    for inc in ctx.glob(pattern) if any(c in pattern for c in "*?[") else [pattern]:
                        read_file(inc, depth + 1)
                continue
            options.setdefault(key, value)

    first = ctx.try_read(SSHD_CONFIG)
    if first.denied:
        raise NeedsRoot(f"cannot read {SSHD_CONFIG}")
    if not first.ok:
        raise NotApplicable(f"{SSHD_CONFIG} not found")
    read_file(SSHD_CONFIG)
    return SshdConfig(
        options,
        "configuration files (run as root for the effective config from sshd -T)",
        sorted(set(notes)),
        partial=True,
    )


def sshd_config(ctx: AuditContext) -> SshdConfig:
    def load() -> SshdConfig:
        installed = ctx.has_command("sshd") or ctx.exists("/usr/sbin/sshd")
        if not installed:
            raise NotApplicable("OpenSSH server is not installed")
        result = ctx.run("sshd", "-T")
        if result.ok and "permitrootlogin" in result.stdout.lower():
            parsed = parse_sshd_t(result.stdout)
            options = {ALIASES.get(k, k): v[0] for k, v in parsed.items()}
            return SshdConfig(options, "sshd -T (effective configuration)")
        if not ctx.is_root:
            return _read_config_files(ctx)
        raise RuntimeError(result.describe())

    return ctx.memo("sshd", load)


def _outcome(cfg: SshdConfig, status: Status, summary: str, *keys: str) -> Outcome:
    return Outcome(
        status,
        summary,
        cfg.evidence(*keys),
        partial=cfg.partial,
        partial_reason="read from files, not the effective configuration" if cfg.partial else "",
    )


@check(
    "SSH-001",
    "Root login over SSH is disabled",
    category="ssh",
    severity=Severity.HIGH,
    fix="Set 'PermitRootLogin no' in /etc/ssh/sshd_config.d/50-hardening.conf, log in as a normal user with "
    "sudo, then run 'sshd -t && systemctl reload ssh'.",
    references=(MAN,),
)
def root_login(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    value = cfg.get("permitrootlogin")
    if value == "no":
        return _outcome(cfg, Status.PASS, "root cannot log in over SSH", "permitrootlogin")
    if value in ("prohibit-password", "without-password", "forced-commands-only"):
        return _outcome(cfg, Status.WARN, f"root can log in with a key ({value})", "permitrootlogin")
    return _outcome(cfg, Status.FAIL, "root can log in with a password", "permitrootlogin")


@check(
    "SSH-002",
    "Password authentication is disabled",
    category="ssh",
    severity=Severity.HIGH,
    fix="After confirming key-based login works, set 'PasswordAuthentication no' and reload ssh. Check files "
    "in /etc/ssh/sshd_config.d/ (cloud images often re-enable it there).",
    references=(MAN,),
)
def password_auth(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    if cfg.get("passwordauthentication") == "no":
        return _outcome(cfg, Status.PASS, "only key-based logins are accepted", "passwordauthentication")
    return _outcome(cfg, Status.FAIL, "passwords are accepted (brute-force target)", "passwordauthentication")


@check(
    "SSH-003",
    "Keyboard-interactive authentication is disabled",
    category="ssh",
    severity=Severity.MEDIUM,
    fix="Set 'KbdInteractiveAuthentication no' (ChallengeResponseAuthentication on older releases) unless you "
    "use it for two-factor login.",
    references=(MAN,),
)
def kbd_interactive(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    kbd, pam = cfg.get("kbdinteractiveauthentication"), cfg.get("usepam")
    if kbd == "no":
        return _outcome(cfg, Status.PASS, "keyboard-interactive login is off", "kbdinteractiveauthentication", "usepam")
    if pam == "yes":
        return _outcome(
            cfg,
            Status.FAIL,
            "PAM keyboard-interactive login can accept passwords",
            "kbdinteractiveauthentication",
            "usepam",
        )
    return _outcome(cfg, Status.WARN, "keyboard-interactive login is on", "kbdinteractiveauthentication", "usepam")


@check(
    "SSH-004",
    "Empty passwords are refused",
    category="ssh",
    severity=Severity.CRITICAL,
    fix="Set 'PermitEmptyPasswords no' (the default) and give every account a password or lock it.",
    references=(MAN,),
)
def empty_passwords(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    if cfg.get("permitemptypasswords") == "no":
        return _outcome(cfg, Status.PASS, "accounts without a password cannot log in", "permitemptypasswords")
    return _outcome(cfg, Status.FAIL, "accounts without a password can log in", "permitemptypasswords")


def _algos(cfg: SshdConfig, key: str) -> list[str]:
    return [a.strip().lower() for a in cfg.options.get(key, "").split(",") if a.strip()]


@check(
    "SSH-005",
    "No weak ciphers, MACs or key exchange algorithms",
    category="ssh",
    severity=Severity.MEDIUM,
    fix="Remove CBC/arcfour ciphers, MD5/SHA1-96 MACs and SHA1 key exchanges from Ciphers, MACs and "
    "KexAlgorithms, or delete those lines to use the OpenSSH defaults.",
    references=(MAN,),
)
def weak_crypto(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    weak: list[str] = []
    legacy: list[str] = []
    for key, bad in (("ciphers", WEAK_CIPHERS), ("macs", WEAK_MACS), ("kexalgorithms", WEAK_KEX)):
        for algo in _algos(cfg, key):
            if any(algo == b or (b.endswith("-") and algo.startswith(b)) for b in bad):
                weak.append(f"{key}: {algo}")
            elif algo in LEGACY:
                legacy.append(f"{key}: {algo}")
    evidence = [f"source: {cfg.source}"]
    if not any(k in cfg.options for k in ("ciphers", "macs", "kexalgorithms")):
        return Outcome(
            Status.PASS,
            "no algorithm lists configured; OpenSSH defaults are used",
            evidence,
            partial=cfg.partial,
            partial_reason="read from files" if cfg.partial else "",
        )
    if legacy:
        evidence.append("legacy but not broken: " + ", ".join(legacy))
    if weak:
        return Outcome(Status.FAIL, f"{len(weak)} weak algorithm(s) enabled", weak + evidence, partial=cfg.partial)
    return Outcome(Status.PASS, "no weak algorithms enabled", evidence, partial=cfg.partial)


@check(
    "SSH-006",
    "MaxAuthTries is 4 or lower",
    category="ssh",
    severity=Severity.LOW,
    fix="Set 'MaxAuthTries 3' to slow down password guessing per connection.",
    references=(MAN,),
)
def max_auth_tries(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    try:
        value = int(cfg.get("maxauthtries"))
    except ValueError:
        return _outcome(cfg, Status.WARN, "MaxAuthTries could not be read", "maxauthtries")
    if value <= 4:
        return _outcome(cfg, Status.PASS, f"MaxAuthTries is {value}", "maxauthtries")
    return _outcome(cfg, Status.WARN, f"MaxAuthTries is {value}", "maxauthtries")


@check(
    "SSH-007",
    "X11 forwarding is disabled",
    category="ssh",
    severity=Severity.LOW,
    fix="Set 'X11Forwarding no'; a web server has no use for it (Ubuntu's shipped sshd_config turns it on).",
    references=(MAN,),
)
def x11(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    if cfg.get("x11forwarding") == "no":
        return _outcome(cfg, Status.PASS, "X11 forwarding is off", "x11forwarding")
    return _outcome(cfg, Status.WARN, "X11 forwarding is on", "x11forwarding")


@check(
    "SSH-008",
    "LoginGraceTime is 60 seconds or less",
    category="ssh",
    severity=Severity.LOW,
    fix="Set 'LoginGraceTime 30' so unauthenticated connections do not hold slots for two minutes.",
    references=(MAN,),
)
def grace_time(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    raw = cfg.get("logingracetime")
    seconds = _duration(raw)
    if seconds is None:
        return _outcome(cfg, Status.WARN, f"LoginGraceTime {raw!r} could not be read", "logingracetime")
    if 0 < seconds <= 60:
        return _outcome(cfg, Status.PASS, f"LoginGraceTime is {seconds}s", "logingracetime")
    text = "unlimited" if seconds == 0 else f"{seconds}s"
    return _outcome(cfg, Status.WARN, f"LoginGraceTime is {text}", "logingracetime")


def _duration(value: str) -> int | None:
    """sshd time format: ``120``, ``2m``, ``1h30m``."""
    if value.isdigit():
        return int(value)
    total, num = 0, ""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    for ch in value.lower():
        if ch.isdigit():
            num += ch
        elif ch in units and num:
            total += int(num) * units[ch]
            num = ""
        else:
            return None
    return total + (int(num) if num else 0)


@check(
    "SSH-009",
    "SSH logins are limited to named users or groups",
    category="ssh",
    severity=Severity.INFO,
    fix="Optionally add 'AllowGroups sshusers' (or AllowUsers) so new system accounts cannot log in by accident.",
    references=(MAN,),
)
def allow_lists(ctx: AuditContext) -> Outcome:
    cfg = sshd_config(ctx)
    keys = [k for k in ("allowusers", "allowgroups", "denyusers", "denygroups") if cfg.options.get(k)]
    port = cfg.options.get("port", "22")
    if keys:
        return Outcome(Status.INFO, "login allow/deny lists are set", [*cfg.evidence(*keys), f"port {port}"])
    return Outcome(
        Status.INFO,
        "no AllowUsers/AllowGroups: every account with a key or password can log in",
        [f"port {port}", f"source: {cfg.source}"],
    )
