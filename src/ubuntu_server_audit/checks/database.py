"""MariaDB/MySQL and Redis network exposure."""

from __future__ import annotations

from ubuntu_server_audit.checks._common import listeners, public_listeners
from ubuntu_server_audit.context import AuditContext, NotApplicable
from ubuntu_server_audit.model import Outcome, Severity, Status
from ubuntu_server_audit.parsers import is_public_address, parse_ini, parse_redis_conf
from ubuntu_server_audit.registry import check

MYSQL_GLOBS = (
    "/etc/mysql/my.cnf",
    "/etc/mysql/*.cnf",
    "/etc/mysql/conf.d/*.cnf",
    "/etc/mysql/mariadb.conf.d/*.cnf",
    "/etc/mysql/mysql.conf.d/*.cnf",
)
REDIS_CONF = "/etc/redis/redis.conf"


def _mysql_settings(ctx: AuditContext) -> tuple[dict[str, tuple[str, str]], list[str]]:
    settings: dict[str, tuple[str, str]] = {}
    unreadable = []
    seen = set()
    for pattern in MYSQL_GLOBS:
        for path in ctx.glob(pattern):
            if path in seen:
                continue
            seen.add(path)
            read = ctx.try_read(path)
            if not read.ok:
                if read.denied:
                    unreadable.append(path)
                continue
            for section, values in parse_ini(read.text or "", comment="#;", dashes=True).items():
                if section in ("mysqld", "mariadb", "server", "mariadbd") or section.startswith("mariadb-"):
                    for key, value in values.items():
                        settings[key] = (value, path)
    return settings, unreadable


@check(
    "DB-001",
    "MariaDB/MySQL is not listening on all interfaces",
    category="database",
    severity=Severity.HIGH,
    fix="Set 'bind-address = 127.0.0.1' in /etc/mysql/mariadb.conf.d/50-server.cnf (or mysql.conf.d/mysqld.cnf) "
    "and restart; for remote access use an SSH tunnel or a private network with firewall rules.",
    references=("https://mariadb.com/kb/en/configuring-mariadb-for-remote-client-access/",),
)
def mysql_bind(ctx: AuditContext) -> Outcome:
    installed = any(ctx.has_command(c) for c in ("mariadbd", "mysqld")) or ctx.exists("/etc/mysql")
    if not installed:
        raise NotApplicable("MariaDB/MySQL is not installed")
    settings, unreadable = _mysql_settings(ctx)
    bind = settings.get("bind_address")
    evidence = []
    if bind:
        evidence.append(f"bind-address = {bind[0]} ({bind[1]})")
    if "skip_networking" in settings:
        evidence.append(f"skip-networking ({settings['skip_networking'][1]})")
    evidence += [f"unreadable: {p}" for p in unreadable]
    sockets = [lst for lst in listeners(ctx) if lst.port in (3306, 33060) and lst.proto == "tcp"]
    evidence += [f"listening: {lst}" for lst in sockets]
    public = [lst for lst in sockets if lst.public]
    if public:
        return Outcome(Status.FAIL, "the database accepts connections from the network", evidence)
    if bind and is_public_address(bind[0]) and not sockets:
        return Outcome(Status.WARN, f"bind-address is {bind[0]} (not running now?)", evidence)
    if not sockets:
        return Outcome(Status.PASS, "no TCP listener on 3306 (local socket only or not running)", evidence)
    return Outcome(Status.PASS, "the database listens on loopback only", evidence)


@check(
    "DB-002",
    "Redis is bound to localhost with protected mode on",
    category="database",
    severity=Severity.HIGH,
    fix=f"In {REDIS_CONF} set 'bind 127.0.0.1 -::1' and 'protected-mode yes', and require a password with "
    "requirepass or ACL users; then sudo systemctl restart redis-server.",
    references=("https://redis.io/docs/latest/operate/oss_and_stack/management/security/",),
)
def redis(ctx: AuditContext) -> Outcome:
    installed = ctx.has_command("redis-server") or ctx.exists(REDIS_CONF)
    if not installed:
        raise NotApplicable("Redis is not installed")
    public = [lst for lst in public_listeners(ctx, 6379) if lst.proto == "tcp"]
    evidence = [f"listening publicly: {lst}" for lst in public]
    read = ctx.try_read(REDIS_CONF)
    problems = []
    partial = False
    if read.ok:
        conf = parse_redis_conf(read.text or "")
        binds = " ".join(conf.get("bind", [])).split()
        protected = (conf.get("protected-mode") or ["yes"])[-1].lower()
        has_auth = bool(conf.get("requirepass")) or any("on" in u.split() for u in conf.get("user", []))
        evidence += [
            f"bind {' '.join(binds) or '(unset: all interfaces)'}",
            f"protected-mode {protected}",
            f"password/ACL configured: {'yes' if has_auth else 'no'}",
        ]  # never print the secret
        if not binds or any(is_public_address(b.lstrip("-")) for b in binds):
            problems.append("bound to a public address")
        if protected == "no":
            problems.append("protected-mode is off")
        if public and not has_auth:
            problems.append("reachable without a password")
    elif read.denied:
        partial = True
        evidence.append(f"{REDIS_CONF}: permission denied (run as root to check bind and protected-mode)")
    if public:
        return Outcome(
            Status.FAIL,
            "Redis is reachable from the network" + (f": {', '.join(problems)}" if problems else ""),
            evidence,
            partial=partial,
            partial_reason="redis.conf needs root" if partial else "",
        )
    if problems:
        return Outcome(Status.WARN, "; ".join(problems), evidence)
    return Outcome(
        Status.PASS,
        "Redis listens on loopback only",
        evidence,
        partial=partial,
        partial_reason="redis.conf needs root" if partial else "",
    )
