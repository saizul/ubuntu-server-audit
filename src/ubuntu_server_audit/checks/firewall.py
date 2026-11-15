"""Firewall (UFW or nftables), listening ports and fail2ban."""

from __future__ import annotations

from ubuntu_server_audit.checks._common import cap, listeners, public_listeners, ufw
from ubuntu_server_audit.context import AuditContext, NeedsRoot, NotApplicable
from ubuntu_server_audit.model import Outcome, Severity, Status
from ubuntu_server_audit.parsers import NftInput, parse_fail2ban_jails, parse_nft_ruleset
from ubuntu_server_audit.registry import check

UFW_DOC = "https://ubuntu.com/server/docs/how-to/security/firewalls/"

#: Services that should not be reachable from the internet.
RISKY_PORTS = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5984: "CouchDB",
    2375: "Docker API (no TLS)",
    2376: "Docker API",
    9000: "PHP-FPM / FastCGI",
    8086: "InfluxDB",
    5601: "Kibana",
    15672: "RabbitMQ management",
    25565: "Minecraft",
}


def _nft(ctx: AuditContext) -> NftInput | None:
    def load() -> NftInput | None:
        if not ctx.has_command("nft"):
            return None
        result = ctx.run("nft", "list", "ruleset")
        if not result.ok:
            if result.denied or not ctx.is_root:
                raise NeedsRoot("nft list ruleset needs root")
            raise RuntimeError(result.describe())
        return parse_nft_ruleset(result.stdout)

    return ctx.memo("nft", load)


@check(
    "FW-001",
    "A host firewall is active",
    category="firewall",
    severity=Severity.HIGH,
    needs_root=True,
    fix="sudo ufw allow OpenSSH && sudo ufw allow 'Nginx Full' && sudo ufw enable (allow your SSH port first).",
    references=(UFW_DOC,),
)
def firewall_active(ctx: AuditContext) -> Outcome:
    status = ufw(ctx)
    evidence = []
    if status is not None:
        evidence.append(f"ufw: {'active' if status.active else 'inactive'}")
        if status.active:
            return Outcome(Status.PASS, "UFW is active", evidence)
    nft = _nft(ctx)
    if nft is not None:
        evidence.append(
            f"nftables input chains: {nft.chains}, rules: {nft.rules}, "
            f"policy drop: {'yes' if nft.policy_drop else 'no'}"
        )
        if nft.chains and (nft.policy_drop or nft.rules):
            if nft.policy_drop:
                return Outcome(Status.PASS, "nftables filters incoming traffic", evidence)
            return Outcome(Status.WARN, "nftables has input rules but the chain policy is accept", evidence)
    if status is None and nft is None:
        evidence.append("neither ufw nor nft is installed")
    return Outcome(Status.FAIL, "no host firewall filters incoming traffic", evidence)


@check(
    "FW-002",
    "Incoming traffic is denied by default",
    category="firewall",
    severity=Severity.MEDIUM,
    needs_root=True,
    fix="sudo ufw default deny incoming && sudo ufw default allow outgoing",
    references=(UFW_DOC,),
)
def default_policy(ctx: AuditContext) -> Outcome:
    status = ufw(ctx)
    if status is not None and status.active:
        evidence = [
            f"incoming: {status.incoming or '?'}",
            f"outgoing: {status.outgoing or '?'}",
            f"routed: {status.routed or '?'}",
            *cap(status.rules, ctx.options.max_listed, "rules"),
        ]
        if status.incoming in ("deny", "reject"):
            return Outcome(Status.PASS, f"default incoming policy is {status.incoming}", evidence)
        return Outcome(Status.FAIL, f"default incoming policy is {status.incoming or 'unknown'}", evidence)
    nft = _nft(ctx)
    if nft is not None and nft.chains:
        if nft.policy_drop:
            return Outcome(Status.PASS, "nftables input policy is drop", ["policy drop"])
        return Outcome(Status.FAIL, "nftables input policy is accept", ["policy accept"])
    raise NotApplicable("no active firewall (see FW-001)")


@check(
    "FW-003",
    "Listening network services (inventory)",
    category="firewall",
    severity=Severity.INFO,
    fix="Stop services you do not need, or bind them to 127.0.0.1.",
)
def inventory(ctx: AuditContext) -> Outcome:
    items = listeners(ctx)
    public = [str(lst) for lst in items if lst.public]
    local = [str(lst) for lst in items if not lst.public]
    evidence = [f"reachable from the network: {len(public)}", *cap(public, ctx.options.max_listed)]
    evidence += [f"local only: {len(local)}", *cap(local, 10)]
    if not ctx.is_root:
        evidence.append("process names need root")
    return Outcome(
        Status.INFO,
        f"{len(public)} public and {len(local)} local listening sockets",
        evidence,
        partial=not ctx.is_root,
        partial_reason="process names need root" if not ctx.is_root else "",
    )


@check(
    "FW-004",
    "Databases and internal services are not exposed",
    category="firewall",
    severity=Severity.HIGH,
    fix="Bind the service to 127.0.0.1 (or a private interface) in its configuration and restart it; if it "
    "must listen publicly, allow only specific source addresses in the firewall.",
)
def risky_ports(ctx: AuditContext) -> Outcome:
    exposed = [lst for lst in public_listeners(ctx) if lst.port in RISKY_PORTS and lst.proto == "tcp"]
    if not exposed:
        return Outcome(Status.PASS, "no database or internal service listens on a public address")
    evidence = [f"{lst} - {RISKY_PORTS[lst.port]}" for lst in exposed]
    try:
        status = ufw(ctx)
    except NeedsRoot:
        return Outcome(
            Status.FAIL,
            f"{len(exposed)} internal service(s) listen on public addresses",
            evidence,
            partial=True,
            partial_reason="firewall rules need root",
        )
    if status is not None and status.active and status.incoming in ("deny", "reject"):
        allowed = [lst for lst in exposed if status.allows_port(lst.port)]
        if not allowed:
            return Outcome(
                Status.WARN,
                "internal services listen publicly but the firewall blocks them",
                [*evidence, "ufw: default deny, no allow rule for these ports"],
            )
        evidence += [f"ufw allows port {lst.port}" for lst in allowed]
    return Outcome(Status.FAIL, f"{len(exposed)} internal service(s) reachable from the network", evidence)


@check(
    "FW-005",
    "fail2ban protects SSH",
    category="firewall",
    severity=Severity.MEDIUM,
    fix="sudo apt install fail2ban; Ubuntu enables the sshd jail by default. Check with 'sudo fail2ban-client "
    "status sshd'.",
    references=("https://github.com/fail2ban/fail2ban",),
)
def fail2ban(ctx: AuditContext) -> Outcome:
    installed = ctx.has_command("fail2ban-client") or ctx.exists("/usr/bin/fail2ban-client")
    if not installed:
        return Outcome(Status.FAIL, "fail2ban is not installed")
    active = ctx.run("systemctl", "is-active", "fail2ban")
    if not active.missing:
        state = active.stdout.strip() or "unknown"
        if state != "active":
            return Outcome(
                Status.FAIL,
                f"fail2ban is installed but its service is {state}",
                [f"systemctl is-active fail2ban: {state}"],
            )
    if not ctx.is_root:
        raise NeedsRoot("fail2ban service is active; listing jails needs root")
    result = ctx.run("fail2ban-client", "status")
    if not result.ok:
        return Outcome(Status.WARN, "fail2ban is running but its status could not be read", [result.describe()])
    jails = parse_fail2ban_jails(result.stdout)
    evidence = [f"jails: {', '.join(jails) or '(none)'}"]
    if any(j in ("sshd", "ssh") or j.startswith("sshd") for j in jails):
        return Outcome(Status.PASS, f"{len(jails)} jail(s) active, including sshd", evidence)
    return Outcome(Status.WARN, "fail2ban runs but no sshd jail is enabled", evidence)
