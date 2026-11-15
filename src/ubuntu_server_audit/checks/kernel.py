"""Kernel parameters (sysctl) for network and process hardening."""

from __future__ import annotations

from ubuntu_server_audit.context import AuditContext, NotApplicable
from ubuntu_server_audit.model import Outcome, Severity, Status
from ubuntu_server_audit.registry import check

SYSCTL_DOC = "https://docs.kernel.org/networking/ip-sysctl.html"
FIX_FILE = "/etc/sysctl.d/60-hardening.conf"

#: key -> (accepted values, recommended value, why)
NETWORK = {
    "net.ipv4.tcp_syncookies": ({"1"}, "1", "SYN flood protection"),
    "net.ipv4.conf.all.accept_redirects": ({"0"}, "0", "ignore ICMP redirects"),
    "net.ipv4.conf.default.accept_redirects": ({"0"}, "0", "ignore ICMP redirects"),
    "net.ipv4.conf.all.secure_redirects": ({"0"}, "0", "ignore gateway ICMP redirects"),
    "net.ipv4.conf.all.send_redirects": ({"0"}, "0", "a server is not a router"),
    "net.ipv4.conf.default.send_redirects": ({"0"}, "0", "a server is not a router"),
    "net.ipv4.conf.all.accept_source_route": ({"0"}, "0", "drop source-routed packets"),
    "net.ipv4.conf.default.accept_source_route": ({"0"}, "0", "drop source-routed packets"),
    "net.ipv4.conf.all.rp_filter": ({"1", "2"}, "1", "reverse path filtering against spoofing"),
    "net.ipv4.conf.default.rp_filter": ({"1", "2"}, "1", "reverse path filtering against spoofing"),
    "net.ipv4.conf.all.log_martians": ({"1"}, "1", "log impossible addresses"),
    "net.ipv4.icmp_echo_ignore_broadcasts": ({"1"}, "1", "smurf attack protection"),
    "net.ipv4.icmp_ignore_bogus_error_responses": ({"1"}, "1", "ignore bogus ICMP errors"),
    "net.ipv6.conf.all.accept_redirects": ({"0"}, "0", "ignore ICMPv6 redirects"),
    "net.ipv6.conf.default.accept_redirects": ({"0"}, "0", "ignore ICMPv6 redirects"),
    "net.ipv6.conf.all.accept_source_route": ({"0"}, "0", "drop source-routed packets"),
}
KERNEL = {
    "kernel.randomize_va_space": ({"2"}, "2", "full address space layout randomisation"),
    "kernel.kptr_restrict": ({"1", "2"}, "1", "hide kernel pointers"),
    "kernel.dmesg_restrict": ({"1"}, "1", "only root reads the kernel log"),
    "kernel.yama.ptrace_scope": ({"1", "2", "3"}, "1", "restrict ptrace"),
    "fs.protected_symlinks": ({"1"}, "1", "symlink race protection"),
    "fs.protected_hardlinks": ({"1"}, "1", "hardlink protection"),
    "fs.protected_fifos": ({"1", "2"}, "1", "FIFO protection in sticky directories"),
    "fs.protected_regular": ({"1", "2"}, "2", "file protection in sticky directories"),
    "fs.suid_dumpable": ({"0"}, "0", "no core dumps of setuid programs"),
}


def read_sysctl(ctx: AuditContext, key: str) -> str | None:
    result = ctx.try_read("/proc/sys/" + key.replace(".", "/"))
    if not result.ok:
        return None
    return " ".join((result.text or "").split())


def _evaluate(ctx: AuditContext, table: dict[str, tuple[set[str], str, str]], label: str) -> Outcome:
    if not ctx.exists("/proc/sys/kernel"):
        raise NotApplicable("/proc/sys is not available (not Linux, or a restricted container)")
    bad, missing, good = [], [], 0
    for key, (accepted, recommended, why) in table.items():
        value = read_sysctl(ctx, key)
        if value is None:
            missing.append(key)
        elif value in accepted:
            good += 1
        else:
            bad.append(f"{key} = {value} (recommended {recommended}: {why})")
    evidence = bad + ([f"not present: {', '.join(missing)}"] if missing else [])
    fix_lines = [f"{k} = {table[k][1]}" for k in (b.split(" = ")[0] for b in bad)]
    fix = (f"Add to {FIX_FILE}:\n  " + "\n  ".join(fix_lines) + "\nthen run: sudo sysctl --system") if bad else None
    if not bad:
        return Outcome(Status.PASS, f"all {good} {label} settings are hardened", evidence)
    status = Status.FAIL if len(bad) >= 3 else Status.WARN
    return Outcome(status, f"{len(bad)} of {len(table)} {label} settings are not hardened", evidence, fix=fix)


@check(
    "KRN-001",
    "Network stack hardening (sysctl)",
    category="kernel",
    severity=Severity.MEDIUM,
    fix=f"Set the listed keys in {FIX_FILE} and run 'sudo sysctl --system'.",
    references=(SYSCTL_DOC,),
)
def network(ctx: AuditContext) -> Outcome:
    return _evaluate(ctx, NETWORK, "network")


@check(
    "KRN-002",
    "Kernel and filesystem hardening (sysctl)",
    category="kernel",
    severity=Severity.LOW,
    fix=f"Set the listed keys in {FIX_FILE} and run 'sudo sysctl --system'.",
    references=("https://docs.kernel.org/admin-guide/sysctl/kernel.html",),
)
def kernel_hardening(ctx: AuditContext) -> Outcome:
    return _evaluate(ctx, KERNEL, "kernel")


@check(
    "KRN-003",
    "IP forwarding is off unless the host routes traffic",
    category="kernel",
    severity=Severity.LOW,
    fix="If this host does not run containers or a VPN, set net.ipv4.ip_forward = 0 in "
    f"{FIX_FILE}; Docker, LXD and WireGuard need it on.",
    references=(SYSCTL_DOC,),
)
def ip_forward(ctx: AuditContext) -> Outcome:
    v4 = read_sysctl(ctx, "net.ipv4.ip_forward")
    v6 = read_sysctl(ctx, "net.ipv6.conf.all.forwarding")
    if v4 is None:
        raise NotApplicable("/proc/sys/net is not available")
    evidence = [f"net.ipv4.ip_forward = {v4}", f"net.ipv6.conf.all.forwarding = {v6 if v6 is not None else '?'}"]
    if v4 == "0" and v6 in (None, "0"):
        return Outcome(Status.PASS, "the host does not forward packets", evidence)
    routers = [name for name in ("docker", "lxd", "wg", "podman", "incus") if ctx.has_command(name)]
    if routers:
        return Outcome(Status.INFO, f"forwarding is on, expected with {', '.join(routers)}", evidence)
    return Outcome(Status.WARN, "the host forwards packets but no container or VPN software was found", evidence)
