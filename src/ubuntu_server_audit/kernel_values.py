"""Recommended sysctl values, shared by the kernel checks and the example hardening file."""

from __future__ import annotations

from ubuntu_server_audit.checks.kernel import KERNEL, NETWORK

#: Every checked key with its recommended value (net.ipv4.ip_forward = 0 for hosts that do not route).
HARDENED_SYSCTL: dict[str, str] = {
    **{k: v[1] for k, v in NETWORK.items()},
    **{k: v[1] for k, v in KERNEL.items()},
    "net.ipv4.ip_forward": "0",
    "net.ipv6.conf.all.forwarding": "0",
}


def sysctl_conf() -> str:
    """The contents of a ``/etc/sysctl.d/60-hardening.conf`` that satisfies KRN-001 to KRN-003."""
    lines = ["# Written by ubuntu-server-audit --print-sysctl. Review, then: sudo sysctl --system", ""]
    lines += [f"{k} = {v}" for k, v in HARDENED_SYSCTL.items()]
    return "\n".join(lines) + "\n"
