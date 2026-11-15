"""Helpers shared by several checks."""

from __future__ import annotations

from ubuntu_server_audit.context import AuditContext, NeedsRoot
from ubuntu_server_audit.parsers import Listener, UfwStatus, parse_ss, parse_ufw_status
from ubuntu_server_audit.system import FileStat


def listeners(ctx: AuditContext) -> list[Listener]:
    """Listening TCP/UDP sockets from ``ss`` (process names only as root)."""

    def load() -> list[Listener]:
        args = ("ss", "-H", "-tulnp") if ctx.is_root else ("ss", "-H", "-tuln")
        result = ctx.run(*args)
        if result.missing:
            result = ctx.run("netstat", "-tuln")
            if result.ok:
                return _parse_netstat(result.stdout)
        if not result.ok:
            raise RuntimeError(result.describe())
        return parse_ss(result.stdout)

    return ctx.memo("listeners", load)


def _parse_netstat(text: str) -> list[Listener]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].startswith(("tcp", "udp")):
            host, _, port = parts[3].rpartition(":")
            if port.isdigit():
                out.append(Listener(parts[0].rstrip("6"), host, int(port)))
    return out


def public_listeners(ctx: AuditContext, port: int | None = None) -> list[Listener]:
    return [lst for lst in listeners(ctx) if lst.public and (port is None or lst.port == port)]


def ufw(ctx: AuditContext) -> UfwStatus | None:
    """``ufw status verbose`` as root; ``None`` if ufw is not installed. Raises :class:`NeedsRoot`."""

    def load() -> UfwStatus | None:
        if not ctx.has_command("ufw"):
            return None
        if not ctx.is_root:
            raise NeedsRoot("ufw status needs root")
        result = ctx.run("ufw", "status", "verbose")
        if not result.ok:
            raise RuntimeError(result.describe())
        return parse_ufw_status(result.stdout)

    return ctx.memo("ufw", load)


def package_installed(ctx: AuditContext, name: str) -> bool | None:
    """``True``/``False`` from dpkg, ``None`` when dpkg-query is not available."""
    result = ctx.run("dpkg-query", "-W", "-f=${Status}", name)
    if result.missing:
        return None
    return result.ok and "install ok installed" in result.stdout


def writable_by_others(st: FileStat) -> str | None:
    """Why a file or directory can be modified by someone other than root, or ``None``."""
    if st.is_link:
        return None
    if st.world_writable and not (st.is_dir and st.sticky):
        return "world-writable"
    if st.uid != 0:
        return f"owned by uid {st.uid}"
    if st.group_writable and st.gid != 0:
        return f"group-writable (gid {st.gid})"
    return None


def cap(items: list[str], limit: int, what: str = "more") -> list[str]:
    if len(items) <= limit:
        return items
    return [*items[:limit], f"... and {len(items) - limit} {what}"]
