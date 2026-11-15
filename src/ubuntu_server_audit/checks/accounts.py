"""Accounts, sudo rules, world-writable web files and setuid programs."""

from __future__ import annotations

import posixpath

from ubuntu_server_audit.checks._common import cap, writable_by_others
from ubuntu_server_audit.context import AuditContext, NotApplicable
from ubuntu_server_audit.model import Outcome, Severity, Status
from ubuntu_server_audit.parsers import (
    parse_passwd,
    parse_shadow_empty,
    sudoers_dir_file_allowed,
    sudoers_includes,
    sudoers_nopasswd,
)
from ubuntu_server_audit.registry import check
from ubuntu_server_audit.system import WalkStats, walk

#: Directories searched for setuid/setgid programs (not /home, /proc, /sys or network mounts).
SUID_DIRS = (
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/opt",
)
SUID_SKIP = ("/usr/lib/modules", "/usr/lib/firmware", "/usr/lib/python3", "/usr/lib/jvm", "/usr/lib/node_modules")
#: setuid/setgid programs shipped by Ubuntu 22.04/24.04 server packages.
KNOWN_SUID = frozenset(
    {
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/gpasswd",
        "/usr/bin/newgrp",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/bin/fusermount",
        "/usr/bin/fusermount3",
        "/usr/bin/pkexec",
        "/usr/bin/at",
        "/usr/bin/crontab",
        "/usr/bin/ssh-agent",
        "/usr/bin/expiry",
        "/usr/bin/chage",
        "/usr/bin/wall",
        "/usr/bin/write",
        "/usr/bin/bsd-write",
        "/usr/bin/dotlockfile",
        "/usr/bin/mlocate",
        "/usr/bin/plocate",
        "/usr/bin/screen",
        "/usr/bin/ntfs-3g",
        "/usr/bin/staprun",
        "/usr/bin/vmware-user-suid-wrapper",
        "/usr/bin/newuidmap",
        "/usr/bin/newgidmap",
        "/usr/bin/sg",
        "/usr/sbin/unix_chkpwd",
        "/usr/sbin/pam_extrausers_chkpwd",
        "/usr/sbin/pppd",
        "/usr/sbin/mount.nfs",
        "/usr/sbin/mount.cifs",
        "/usr/sbin/postdrop",
        "/usr/sbin/postqueue",
        "/usr/sbin/exim4",
        "/usr/sbin/sendmail",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/policykit-1/polkit-agent-helper-1",
        "/usr/libexec/polkit-agent-helper-1",
        "/usr/lib/eject/dmcrypt-get-device",
        "/usr/lib/snapd/snap-confine",
        "/usr/lib/xorg/Xorg.wrap",
        "/usr/lib/x86_64-linux-gnu/utempter/utempter",
        "/usr/lib/aarch64-linux-gnu/utempter/utempter",
        "/usr/libexec/utempter/utempter",
        "/usr/lib/landscape/apt-update",
        "/usr/lib/chromium/chrome-sandbox",
        "/bin/su",
        "/bin/mount",
        "/bin/umount",
        "/bin/fusermount",
        "/sbin/unix_chkpwd",
    }
)


@check(
    "USR-001",
    "No account has an empty password",
    category="accounts",
    severity=Severity.CRITICAL,
    needs_root=True,
    fix="Lock the account (sudo passwd -l NAME) or set a password (sudo passwd NAME).",
)
def empty_passwords(ctx: AuditContext) -> Outcome:
    text = ctx.read("/etc/shadow")
    if text is None:
        raise NotApplicable("/etc/shadow not found")
    empty = parse_shadow_empty(text)
    if empty:
        return Outcome(Status.FAIL, f"{len(empty)} account(s) without a password", [f"account: {n}" for n in empty])
    return Outcome(Status.PASS, "every account has a password hash or is locked")


@check(
    "USR-002",
    "Only root has UID 0",
    category="accounts",
    severity=Severity.CRITICAL,
    fix="Give the extra account a normal UID (usermod -u) or delete it; use sudo for administrators.",
)
def uid_zero(ctx: AuditContext) -> Outcome:
    text = ctx.read("/etc/passwd")
    if text is None:
        raise NotApplicable("/etc/passwd not found")
    entries = parse_passwd(text)
    extra = [e.name for e in entries if e.uid == 0 and e.name != "root"]
    shells = [e for e in entries if e.uid >= 1000 and e.uid != 65534 and not e.shell.endswith(("nologin", "false"))]
    evidence = [f"login accounts (UID >= 1000): {', '.join(e.name for e in shells) or '(none)'}"]
    if extra:
        return Outcome(
            Status.FAIL, f"{len(extra)} other account(s) with UID 0", [*[f"UID 0: {n}" for n in extra], *evidence]
        )
    return Outcome(Status.PASS, "root is the only UID 0 account", evidence)


def _sudoers_files(ctx: AuditContext) -> tuple[list[str], list[str]]:
    files: list[str] = []
    errors: list[str] = []
    queue = ["/etc/sudoers"]
    while queue and len(files) < 200:
        path = queue.pop(0)
        if path in files:
            continue
        text = ctx.read(path)
        if text is None:
            continue
        files.append(path)
        inc_files, inc_dirs = sudoers_includes(text)
        queue.extend(inc_files)
        for directory in inc_dirs:
            try:
                names = ctx.fs.listdir(directory)
            except OSError as exc:
                errors.append(f"{directory}: {exc}")
                continue
            queue.extend(posixpath.join(directory, n) for n in names if sudoers_dir_file_allowed(n))
    return files, errors


@check(
    "USR-003",
    "sudo asks for a password (no NOPASSWD rules)",
    category="accounts",
    severity=Severity.MEDIUM,
    needs_root=True,
    fix="Remove NOPASSWD from the listed rules (cloud images add one for the default user in "
    "/etc/sudoers.d/90-cloud-init-users), or limit it to specific commands.",
)
def nopasswd(ctx: AuditContext) -> Outcome:
    files, errors = _sudoers_files(ctx)
    if not files:
        raise NotApplicable("sudo is not configured")
    found = []
    for path in files:
        for rule in sudoers_nopasswd(ctx.read(path) or ""):
            found.append(f"{path}: {rule}")
    evidence = [*found, *errors, f"files read: {len(files)}"]
    if found:
        broad = [f for f in found if f.rstrip().endswith("ALL")]
        status = Status.FAIL if broad else Status.WARN
        return Outcome(
            status, f"{len(found)} NOPASSWD rule(s)" + (" allowing every command" if broad else ""), evidence
        )
    return Outcome(Status.PASS, "every sudo rule requires a password", evidence)


def _web_roots(ctx: AuditContext) -> list[str]:
    roots = list(ctx.options.web_roots)
    try:
        from ubuntu_server_audit.checks.web import nginx_config

        config = nginx_config(ctx)
        for d in config.config.find("root"):
            if d.args and d.args[0].startswith("/") and "$" not in d.args[0]:
                roots.append(d.args[0].rstrip("/") or "/")
    except Exception:  # nginx not installed or unreadable: the default roots are enough
        pass
    out: list[str] = []
    for root in roots:
        if root in ("/", "/usr", "/etc", "/home") or root.startswith("/home/"):
            continue  # never walk home directories or system trees from here
        if not any(root == o or root.startswith(o.rstrip("/") + "/") for o in out):
            out = [o for o in out if not o.startswith(root.rstrip("/") + "/")]
            out.append(root)
    return sorted(out)


@check(
    "USR-004",
    "No world-writable files in web roots",
    category="accounts",
    severity=Severity.HIGH,
    fix="chmod o-w the listed paths (find WEBROOT -perm -0002 -exec chmod o-w {} +); give write access to the "
    "PHP-FPM user through group ownership of specific upload directories only.",
)
def world_writable_web(ctx: AuditContext) -> Outcome:
    roots = [r for r in _web_roots(ctx) if ctx.fs.is_dir(r)]
    if not roots:
        raise NotApplicable("no web root found (" + ", ".join(ctx.options.web_roots) + ")")
    stats = WalkStats()
    hits: list[str] = []
    for root in roots:
        top = ctx.stat(root, follow_symlinks=False)
        entries = [(root, top)] if top is not None else []
        for path, st in [*entries, *walk(ctx.fs, root, max_entries=ctx.options.max_walk_entries, stats=stats)]:
            if st.is_link:
                continue
            if st.world_writable and not (st.is_dir and st.sticky):
                hits.append(f"{path} ({oct(st.perms)}{', directory' if st.is_dir else ''})")
    evidence = [f"web roots: {', '.join(roots)}", f"entries checked: {stats.entries}"]
    partial = bool(stats.errors) or stats.truncated
    if stats.errors:
        evidence.append(f"unreadable: {len(stats.errors)} path(s), e.g. {stats.errors[0]}")
    if stats.truncated:
        evidence.append(f"stopped after {ctx.options.max_walk_entries} entries")
    reason = "some directories could not be read" + (" (run as root)" if not ctx.is_root else "")
    if hits:
        return Outcome(
            Status.FAIL,
            f"{len(hits)} world-writable path(s) in web roots",
            [*cap(hits, ctx.options.max_listed), *evidence],
            partial=partial,
            partial_reason=reason,
        )
    return Outcome(
        Status.PASS,
        "no world-writable files or directories in web roots",
        evidence,
        partial=partial,
        partial_reason=reason if partial else "",
    )


@check(
    "USR-005",
    "setuid/setgid programs (review list)",
    category="accounts",
    severity=Severity.MEDIUM,
    fix="Investigate programs not installed by Ubuntu packages (dpkg -S PATH); remove the bit with chmod u-s,g-s "
    "if it is not needed. A setuid file writable by a non-root user is a root shell for that user.",
)
def suid(ctx: AuditContext) -> Outcome:
    stats = WalkStats()
    found: list[tuple[str, str]] = []
    writable: list[str] = []
    for top in SUID_DIRS:
        top_stat = ctx.stat(top, follow_symlinks=False)
        if top_stat is None or top_stat.is_link or not top_stat.is_dir:
            continue  # /bin and /sbin are symlinks to /usr on merged-/usr systems
        for path, st in walk(
            ctx.fs, top, max_depth=6, max_entries=ctx.options.max_walk_entries, stats=stats, skip=SUID_SKIP
        ):
            if not st.is_file or not (st.suid or st.sgid):
                continue
            bits = "+".join(b for b, on in (("setuid", st.suid), ("setgid", st.sgid)) if on)
            found.append((path, bits))
            why = writable_by_others(st)
            if why:
                writable.append(f"{path} ({bits}, {why})")
    if not found and not stats.entries:
        raise NotApplicable("no program directories found")
    unknown = [f"{p} ({b})" for p, b in found if p not in KNOWN_SUID]
    evidence = [f"setuid/setgid programs: {len(found)}, not on the Ubuntu default list: {len(unknown)}"]
    evidence += cap(unknown, ctx.options.max_listed)
    evidence.append("known: " + ", ".join(posixpath.basename(p) for p, _ in found if p in KNOWN_SUID))
    partial = bool(stats.errors) or stats.truncated
    if stats.errors:
        evidence.append(f"unreadable: {len(stats.errors)} path(s)")
    if stats.truncated:
        evidence.append(f"stopped after {ctx.options.max_walk_entries} entries (--max-files)")
    if writable:
        return Outcome(
            Status.FAIL,
            f"{len(writable)} setuid/setgid program(s) writable by non-root users",
            [*writable, *evidence],
            partial=partial,
        )
    if unknown:
        return Outcome(
            Status.WARN,
            f"{len(unknown)} setuid/setgid program(s) to review",
            evidence,
            partial=partial,
            partial_reason="some directories could not be read" if partial else "",
        )
    return Outcome(
        Status.PASS,
        "only the usual setuid/setgid programs",
        evidence,
        partial=partial,
        partial_reason="some directories could not be read" if partial else "",
    )
