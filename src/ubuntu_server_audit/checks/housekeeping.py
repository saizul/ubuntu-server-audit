"""Swap, disk and inode usage, time sync, journald size and root cron jobs."""

from __future__ import annotations

import posixpath

from ubuntu_server_audit.checks._common import cap, writable_by_others
from ubuntu_server_audit.context import AuditContext, NotApplicable
from ubuntu_server_audit.model import Outcome, Severity, Status
from ubuntu_server_audit.parsers import (
    CronJob,
    command_paths,
    parse_crontab,
    parse_df,
    parse_ini,
    parse_journal_usage,
    parse_key_values,
    parse_size,
)
from ubuntu_server_audit.registry import check

DF_EXCLUDE = ("-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs")
CRON_DIRS = ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")


@check(
    "HK-001",
    "Swap is configured",
    category="housekeeping",
    severity=Severity.LOW,
    fix="Create a swap file: sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile "
    "&& sudo swapon /swapfile, and add it to /etc/fstab. Small VPS plans often have none, so the kernel "
    "kills MariaDB or PHP-FPM under memory pressure.",
)
def swap(ctx: AuditContext) -> Outcome:
    meminfo = ctx.try_read("/proc/meminfo")
    if not meminfo.ok:
        raise NotApplicable("/proc/meminfo is not available")
    values = {}
    for line in (meminfo.text or "").splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0]) * 1024
    total, ram = values.get("SwapTotal", 0), values.get("MemTotal", 0)
    evidence = [f"RAM {ram / 1024**3:.1f} GiB, swap {total / 1024**3:.1f} GiB"]
    if total > 0:
        return Outcome(Status.PASS, "swap is available", evidence)
    return Outcome(Status.WARN, "no swap: memory spikes end in the out-of-memory killer", evidence)


PSEUDO_FS = ("tmpfs", "devtmpfs", "udev", "overlay", "squashfs", "efivarfs", "devfs", "map", "none")


def _df(ctx: AuditContext, inodes: bool, label: str) -> Outcome:
    base = ("df", "-P", "-i") if inodes else ("df", "-P")
    result = ctx.run(*base, *DF_EXCLUDE)
    if result.missing:
        raise NotApplicable("df is not available")
    rows = parse_df(result.stdout)  # df exits 1 when one mount is unreadable but still prints the others
    if not rows:
        result = ctx.run(*base)  # a df without -x (BusyBox): filter pseudo filesystems here instead
        rows = [
            r
            for r in parse_df(result.stdout)
            if r.filesystem not in PSEUDO_FS and not r.mount.startswith(("/snap/", "/proc", "/sys", "/dev", "/run"))
        ]
    if not rows:
        raise RuntimeError(result.describe())
    warn, fail = ctx.options.disk_warn_percent, ctx.options.disk_fail_percent
    evidence = [f"{r.mount}: {r.used_percent}% {label} used ({r.filesystem})" for r in rows]
    full = [r for r in rows if r.used_percent >= fail]
    high = [r for r in rows if warn <= r.used_percent < fail]
    if full:
        return Outcome(
            Status.FAIL, ", ".join(f"{r.mount} {r.used_percent}%" for r in full) + f" {label} used", evidence
        )
    if high:
        return Outcome(
            Status.WARN, ", ".join(f"{r.mount} {r.used_percent}%" for r in high) + f" {label} used", evidence
        )
    return Outcome(Status.PASS, f"all filesystems below {warn}% {label} usage", evidence)


@check(
    "HK-002",
    "Disks have free space",
    category="housekeeping",
    severity=Severity.MEDIUM,
    fix="Find large directories with 'sudo du -xh / --max-depth=2 | sort -h | tail'; clean old logs, backups, "
    "caches (apt clean, journalctl --vacuum-size=500M) or grow the disk.",
)
def disk(ctx: AuditContext) -> Outcome:
    return _df(ctx, False, "space")


@check(
    "HK-003",
    "Filesystems have free inodes",
    category="housekeeping",
    severity=Severity.MEDIUM,
    fix="Find directories with many small files (sessions, cache, mail queue): "
    "'sudo find / -xdev -type d -size +1M' and clean them up.",
)
def inodes(ctx: AuditContext) -> Outcome:
    return _df(ctx, True, "inodes")


@check(
    "HK-004",
    "The clock is synchronised (NTP)",
    category="housekeeping",
    severity=Severity.MEDIUM,
    fix="sudo timedatectl set-ntp true (systemd-timesyncd), or install chrony; TLS, logs and TOTP need a correct "
    "clock.",
    references=("https://ubuntu.com/server/docs/how-to/networking/timedatectl-and-timesyncd/",),
)
def time_sync(ctx: AuditContext) -> Outcome:
    result = ctx.run("timedatectl", "show")
    if result.missing:
        raise NotApplicable("timedatectl is not available")
    values = parse_key_values(result.stdout) if result.ok else {}
    if not values:
        raise RuntimeError(result.describe())
    ntp, synced = values.get("NTP", "?"), values.get("NTPSynchronized", "?")
    evidence = [f"NTP={ntp}", f"NTPSynchronized={synced}", f"Timezone={values.get('Timezone', '?')}"]
    if synced == "yes":
        return Outcome(Status.PASS, "the clock is synchronised", evidence)
    if ntp == "yes":
        return Outcome(Status.WARN, "NTP is enabled but the clock is not synchronised yet", evidence)
    return Outcome(Status.FAIL, "time synchronisation is off", evidence)


@check(
    "HK-005",
    "The systemd journal has a size limit",
    category="housekeeping",
    severity=Severity.LOW,
    fix="Set 'SystemMaxUse=500M' in /etc/systemd/journald.conf.d/size.conf, then sudo systemctl restart "
    "systemd-journald (or vacuum now: sudo journalctl --vacuum-size=500M).",
)
def journald(ctx: AuditContext) -> Outcome:
    limit = None
    for path in ["/etc/systemd/journald.conf", *ctx.glob("/etc/systemd/journald.conf.d/*.conf")]:
        read = ctx.try_read(path)
        if read.ok:
            value = parse_ini(read.text or "", comment="#;").get("journal", {}).get("systemmaxuse")
            if value:
                limit = (value, path)
    result = ctx.run("journalctl", "--disk-usage")
    if result.missing and limit is None:
        raise NotApplicable("journald is not in use")
    usage = parse_journal_usage(result.stdout + result.stderr)
    evidence = [
        f"SystemMaxUse={limit[0]} ({limit[1]})"
        if limit
        else "SystemMaxUse not set (default: 10% of the filesystem, at most 4G)"
    ]
    if usage is not None:
        evidence.append(f"journal size: {usage / 1024**2:.0f} MiB")
    partial = not ctx.is_root
    reason = "as a normal user journalctl may only count journals you can read" if partial else ""
    if usage is not None and usage > ctx.options.journal_warn_bytes:
        return Outcome(
            Status.WARN, f"the journal uses {usage / 1024**3:.1f} GiB", evidence, partial=partial, partial_reason=reason
        )
    if limit is not None:
        limit_bytes = parse_size(limit[0])
        if limit_bytes is not None and limit_bytes > 8 * 1024**3:
            return Outcome(Status.WARN, f"SystemMaxUse={limit[0]} is very large", evidence)
    return Outcome(Status.PASS, "the journal size is bounded", evidence, partial=partial, partial_reason=reason)


def _root_jobs(ctx: AuditContext) -> tuple[list[CronJob], list[str]]:
    jobs: list[CronJob] = []
    unreadable: list[str] = []
    sources = [("/etc/crontab", True), *[(p, True) for p in ctx.glob("/etc/cron.d/*")]]
    for path, system in sources:
        if posixpath.basename(path).startswith(".") or path.endswith((".dpkg-old", ".dpkg-dist", "~")):
            continue
        read = ctx.try_read(path)
        if read.ok:
            jobs += [j for j in parse_crontab(read.text or "", path, system=system) if j.user == "root"]
        elif read.denied:
            unreadable.append(path)
    spool = "/var/spool/cron/crontabs/root"
    read = ctx.try_read(spool)
    if read.ok:
        jobs += parse_crontab(read.text or "", spool, system=False)
    elif read.denied or not ctx.is_root:
        unreadable.append(spool)
    for directory in CRON_DIRS:
        try:
            names = ctx.fs.listdir(directory)
        except OSError:
            continue
        for name in names:
            if name.startswith(".") or name == "placeholder":
                continue
            path = posixpath.join(directory, name)
            jobs.append(CronJob(directory, "root", path))
    return jobs, unreadable


@check(
    "HK-006",
    "Root cron jobs do not run writable scripts",
    category="housekeeping",
    severity=Severity.HIGH,
    fix="Make every script that root runs from cron owned by root and not writable by group or others "
    "(chown root:root FILE && chmod 755 FILE), including its directory. Run site tasks such as "
    "'php artisan schedule:run' or wp-cron from the site user's crontab instead of root's.",
)
def cron_writable(ctx: AuditContext) -> Outcome:
    jobs, unreadable = _root_jobs(ctx)
    if not jobs and not unreadable:
        raise NotApplicable("no root cron jobs found")
    risky: list[str] = []
    checked = 0
    for job in jobs:
        for path in command_paths(job.command):
            st = ctx.stat(path)
            if st is None:
                continue
            checked += 1
            why = writable_by_others(st)
            target = path
            if why is None:
                parent = posixpath.dirname(path.rstrip("/"))
                pst = ctx.stat(parent) if parent else None
                if pst is not None:
                    why = writable_by_others(pst)
                    target = f"{path} (directory {parent})" if why else path
            if why:
                risky.append(f"{target}: {why} - from {job.source}: {job.command[:120]}")
    evidence = [f"root cron jobs: {len(jobs)}, paths checked: {checked}"]
    evidence += [f"unreadable: {p}" for p in unreadable]
    partial = bool(unreadable)
    reason = "root's own crontab needs root to read" if partial else ""
    if risky:
        return Outcome(
            Status.FAIL,
            f"{len(risky)} root cron path(s) can be modified by other users",
            [*cap(risky, ctx.options.max_listed), *evidence],
            partial=partial,
            partial_reason=reason,
        )
    return Outcome(
        Status.PASS,
        "every path run by root's cron jobs is owned and writable by root only",
        evidence,
        partial=partial,
        partial_reason=reason,
    )
