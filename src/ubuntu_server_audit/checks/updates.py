"""Security updates: unattended-upgrades, pending updates, reboot-required, release support."""

from __future__ import annotations

from datetime import datetime, timezone

from ubuntu_server_audit.checks._common import cap, package_installed
from ubuntu_server_audit.context import AuditContext, NotApplicable
from ubuntu_server_audit.model import Outcome, Severity, Status
from ubuntu_server_audit.parsers import parse_apt_check, parse_apt_config, parse_apt_upgradable, parse_os_release
from ubuntu_server_audit.registry import check

AUTO_DOC = "https://ubuntu.com/server/docs/how-to/software/automatic-updates/"
AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
APT_CHECK = "/usr/lib/update-notifier/apt-check"
REBOOT_REQUIRED = "/var/run/reboot-required"
TESTED_RELEASES = ("22.04", "24.04")
SUPPORTED_LTS = ("22.04", "24.04", "26.04")


def _periodic(ctx: AuditContext) -> tuple[dict[str, str], str]:
    result = ctx.run("apt-config", "dump")
    if result.ok:
        return parse_apt_config(result.stdout), "apt-config dump"
    merged: dict[str, str] = {}
    files = ctx.glob("/etc/apt/apt.conf.d/*")
    for path in files:
        read = ctx.try_read(path)
        if read.ok:
            merged.update(parse_apt_config(read.text or ""))
    return merged, "/etc/apt/apt.conf.d/*"


@check(
    "UPD-001",
    "Automatic security updates are enabled",
    category="updates",
    severity=Severity.HIGH,
    fix="sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades (writes "
    f'{AUTO_UPGRADES} with APT::Periodic::Unattended-Upgrade "1").',
    references=(AUTO_DOC,),
)
def unattended(ctx: AuditContext) -> Outcome:
    installed = package_installed(ctx, "unattended-upgrades")
    if installed is None:
        raise NotApplicable("dpkg is not available (not a Debian/Ubuntu system)")
    if not installed:
        return Outcome(Status.FAIL, "unattended-upgrades is not installed")
    config, source = _periodic(ctx)
    lists = config.get("APT::Periodic::Update-Package-Lists", "0")
    upgrade = config.get("APT::Periodic::Unattended-Upgrade", "0")
    evidence = [
        f'APT::Periodic::Update-Package-Lists "{lists}"',
        f'APT::Periodic::Unattended-Upgrade "{upgrade}"',
        f"source: {source}",
    ]
    timer = ctx.run("systemctl", "is-enabled", "apt-daily-upgrade.timer")
    if not timer.missing:
        evidence.append(f"apt-daily-upgrade.timer: {timer.stdout.strip() or timer.describe()}")
    if upgrade in ("0", "") or lists in ("0", ""):
        return Outcome(Status.FAIL, "unattended-upgrades is installed but the periodic run is disabled", evidence)
    if not timer.missing and timer.stdout.strip() not in ("enabled", "static", "indirect", "alias"):
        return Outcome(Status.WARN, "enabled in APT, but the apt-daily-upgrade timer is not enabled", evidence)
    return Outcome(Status.PASS, "security updates install automatically", evidence)


@check(
    "UPD-002",
    "No pending security updates",
    category="updates",
    severity=Severity.HIGH,
    fix="sudo apt update && sudo apt upgrade (or wait for unattended-upgrades); then check reboot-required.",
    references=(AUTO_DOC,),
)
def pending(ctx: AuditContext) -> Outcome:
    if ctx.exists(APT_CHECK):
        result = ctx.run(APT_CHECK)
        counts = parse_apt_check(result.stderr + result.stdout)
        if counts is not None:
            total, security = counts
            evidence = [f"apt-check: {total} update(s), {security} security", _lists_age_note(ctx)]
            if security:
                return Outcome(Status.FAIL, f"{security} security update(s) pending", evidence)
            if total:
                return Outcome(Status.WARN, f"{total} non-security update(s) pending", evidence)
            return Outcome(Status.PASS, "no pending updates", evidence)
    result = ctx.run("apt", "list", "--upgradable")
    if result.missing:
        raise NotApplicable("apt is not available")
    if not result.ok:
        raise RuntimeError(result.describe())
    every, security = parse_apt_upgradable(result.stdout)
    evidence = [
        f"{len(every)} upgradable, {len(security)} from -security",
        *cap(security, ctx.options.max_listed),
        _lists_age_note(ctx),
    ]
    if security:
        return Outcome(Status.FAIL, f"{len(security)} security update(s) pending", evidence)
    if every:
        return Outcome(Status.WARN, f"{len(every)} non-security update(s) pending", evidence)
    return Outcome(Status.PASS, "no pending updates", evidence)


def _lists_age_days(ctx: AuditContext) -> float | None:
    for path in ("/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists/partial", "/var/lib/apt/lists"):
        st = ctx.stat(path)
        if st is not None and st.mtime:
            when = datetime.fromtimestamp(st.mtime, tz=timezone.utc)
            return max((ctx.now - when).total_seconds() / 86400, 0.0)
    return None


def _lists_age_note(ctx: AuditContext) -> str:
    age = _lists_age_days(ctx)
    return "package lists: age unknown" if age is None else f"package lists updated {age:.1f} day(s) ago"


@check(
    "UPD-003",
    "No reboot is pending",
    category="updates",
    severity=Severity.MEDIUM,
    fix="Schedule a reboot (sudo reboot) so the updated kernel and libraries are used, or set "
    'Unattended-Upgrade::Automatic-Reboot "true" with a quiet Automatic-Reboot-Time.',
    references=(AUTO_DOC,),
)
def reboot_required(ctx: AuditContext) -> Outcome:
    if not ctx.exists(REBOOT_REQUIRED) and not ctx.exists("/run/reboot-required"):
        return Outcome(Status.PASS, "no reboot required")
    pkgs = ctx.try_read(REBOOT_REQUIRED + ".pkgs")
    if not pkgs.ok:
        pkgs = ctx.try_read("/run/reboot-required.pkgs")
    names = sorted({p.strip() for p in (pkgs.text or "").splitlines() if p.strip()})
    return Outcome(
        Status.FAIL,
        "a reboot is required to finish installing updates",
        [f"{REBOOT_REQUIRED} exists", *cap([f"package: {n}" for n in names], ctx.options.max_listed)],
    )


@check(
    "UPD-004",
    "Package lists are recent",
    category="updates",
    severity=Severity.LOW,
    fix='sudo apt update; make sure APT::Periodic::Update-Package-Lists is "1" so this happens daily.',
)
def lists_fresh(ctx: AuditContext) -> Outcome:
    age = _lists_age_days(ctx)
    if age is None:
        raise NotApplicable("APT package lists not found")
    limit = ctx.options.apt_lists_max_age_days
    evidence = [f"last update {age:.1f} day(s) ago (limit {limit})"]
    if age <= limit:
        return Outcome(Status.PASS, "package lists are up to date, so update checks are meaningful", evidence)
    return Outcome(Status.WARN, f"package lists are {age:.0f} days old; pending updates may be missed", evidence)


@check(
    "UPD-005",
    "The Ubuntu release is supported",
    category="updates",
    severity=Severity.HIGH,
    fix="Upgrade to a supported LTS release (do-release-upgrade) or enable Ubuntu Pro for extended security "
    "maintenance.",
    references=("https://ubuntu.com/about/release-cycle",),
)
def release(ctx: AuditContext) -> Outcome:
    text = ctx.read("/etc/os-release")
    if text is None:
        raise NotApplicable("/etc/os-release not found")
    data = parse_os_release(text)
    name, version = data.get("PRETTY_NAME", "?"), data.get("VERSION_ID", "")
    evidence = [f"{name} (ID={data.get('ID', '?')}, VERSION_ID={version or '?'})"]
    if data.get("ID") != "ubuntu":
        return Outcome(Status.WARN, f"not Ubuntu ({name}); results may not apply", evidence)
    if version in TESTED_RELEASES:
        return Outcome(Status.PASS, f"{name} is a supported LTS release", evidence)
    if version in SUPPORTED_LTS:
        return Outcome(Status.PASS, f"{name} is an LTS release (not yet tested with this tool)", evidence)
    lts = version.endswith(".04") and version[:2].isdigit() and int(version[:2]) % 2 == 0
    if lts and version < SUPPORTED_LTS[0]:
        return Outcome(Status.FAIL, f"{name} is past standard support", [*evidence, "check Ubuntu Pro / ESM"])
    return Outcome(Status.WARN, f"{name} is not an LTS release this tool knows", evidence)
