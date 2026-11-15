"""Edge cases of individual checks, on top of the fake hosts."""

import pytest

from fakes import FakeFS, FakeRunner, fail, ok
from hosts import NOW, hardened_host, neglected_host
from ubuntu_server_audit.context import AuditContext, AuditOptions
from ubuntu_server_audit.engine import run_check
from ubuntu_server_audit.model import Status
from ubuntu_server_audit.registry import REGISTRY, all_checks

all_checks()


def run(check_id, ctx):
    return run_check(REGISTRY[check_id], ctx)


def empty_ctx(root=True, runner=None, fs=None):
    return AuditContext(runner or FakeRunner(), fs or FakeFS(), root, AuditOptions(), now=NOW)


@pytest.mark.parametrize(
    ("value", "status"),
    [
        ("no", Status.PASS),
        ("prohibit-password", Status.WARN),
        ("without-password", Status.WARN),
        ("forced-commands-only", Status.WARN),
        ("yes", Status.FAIL),
    ],
)
def test_root_login_values(value, status):
    ctx = hardened_host()
    ctx.runner.set("sshd -T", ok(f"permitrootlogin {value}\npasswordauthentication no\n"))
    assert run("SSH-001", ctx).status is status


def test_ssh_not_installed_is_na():
    ctx = hardened_host()
    ctx.runner.remove("sshd")
    ctx.fs.remove("/usr/sbin/sshd")
    finding = run("SSH-002", ctx)
    assert finding.status is Status.NOT_APPLICABLE and "not installed" in finding.summary


def test_ssh_root_failure_is_error_not_crash():
    ctx = hardened_host()
    ctx.runner.set("sshd -T", fail(255, "/etc/ssh/sshd_config line 3: Bad configuration option: Foo"))
    finding = run("SSH-001", ctx)
    assert finding.status is Status.ERROR and "Bad configuration option" in finding.summary


def test_ssh_include_files_first_value_wins():
    ctx = hardened_host(root=False)
    ctx.fs.add_file("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    ctx.fs.add_file("/etc/ssh/sshd_config.d/60-hardening.conf", "PasswordAuthentication no\nPermitRootLogin no\n")
    assert run("SSH-002", ctx).status is Status.FAIL  # 50-cloud-init.conf is read first
    assert run("SSH-001", ctx).status is Status.PASS


def test_ssh_unreadable_config_needs_root():
    ctx = hardened_host(root=False)
    ctx.fs.deny("/etc/ssh/sshd_config")
    finding = run("SSH-001", ctx)
    assert finding.status is Status.SKIPPED and finding.skipped_reason == "needs root"


@pytest.mark.parametrize(
    ("value", "status"),
    [
        ("30", Status.PASS),
        ("1m", Status.PASS),
        ("2m", Status.WARN),
        ("0", Status.WARN),
        ("1h30m", Status.WARN),
        ("abc", Status.WARN),
    ],
)
def test_login_grace_time(value, status):
    ctx = hardened_host()
    ctx.runner.set("sshd -T", ok(f"permitrootlogin no\nlogingracetime {value}\n"))
    assert run("SSH-008", ctx).status is status


def test_ssh_defaults_when_no_algorithm_lists():
    ctx = hardened_host()
    ctx.runner.set("sshd -T", ok("permitrootlogin no\n"))
    assert run("SSH-005", ctx).status is Status.PASS


def test_firewall_nftables_only():
    ctx = neglected_host()
    ctx.runner.remove("ufw")
    ctx.runner.set(
        "nft list ruleset",
        ok(
            "table inet filter {\n chain input {\n  type filter hook input priority 0; "
            "policy drop;\n  tcp dport 22 accept\n }\n}\n"
        ),
    )
    assert run("FW-001", ctx).status is Status.PASS
    assert run("FW-002", ctx).status is Status.PASS
    ctx = neglected_host()
    ctx.runner.remove("ufw")
    ctx.runner.set(
        "nft list ruleset",
        ok(
            "table inet filter {\n chain input {\n  type filter hook input priority 0; "
            "policy accept;\n  tcp dport 22 accept\n }\n}\n"
        ),
    )
    assert run("FW-001", ctx).status is Status.WARN
    assert run("FW-002", ctx).status is Status.FAIL


def test_no_firewall_tools_at_all():
    ctx = neglected_host()
    ctx.runner.remove("ufw")
    finding = run("FW-001", ctx)
    assert finding.status is Status.FAIL and "neither ufw nor nft" in " ".join(finding.evidence)


def test_risky_port_blocked_by_firewall_is_warn():
    ctx = neglected_host()
    ctx.runner.set(
        "ufw status verbose",
        ok(
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n\n"
            "To Action From\n-- ------ ----\n22/tcp ALLOW IN Anywhere\n"
        ),
    )
    assert run("FW-004", ctx).status is Status.WARN
    ctx.runner.set(
        "ufw status verbose",
        ok(
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n\n"
            "To Action From\n-- ------ ----\n3306/tcp ALLOW IN Anywhere\n"
        ),
    )
    ctx._memo.clear()
    ctx._commands.clear()
    finding = run("FW-004", ctx)
    assert finding.status is Status.FAIL and any("ufw allows port 3306" in e for e in finding.evidence)


def test_fail2ban_without_sshd_jail():
    ctx = hardened_host()
    ctx.runner.set("fail2ban-client status", ok("`- Jail list:\tnginx-http-auth\n"))
    assert run("FW-005", ctx).status is Status.WARN
    ctx = hardened_host()
    ctx.runner.set("systemctl is-active fail2ban", fail(3, stdout="inactive\n"))
    assert run("FW-005", ctx).status is Status.FAIL


def test_unattended_upgrades_variants():
    ctx = hardened_host()
    ctx.runner.set(
        "apt-config dump", ok('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "0";\n')
    )
    assert run("UPD-001", ctx).status is Status.FAIL
    ctx = hardened_host()
    ctx.runner.remove("apt-config")  # falls back to /etc/apt/apt.conf.d/20auto-upgrades
    finding = run("UPD-001", ctx)
    assert finding.status is Status.PASS and "/etc/apt/apt.conf.d/*" in " ".join(finding.evidence)
    ctx = hardened_host()
    ctx.runner.set("systemctl is-enabled apt-daily-upgrade.timer", fail(1, stdout="disabled\n"))
    assert run("UPD-001", ctx).status is Status.WARN
    ctx = empty_ctx()
    assert run("UPD-001", ctx).status is Status.NOT_APPLICABLE


def test_pending_updates_from_apt_check():
    ctx = hardened_host()
    ctx.runner.set("/usr/lib/update-notifier/apt-check", ok("", "7;3"))
    assert run("UPD-002", ctx).status is Status.FAIL
    ctx = hardened_host()
    ctx.runner.set("/usr/lib/update-notifier/apt-check", ok("", "4;0"))
    assert run("UPD-002", ctx).status is Status.WARN


@pytest.mark.parametrize(
    ("release", "status"),
    [
        ('ID=ubuntu\nVERSION_ID="24.04"\n', Status.PASS),
        ('ID=ubuntu\nVERSION_ID="26.04"\n', Status.PASS),
        ('ID=ubuntu\nVERSION_ID="20.04"\n', Status.FAIL),
        ('ID=ubuntu\nVERSION_ID="25.10"\n', Status.WARN),
        ('ID=debian\nVERSION_ID="12"\n', Status.WARN),
    ],
)
def test_release(release, status):
    ctx = hardened_host()
    ctx.fs.add_file("/etc/os-release", release)
    assert run("UPD-005", ctx).status is status


def test_kernel_na_without_proc():
    finding = run("KRN-001", empty_ctx())
    assert finding.status is Status.NOT_APPLICABLE


def test_kernel_fix_hint_lists_keys():
    finding = run("KRN-001", neglected_host())
    assert "net.ipv4.conf.all.rp_filter = 1" in finding.fix and "sysctl --system" in finding.fix


def test_ip_forward_with_docker_is_info():
    ctx = neglected_host()
    ctx.runner.available.add("docker")
    assert run("KRN-003", ctx).status is Status.INFO


def test_web_roots_include_nginx_root_and_skip_home():
    ctx = hardened_host()
    ctx.fs.add_dir("/srv/sites/shop", mode=0o777)
    ctx.runner.set(
        "nginx -T",
        ok(
            "# configuration file /etc/nginx/nginx.conf:\nhttp { server_tokens off; "
            "server { root /srv/sites/shop; } server { root /home/bob/www; } }\n"
        ),
    )
    ctx.fs.add_dir("/home/bob/www", mode=0o777)
    finding = run("USR-004", ctx)
    assert finding.status is Status.FAIL
    text = " ".join(finding.evidence)
    assert "/srv/sites/shop" in text and "/home" not in text


def test_web_root_option_and_na():
    ctx = hardened_host()
    ctx.options.web_roots = ["/nonexistent"]
    ctx.runner.remove("nginx")
    ctx.fs.remove("/etc/nginx")
    assert run("USR-004", ctx).status is Status.NOT_APPLICABLE


def test_walk_limit_marks_partial():
    ctx = neglected_host()
    ctx.options.max_walk_entries = 2
    finding = run("USR-004", ctx)
    assert finding.partial and any("stopped after 2" in e for e in finding.evidence)


def test_php_defaults_and_cli_ignored():
    ctx = hardened_host()
    ctx.fs.add_file("/etc/php/8.3/fpm/php.ini", "[PHP]\nlog_errors = On\n")  # nothing set: PHP defaults (On)
    assert run("WEB-003", ctx).status is Status.FAIL
    assert run("WEB-004", ctx).status is Status.FAIL
    ctx = hardened_host()
    ctx.fs.remove("/etc/php/8.3/fpm")
    assert run("WEB-003", ctx).status is Status.NOT_APPLICABLE  # only CLI is left


def test_php_conf_d_override_wins():
    ctx = hardened_host()
    ctx.fs.add_file("/etc/php/8.3/fpm/conf.d/99-dev.ini", "display_errors = On\n")
    finding = run("WEB-004", ctx)
    assert finding.status is Status.FAIL and any("99-dev.ini" in e for e in finding.evidence)


def test_nginx_without_tls_is_na_and_default_is_warn():
    ctx = hardened_host()
    ctx.runner.set("nginx -T", ok("# configuration file /etc/nginx/nginx.conf:\nhttp { server { listen 80; } }\n"))
    assert run("WEB-002", ctx).status is Status.NOT_APPLICABLE
    ctx = hardened_host()
    ctx.runner.set("nginx -T", ok("# configuration file /etc/nginx/nginx.conf:\nhttp { server { listen 443 ssl; } }\n"))
    assert run("WEB-002", ctx).status is Status.WARN
    assert run("WEB-001", ctx).status is Status.FAIL


def test_nginx_server_tokens_override_in_server_block():
    ctx = hardened_host()
    ctx.runner.set(
        "nginx -T",
        ok("# configuration file /etc/nginx/nginx.conf:\nhttp { server_tokens off; server { server_tokens on; } }\n"),
    )
    assert run("WEB-001", ctx).status is Status.FAIL


def test_mysql_socket_only_and_not_installed():
    ctx = hardened_host()
    ctx.runner.set("ss -H -tulnp", ok(""))
    finding = run("DB-001", ctx)
    assert finding.status is Status.PASS and "socket only" in finding.summary
    ctx = hardened_host()
    ctx.runner.remove("mariadbd")
    ctx.fs.remove("/etc/mysql")
    assert run("DB-001", ctx).status is Status.NOT_APPLICABLE


def test_redis_config_problems_without_public_listener():
    ctx = hardened_host()
    ctx.fs.add_file("/etc/redis/redis.conf", "bind 0.0.0.0\nprotected-mode no\n")
    finding = run("DB-002", ctx)
    assert finding.status is Status.WARN and "protected-mode is off" in finding.summary


def test_disk_thresholds_and_busybox_fallback():
    ctx = hardened_host()
    ctx.options.disk_warn_percent = 20
    assert run("HK-002", ctx).status is Status.WARN
    ctx = hardened_host()
    ctx.runner.set("df -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs", fail(1, "df: unrecognized option"))
    ctx.runner.set(
        "df -P",
        ok("Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/root 100 50 50 50% /\ntmpfs 100 99 1 99% /run\n"),
    )
    finding = run("HK-002", ctx)
    assert finding.status is Status.PASS and "/run" not in " ".join(finding.evidence)


def test_time_sync_pending():
    ctx = hardened_host()
    ctx.runner.set("timedatectl show", ok("NTP=yes\nNTPSynchronized=no\n"))
    assert run("HK-004", ctx).status is Status.WARN


def test_cron_writable_directory_and_symlink():
    ctx = hardened_host()
    ctx.fs.add_dir("/opt/jobs", mode=0o777)
    ctx.fs.add_file("/opt/jobs/run.sh", "#!/bin/sh\n", mode=0o755)
    ctx.fs.add_file("/etc/cron.d/jobs", "0 * * * * root /opt/jobs/run.sh\n")
    finding = run("HK-006", ctx)
    assert finding.status is Status.FAIL and "directory /opt/jobs" in " ".join(finding.evidence)


def test_root_spool_job_checked_as_root():
    ctx = hardened_host()
    ctx.fs.add_file("/usr/local/sbin/backup.sh", "#!/bin/sh\n", mode=0o775, gid=1000)
    finding = run("HK-006", ctx)
    assert finding.status is Status.FAIL and "group-writable" in " ".join(finding.evidence)


def test_journald_large_limit():
    ctx = hardened_host()
    ctx.fs.add_file("/etc/systemd/journald.conf.d/size.conf", "[Journal]\nSystemMaxUse=20G\n")
    assert run("HK-005", ctx).status is Status.WARN


def test_swap_na_without_proc():
    assert run("HK-001", empty_ctx()).status is Status.NOT_APPLICABLE


def test_suid_walk_limit_is_partial():
    ctx = neglected_host()
    ctx.options.max_walk_entries = 3
    finding = run("USR-005", ctx)
    assert finding.partial and any("--max-files" in e for e in finding.evidence)
