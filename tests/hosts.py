"""Fake Ubuntu hosts: a hardened 24.04 web server and a neglected 22.04 one."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fakes import DENIED, FakeFS, FakeRunner, fail, ok
from ubuntu_server_audit.context import AuditContext, AuditOptions
from ubuntu_server_audit.kernel_values import HARDENED_SYSCTL

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
RECENT = NOW.timestamp() - 3600


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000:Admin:/home/admin:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""
SHADOW = """root:*:19800:0:99999:7:::
daemon:*:19800:0:99999:7:::
www-data:*:19800:0:99999:7:::
sshd:!:19800::::::
admin:$y$j9T$saltsalt$hashhashhash:19800:0:99999:7:::
nobody:*:19800:0:99999:7:::
"""
SUDOERS = """Defaults	env_reset
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root	ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
"""
OS_2404 = 'PRETTY_NAME="Ubuntu 24.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\nID_LIKE=debian\n'
OS_2204 = 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nID_LIKE=debian\n'
CRONTAB = """SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
"""
KNOWN_SUID = ["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/mount", "/usr/lib/openssh/ssh-keysign"]


def _sysctl(fs: FakeFS, values: dict[str, str]) -> None:
    for key, value in values.items():
        fs.add_file("/proc/sys/" + key.replace(".", "/"), value + "\n")


def _base_fs(os_release: str) -> FakeFS:
    fs = FakeFS()
    fs.add_file("/etc/os-release", os_release)
    fs.add_file("/proc/sys/kernel/hostname", "web1\n")
    fs.add_file("/proc/sys/kernel/osrelease", "6.8.0-48-generic\n")
    fs.add_file("/proc/uptime", "864000.12 1700000.00\n")
    fs.add_file("/etc/passwd", PASSWD)
    fs.add_file("/etc/shadow", SHADOW, mode=0o640, gid=42)
    fs.add_file("/etc/sudoers", SUDOERS, mode=0o440)
    fs.add_dir("/etc/sudoers.d", mode=0o750)
    fs.add_file("/etc/sudoers.d/README", "# comments only\n", mode=0o440)
    fs.add_file("/etc/ssh/sshd_config", fixture("sshd_config-ubuntu-2404.txt"))
    fs.add_dir("/etc/ssh/sshd_config.d")
    fs.add_file("/usr/sbin/sshd", "", mode=0o755)
    fs.add_file("/etc/crontab", CRONTAB)
    fs.add_dir("/etc/cron.d")
    fs.add_file(
        "/etc/cron.d/e2scrub_all",
        "30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 "
        "/usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n",
    )
    fs.add_file("/usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron", "#!/bin/sh\n", mode=0o755)
    fs.add_file("/etc/cron.daily/logrotate", "#!/bin/sh\n", mode=0o755)
    fs.add_file("/etc/cron.daily/.placeholder", "")
    fs.add_dir("/var/spool/cron/crontabs", mode=0o1730, gid=105)
    fs.add_dir("/var/lib/apt/periodic")
    fs.add_file("/var/lib/apt/periodic/update-success-stamp", "", mtime=RECENT)
    fs.add_file("/usr/lib/update-notifier/apt-check", "", mode=0o755)
    for path in KNOWN_SUID:
        fs.add_file(path, "", mode=0o4755)
    fs.add_file("/usr/bin/ls", "", mode=0o755)
    fs.add_link("/bin", "usr/bin")
    fs.add_file("/etc/systemd/journald.conf", "[Journal]\n#SystemMaxUse=\n")
    fs.add_file("/proc/meminfo", "MemTotal:        4014560 kB\nSwapTotal:       2097148 kB\n")
    return fs


def hardened_host(*, root: bool = True) -> AuditContext:
    fs = _base_fs(OS_2404)
    _sysctl(fs, HARDENED_SYSCTL)
    fs.add_file(
        "/etc/apt/apt.conf.d/20auto-upgrades",
        'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
    )
    fs.add_dir("/var/www/example.com/public", uid=1000, gid=33, mode=0o755)
    fs.add_file("/var/www/example.com/public/index.php", "<?php echo 1;", uid=1000, gid=33, mode=0o644)
    fs.add_dir("/var/www/example.com/public/uploads", uid=33, gid=33, mode=0o775)
    fs.add_dir("/var/www/example.com/tmp", mode=0o1777)  # sticky: fine
    fs.add_file("/etc/nginx/nginx.conf", "events {}\nhttp { server_tokens off; }\n")
    fs.add_file("/etc/php/8.3/fpm/php.ini", "[PHP]\nexpose_php = Off\ndisplay_errors = Off\nlog_errors = On\n")
    fs.add_file("/etc/php/8.3/fpm/conf.d/10-opcache.ini", "zend_extension=opcache.so\n")
    fs.add_file("/etc/php/8.3/fpm/pool.d/www.conf", "[www]\nuser = www-data\nphp_admin_flag[log_errors] = on\n")
    fs.add_file("/etc/php/8.3/cli/php.ini", "[PHP]\nexpose_php = On\ndisplay_errors = STDOUT\n")  # CLI: ignored
    fs.add_file("/etc/mysql/my.cnf", "!includedir /etc/mysql/conf.d/\n!includedir /etc/mysql/mariadb.conf.d/\n")
    fs.add_file(
        "/etc/mysql/mariadb.conf.d/50-server.cnf",
        "[server]\n\n[mysqld]\nuser = mysql\nbind-address            = 127.0.0.1\n",
    )
    fs.add_file(
        "/etc/redis/redis.conf",
        "bind 127.0.0.1 -::1\nprotected-mode yes\nport 6379\nrequirepass ${REDIS_PASSWORD_FROM_VAULT}\n",
        mode=0o640,
        uid=112,
        gid=117,
    )
    fs.add_file("/etc/systemd/journald.conf.d/size.conf", "[Journal]\nSystemMaxUse=500M\n")
    fs.add_file("/var/spool/cron/crontabs/root", "0 3 * * * /usr/local/sbin/backup.sh\n", mode=0o600)
    fs.add_file("/usr/local/sbin/backup.sh", "#!/bin/sh\n", mode=0o700)

    runner = FakeRunner(
        {
            "sshd -T": fixture("sshd-T-hardened.txt"),
            "ufw status verbose": fixture("ufw-active.txt"),
            "nft list ruleset": "table inet filter {\n}\n",
            "ss -H -tulnp": fixture("ss-hardened.txt"),
            "ss -H -tuln": fixture("ss-hardened.txt"),
            "systemctl is-active fail2ban": "active\n",
            "fail2ban-client status": "Status\n|- Number of jail:\t2\n`- Jail list:\tnginx-http-auth, sshd\n",
            "dpkg-query -W -f=${Status} unattended-upgrades": "install ok installed",
            "apt-config dump": fixture("apt-config-enabled.txt"),
            "systemctl is-enabled apt-daily-upgrade.timer": "enabled\n",
            "/usr/lib/update-notifier/apt-check": ok("", "0;0"),
            "nginx -T": fixture("nginx-T-hardened.txt"),
            "df -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs": fixture("df-ok.txt"),
            "df -P -i -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs": fixture("df-i-ok.txt"),
            "timedatectl show": "Timezone=Etc/UTC\nNTP=yes\nNTPSynchronized=yes\n",
            "journalctl --disk-usage": "Archived and active journals take up 312.0M in the file system.\n",
        },
        available={
            "sshd",
            "ufw",
            "nft",
            "ss",
            "systemctl",
            "fail2ban-client",
            "dpkg-query",
            "apt-config",
            "apt",
            "nginx",
            "mariadbd",
            "redis-server",
            "df",
            "timedatectl",
            "journalctl",
        },
    )
    if not root:
        _drop_privileges(fs, runner)
    return AuditContext(runner, fs, root, AuditOptions(), now=NOW)


def neglected_host(*, root: bool = True) -> AuditContext:
    fs = _base_fs(OS_2204)
    weak = dict(HARDENED_SYSCTL)
    weak.update(
        {
            "net.ipv4.conf.all.accept_redirects": "1",
            "net.ipv4.conf.all.send_redirects": "1",
            "net.ipv4.conf.default.send_redirects": "1",
            "net.ipv4.conf.all.rp_filter": "0",
            "net.ipv4.conf.all.log_martians": "0",
            "net.ipv4.ip_forward": "1",
            "kernel.dmesg_restrict": "0",
        }
    )
    _sysctl(fs, weak)
    fs.add_file("/etc/passwd", PASSWD + "toor:x:0:0::/root:/bin/bash\ndeploy:x:1001:1001::/home/deploy:/bin/bash\n")
    fs.add_file("/etc/shadow", SHADOW + "toor:$6$x$y:19800::::::\ndeploy::19800:0:99999:7:::\n", mode=0o640, gid=42)
    fs.add_file(
        "/etc/sudoers.d/90-cloud-init-users", "# Created by cloud-init\nubuntu ALL=(ALL) NOPASSWD:ALL\n", mode=0o440
    )
    fs.add_file("/etc/sudoers.d/deploy", "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx\n", mode=0o440)
    fs.add_file("/etc/sudoers.d/old.bak", "deploy ALL=(ALL) NOPASSWD:ALL\n", mode=0o440)  # ignored by sudo
    fs.add_dir("/var/www/html", uid=33, gid=33)
    fs.add_file("/var/www/html/index.php", "<?php", uid=33, gid=33, mode=0o666)
    fs.add_dir("/var/www/html/wp-content/uploads", uid=33, gid=33, mode=0o777)
    fs.add_file("/var/www/html/cron.sh", "#!/bin/sh\nphp wp-cron.php\n", uid=33, gid=33, mode=0o755)
    fs.add_file(
        "/etc/cron.d/wordpress",
        "*/5 * * * * root /bin/sh /var/www/html/cron.sh > /dev/null 2>&1\n"
        "@daily www-data /usr/bin/php /var/www/html/wp-cron.php\n",
    )
    fs.add_file("/etc/cron.daily/backup", "#!/bin/sh\n", mode=0o777)
    fs.add_file("/usr/local/bin/helper", "", mode=0o4777, uid=0)
    fs.add_file("/usr/local/bin/oldtool", "", mode=0o2755)
    fs.add_file("/etc/nginx/nginx.conf", fixture("nginx.conf-ubuntu-2204.txt"))
    fs.add_file("/etc/nginx/mime.types", "types { text/html html; }\n")
    fs.add_dir("/etc/nginx/conf.d")
    fs.add_file("/etc/nginx/sites-enabled/default", fixture("site-default.txt"))
    fs.add_file("/etc/php/8.1/fpm/php.ini", "[PHP]\nexpose_php = On\ndisplay_errors = Off\n")
    fs.add_file("/etc/php/8.1/fpm/pool.d/www.conf", "[www]\nphp_flag[display_errors] = on\n")
    fs.add_file("/etc/mysql/mariadb.conf.d/50-server.cnf", "[mysqld]\nbind-address = 0.0.0.0\n")
    fs.add_file(
        "/etc/redis/redis.conf", "# bind 127.0.0.1 -::1\nprotected-mode no\nport 6379\n", mode=0o640, uid=112, gid=117
    )
    fs.add_file("/var/run/reboot-required", "*** System restart required ***\n")
    fs.add_file("/var/run/reboot-required.pkgs", "linux-base\nlibssl3\nlibssl3\n")
    fs.add_file("/var/lib/apt/periodic/update-success-stamp", "", mtime=NOW.timestamp() - 40 * 86400)
    fs.remove("/usr/lib/update-notifier/apt-check")
    fs.add_file("/proc/meminfo", "MemTotal:        1004560 kB\nSwapTotal:             0 kB\n")

    runner = FakeRunner(
        {
            "sshd -T": fixture("sshd-T-weak.txt"),
            "ufw status verbose": "Status: inactive\n",
            "ss -H -tulnp": fixture("ss-exposed.txt"),
            "ss -H -tuln": fixture("ss-exposed.txt"),
            "dpkg-query -W -f=${Status} unattended-upgrades": fail(
                1, "dpkg-query: no packages found matching unattended-upgrades"
            ),
            "apt list --upgradable": ok(
                fixture("apt-list-upgradable.txt"), "WARNING: apt does not have a stable CLI interface."
            ),
            "nginx -T": fail(1, 'nginx: [emerg] open() "/run/nginx.pid" failed (13: Permission denied)'),
            "df -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs": fixture("df-full.txt"),
            "df -P -i -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs": fixture("df-i-high.txt"),
            "timedatectl show": "Timezone=Etc/UTC\nNTP=no\nNTPSynchronized=no\n",
            "journalctl --disk-usage": "Archived and active journals take up 3.5G in the file system.\n",
        },
        available={
            "sshd",
            "ufw",
            "ss",
            "systemctl",
            "dpkg-query",
            "apt",
            "nginx",
            "mysqld",
            "redis-server",
            "df",
            "timedatectl",
            "journalctl",
        },
    )
    if not root:
        _drop_privileges(fs, runner)
    return AuditContext(runner, fs, root, AuditOptions(), now=NOW)


def _drop_privileges(fs: FakeFS, runner: FakeRunner) -> None:
    """What a normal user sees: root-only files and commands are denied."""
    fs.deny("/etc/shadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/redis/redis.conf", "/var/spool/cron/crontabs")
    denied = {
        "sshd -T": fail(1, "sshd: no hostkeys available -- exiting."),
        "ufw status verbose": fail(1, "ERROR: You need to be root to run this script"),
        "nft list ruleset": fail(1, "Operation not permitted (you must be root)"),
        "fail2ban-client status": DENIED,
        "nginx -T": fail(
            1,
            'nginx: [alert] could not open error log file: open() "/var/log/nginx/error.log" '
            "failed (13: Permission denied)",
        ),
        "ss -H -tulnp": fail(1, "Permission denied"),
    }
    for command, result in denied.items():
        if command.split()[0] in runner.available:
            runner.set(command, result)
