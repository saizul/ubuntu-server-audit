import pytest

from hosts import fixture
from ubuntu_server_audit import parsers as p


def test_os_release():
    data = p.parse_os_release('NAME="Ubuntu"\nVERSION_ID="24.04"\n# c\nID=ubuntu\nBAD\nX=\'it"s\'\n')
    assert data == {"NAME": "Ubuntu", "VERSION_ID": "24.04", "ID": "ubuntu", "X": 'it"s'}


def test_sshd_t():
    data = p.parse_sshd_t(fixture("sshd-T-hardened.txt"))
    assert data["permitrootlogin"] == ["no"]
    assert data["listenaddress"] == ["[::]:22", "0.0.0.0:22"]
    assert "chacha20-poly1305@openssh.com" in data["ciphers"][0]


def test_sshd_config_lines():
    pairs = p.parse_sshd_config_lines('# c\nPort 2222\nPermitRootLogin=no\nBanner "/etc/issue net"\n\tUsePAM   yes\n')
    assert pairs == [("port", "2222"), ("permitrootlogin", "no"), ("banner", "/etc/issue net"), ("usepam", "yes")]


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("0.0.0.0", True),
        ("*", True),
        ("::", True),
        ("203.0.113.5", True),
        ("10.0.0.5", True),
        ("127.0.0.1", False),
        ("127.0.0.53%lo", False),
        ("::1", False),
        ("fe80::1%eth0", False),
        ("::ffff:127.0.0.1", False),
        ("not-an-ip", True),
    ],
)
def test_public_address(address, public):
    assert p.is_public_address(address) is public


def test_parse_ss():
    rows = p.parse_ss(fixture("ss-hardened.txt"))
    by = {(r.address, r.port): r for r in rows}
    assert by[("127.0.0.1", 3306)].process == "mariadbd" and not by[("127.0.0.1", 3306)].public
    assert by[("::", 22)].public and by[("::1", 6379)].proto == "tcp"
    assert str(by[("::", 443)]) == "tcp [::]:443 (nginx)"
    assert p.parse_ss("Netid State Recv-Q Send-Q Local Peer\ngarbage line\n") == []


def test_ufw_status():
    status = p.parse_ufw_status(fixture("ufw-active.txt"))
    assert status.active and status.incoming == "deny" and status.outgoing == "allow" and status.routed == "disabled"
    assert status.allows_port(22) and status.allows_port(443) and not status.allows_port(3306)
    assert not status.allows_port(22, "udp")
    assert not p.parse_ufw_status("Status: inactive\n").active
    ranged = p.parse_ufw_status("Status: active\n\nTo Action From\n-- ------ ----\n6000:6010/tcp ALLOW IN Anywhere\n")
    assert ranged.allows_port(6005) and not ranged.allows_port(6011)


def test_nft_ruleset():
    text = """table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                tcp dport 22 accept
        }
        chain forward {
                type filter hook forward priority filter; policy drop;
        }
}"""
    result = p.parse_nft_ruleset(text)
    assert result.chains == 1 and result.policy_drop and result.rules == 2
    assert p.parse_nft_ruleset("table inet filter {\n}\n").chains == 0


def test_fail2ban_jails():
    assert p.parse_fail2ban_jails("`- Jail list:\tnginx-http-auth, sshd\n") == ["nginx-http-auth", "sshd"]
    assert p.parse_fail2ban_jails("nothing") == []


def test_apt_config():
    data = p.parse_apt_config(fixture("apt-config-enabled.txt"))
    assert data["APT::Periodic::Unattended-Upgrade"] == "1"
    nested = p.parse_apt_config(
        '// comment\nAPT {\n  Periodic {\n    Unattended-Upgrade "0"; // off\n  };\n};\n'
        '/* block */ APT::Periodic::Update-Package-Lists "1";\n'
    )
    assert nested == {"APT::Periodic::Unattended-Upgrade": "0", "APT::Periodic::Update-Package-Lists": "1"}


def test_apt_check_and_list():
    assert p.parse_apt_check("12;5") == (12, 5)
    assert p.parse_apt_check("garbage") is None
    every, security = p.parse_apt_upgradable(fixture("apt-list-upgradable.txt"))
    assert every == ["libssl3", "openssl", "nginx"] and security == ["libssl3", "openssl"]


def test_passwd_shadow():
    entries = p.parse_passwd("root:x:0:0:root:/root:/bin/bash\nbad:line\nx:x:notanumber:0::/:/bin/sh\n")
    assert [e.name for e in entries] == ["root"]
    assert p.parse_shadow_empty("a::1::::::\nb:*:1::::::\nc:!:1::::::\n#d::\n") == ["a"]


def test_sudoers():
    text = (
        "# comment NOPASSWD\nDefaults !authenticate\nadmin ALL=(ALL) NOPASSWD: ALL\n"
        "deploy ALL=(root) NOPASSWD: /bin/systemctl \\\n  reload nginx\n@includedir /etc/sudoers.d\n"
        "#include /etc/sudoers.local\n"
    )
    rules = p.sudoers_nopasswd(text)
    assert rules == ["admin ALL=(ALL) NOPASSWD: ALL", "deploy ALL=(root) NOPASSWD: /bin/systemctl reload nginx"]
    assert p.sudoers_includes(text) == (["/etc/sudoers.local"], ["/etc/sudoers.d"])
    assert p.sudoers_dir_file_allowed("90-cloud-init-users")
    assert not p.sudoers_dir_file_allowed("old.bak") and not p.sudoers_dir_file_allowed("x~")


def test_ini():
    data = p.parse_ini('; c\n[PHP]\nexpose_php = On ; comment\ndisplay_errors="Off"\n[Date]\ndate.timezone = UTC\n')
    assert data["php"] == {"expose_php": "On", "display_errors": "Off"}
    assert data["date"]["date.timezone"] == "UTC"
    my = p.parse_ini(
        "[mysqld]\nbind-address = 0.0.0.0 # all\nskip-name-resolve\n!includedir /x\n", comment="#;", dashes=True
    )
    assert my["mysqld"] == {"bind_address": "0.0.0.0", "skip_name_resolve": ""}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("On", True),
        ("1", True),
        ("stderr", True),
        ("Off", False),
        ("0", False),
        ("", False),
        ("maybe", None),
        (None, None),
    ],
)
def test_php_bool(value, expected):
    assert p.php_bool(value) is expected


def test_redis_conf():
    conf = p.parse_redis_conf("# bind 127.0.0.1\nbind 127.0.0.1 -::1\nprotected-mode yes\nuser default on >x ~*\n")
    assert conf["bind"] == ["127.0.0.1 -::1"] and conf["protected-mode"] == ["yes"] and "user" in conf


def test_df_and_sizes():
    rows = p.parse_df(fixture("df-full.txt"))
    assert [(r.mount, r.used_percent) for r in rows] == [("/", 95), ("/var/lib/mysql", 82)]
    assert p.parse_df(fixture("df-i-ok.txt"))[0].used_percent == 5
    assert p.parse_df("Filesystem Inodes IUsed IFree IUse% Mounted on\nbtrfs 0 0 0 - /\n") == []
    assert p.parse_size("1.5G") == int(1.5 * 1024**3)
    assert p.parse_size("512M") == 512 * 1024**2
    assert p.parse_size("8.0K") == 8192 and p.parse_size("12B") == 12 and p.parse_size("x") is None
    assert p.parse_journal_usage("Archived and active journals take up 3.5G in the file system.") == int(3.5 * 1024**3)
    assert p.parse_key_values("NTP=yes\nbad\nA=b=c\n") == {"NTP": "yes", "A": "b=c"}


def test_crontab():
    system = p.parse_crontab(
        "SHELL=/bin/sh\n# x\n*/5 * * * * root /opt/a.sh\n@daily www-data /usr/bin/php x\n* * * root\n",
        "/etc/cron.d/x",
        system=True,
    )
    assert [(j.user, j.command) for j in system] == [("root", "/opt/a.sh"), ("www-data", "/usr/bin/php x")]
    user = p.parse_crontab("0 3 * * * /usr/local/sbin/backup.sh --full\n@reboot /opt/start\n", "root", system=False)
    assert [j.command for j in user] == ["/usr/local/sbin/backup.sh --full", "/opt/start"]


@pytest.mark.parametrize(
    ("command", "paths"),
    [
        ("/bin/sh /var/www/html/cron.sh > /dev/null 2>&1", ["/bin/sh", "/var/www/html/cron.sh"]),
        ("cd / && run-parts --report /etc/cron.daily", ["/etc/cron.daily"]),
        (
            "test -x /usr/sbin/anacron || { cd / && run-parts /etc/cron.weekly; }",
            ["/usr/sbin/anacron", "/etc/cron.weekly"],
        ),
        ("SERVICE_MODE=1 /usr/lib/e2scrub_all_cron", ["/usr/lib/e2scrub_all_cron"]),
        ("/usr/bin/php /srv/app/artisan schedule:run >> /var/log/app.log", ["/usr/bin/php", "/srv/app/artisan"]),
        ("'unbalanced", []),
    ],
)
def test_command_paths(command, paths):
    assert p.command_paths(command) == paths
