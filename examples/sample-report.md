# Server audit: web1

**Score 8/100 (grade F)** from 36 scored checks.

- OS: Ubuntu 22.04.5 LTS, kernel 6.8.0-48-generic, uptime 10d 0h
- Run as: root
- Date: 2026-11-15T12:00:00+00:00, ubuntu-server-audit 0.1.0

## Fix first

| Severity | ID | Problem | Fix |
| --- | --- | --- | --- |
| critical | SSH-004 | accounts without a password can log in | Set 'PermitEmptyPasswords no' (the default) and give every account a password or lock it. |
| critical | USR-001 | 1 account(s) without a password | Lock the account (sudo passwd -l NAME) or set a password (sudo passwd NAME). |
| critical | USR-002 | 1 other account(s) with UID 0 | Give the extra account a normal UID (usermod -u) or delete it; use sudo for administrators. |
| high | DB-001 | the database accepts connections from the network | Set 'bind-address = 127.0.0.1' in /etc/mysql/mariadb.conf.d/50-server.cnf (or mysql.conf.d/mysqld.cnf) and restart; for remote access use an SSH tunnel or a private network with firewall rules. |
| high | DB-002 | Redis is reachable from the network: bound to a public address, protected-mode is off, reachable without a password | In /etc/redis/redis.conf set 'bind 127.0.0.1 -::1' and 'protected-mode yes', and require a password with requirepass or ACL users; then sudo systemctl restart redis-server. |
| high | FW-001 | no host firewall filters incoming traffic | sudo ufw allow OpenSSH && sudo ufw allow 'Nginx Full' && sudo ufw enable (allow your SSH port first). |
| high | FW-004 | 2 internal service(s) reachable from the network | Bind the service to 127.0.0.1 (or a private interface) in its configuration and restart it; if it must listen publicly, allow only specific source addresses in the firewall. |
| high | HK-006 | 2 root cron path(s) can be modified by other users | Make every script that root runs from cron owned by root and not writable by group or others (chown root:root FILE && chmod 755 FILE), including its directory. Run site tasks such as 'php artisan schedule:run' or wp-cron from the site user's crontab instead of root's. |
| high | SSH-001 | root can log in with a password | Set 'PermitRootLogin no' in /etc/ssh/sshd\_config.d/50-hardening.conf, log in as a normal user with sudo, then run 'sshd -t && systemctl reload ssh'. |
| high | SSH-002 | passwords are accepted (brute-force target) | After confirming key-based login works, set 'PasswordAuthentication no' and reload ssh. Check files in /etc/ssh/sshd\_config.d/ (cloud images often re-enable it there). |
| high | UPD-001 | unattended-upgrades is not installed | sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades (writes /etc/apt/apt.conf.d/20auto-upgrades with APT::Periodic::Unattended-Upgrade "1"). |
| high | UPD-002 | 2 security update(s) pending | sudo apt update && sudo apt upgrade (or wait for unattended-upgrades); then check reboot-required. |
| high | USR-004 | 2 world-writable path(s) in web roots | chmod o-w the listed paths (find WEBROOT -perm -0002 -exec chmod o-w {} +); give write access to the PHP-FPM user through group ownership of specific upload directories only. |
| high | WEB-002 | old protocols enabled: TLSv1, TLSv1.1 | Set 'ssl\_protocols TLSv1.2 TLSv1.3;' in the http block (Ubuntu 22.04's nginx.conf still lists TLSv1 and TLSv1.1) and in any server block that overrides it. |
| medium | FW-005 | fail2ban is not installed | sudo apt install fail2ban; Ubuntu enables the sshd jail by default. Check with 'sudo fail2ban-client status sshd'. |
| medium | HK-002 | / 95% space used | Find large directories with 'sudo du -xh / --max-depth=2 \| sort -h \| tail'; clean old logs, backups, caches (apt clean, journalctl --vacuum-size=500M) or grow the disk. |
| medium | HK-004 | time synchronisation is off | sudo timedatectl set-ntp true (systemd-timesyncd), or install chrony; TLS, logs and TOTP need a correct clock. |
| medium | KRN-001 | 5 of 16 network settings are not hardened | Add to /etc/sysctl.d/60-hardening.conf:   net.ipv4.conf.all.accept\_redirects = 0   net.ipv4.conf.all.send\_redirects = 0   net.ipv4.conf.default.send\_redirects = 0   net.ipv4.conf.all.rp\_filter = 1   net.ipv4.conf.all.log\_martians = 1 then run: sudo sysctl --system |
| medium | SSH-003 | PAM keyboard-interactive login can accept passwords | Set 'KbdInteractiveAuthentication no' (ChallengeResponseAuthentication on older releases) unless you use it for two-factor login. |
| medium | SSH-005 | 5 weak algorithm(s) enabled | Remove CBC/arcfour ciphers, MD5/SHA1-96 MACs and SHA1 key exchanges from Ciphers, MACs and KexAlgorithms, or delete those lines to use the OpenSSH defaults. |
| medium | UPD-003 | a reboot is required to finish installing updates | Schedule a reboot (sudo reboot) so the updated kernel and libraries are used, or set Unattended-Upgrade::Automatic-Reboot "true" with a quiet Automatic-Reboot-Time. |
| medium | USR-003 | 2 NOPASSWD rule(s) allowing every command | Remove NOPASSWD from the listed rules (cloud images add one for the default user in /etc/sudoers.d/90-cloud-init-users), or limit it to specific commands. |
| medium | USR-005 | 1 setuid/setgid program(s) writable by non-root users | Investigate programs not installed by Ubuntu packages (dpkg -S PATH); remove the bit with chmod u-s,g-s if it is not needed. A setuid file writable by a non-root user is a root shell for that user. |
| medium | WEB-004 | errors are shown to visitors by PHP 8.1 fpm | Set 'display\_errors = Off' and 'log\_errors = On' in php.ini and in pool files (php\_admin\_flag\[display\_errors\] = off), then restart PHP-FPM. |
| low | WEB-001 | server\_tokens is not set; nginx sends its version (default on) | Add 'server\_tokens off;' to the http block of /etc/nginx/nginx.conf (Ubuntu ships it commented out), then 'sudo nginx -t && sudo systemctl reload nginx'. |
| low | WEB-003 | X-Powered-By header sent by PHP 8.1 fpm | Set 'expose\_php = Off' in /etc/php/VERSION/fpm/php.ini (or a conf.d override) and restart PHP-FPM. |
| medium | HK-003 | / 85% inodes used | Find directories with many small files (sessions, cache, mail queue): 'sudo find / -xdev -type d -size +1M' and clean them up. |
| low | HK-001 | no swap: memory spikes end in the out-of-memory killer | Create a swap file: sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile, and add it to /etc/fstab. Small VPS plans often have none, so the kernel kills MariaDB or PHP-FPM under memory pressure. |
| low | HK-005 | the journal uses 3.5 GiB | Set 'SystemMaxUse=500M' in /etc/systemd/journald.conf.d/size.conf, then sudo systemctl restart systemd-journald (or vacuum now: sudo journalctl --vacuum-size=500M). |
| low | KRN-002 | 1 of 9 kernel settings are not hardened | Add to /etc/sysctl.d/60-hardening.conf:   kernel.dmesg\_restrict = 1 then run: sudo sysctl --system |
| low | KRN-003 | the host forwards packets but no container or VPN software was found | If this host does not run containers or a VPN, set net.ipv4.ip\_forward = 0 in /etc/sysctl.d/60-hardening.conf; Docker, LXD and WireGuard need it on. |
| low | SSH-006 | MaxAuthTries is 6 | Set 'MaxAuthTries 3' to slow down password guessing per connection. |
| low | SSH-007 | X11 forwarding is on | Set 'X11Forwarding no'; a web server has no use for it (Ubuntu's shipped sshd\_config turns it on). |
| low | SSH-008 | LoginGraceTime is 120s | Set 'LoginGraceTime 30' so unauthenticated connections do not hold slots for two minutes. |
| low | UPD-004 | package lists are 40 days old; pending updates may be missed | sudo apt update; make sure APT::Periodic::Update-Package-Lists is "1" so this happens daily. |

## All checks

### SSH

| Status | ID | Check | Severity | Result |
| --- | --- | --- | --- | --- |
| FAIL | SSH-001 | Root login over SSH is disabled | high | root can log in with a password |
| FAIL | SSH-002 | Password authentication is disabled | high | passwords are accepted (brute-force target) |
| FAIL | SSH-003 | Keyboard-interactive authentication is disabled | medium | PAM keyboard-interactive login can accept passwords |
| FAIL | SSH-004 | Empty passwords are refused | critical | accounts without a password can log in |
| FAIL | SSH-005 | No weak ciphers, MACs or key exchange algorithms | medium | 5 weak algorithm(s) enabled |
| WARN | SSH-006 | MaxAuthTries is 4 or lower | low | MaxAuthTries is 6 |
| WARN | SSH-007 | X11 forwarding is disabled | low | X11 forwarding is on |
| WARN | SSH-008 | LoginGraceTime is 60 seconds or less | low | LoginGraceTime is 120s |
| INFO | SSH-009 | SSH logins are limited to named users or groups | info | no AllowUsers/AllowGroups: every account with a key or password can log in |

### Firewall and network

| Status | ID | Check | Severity | Result |
| --- | --- | --- | --- | --- |
| FAIL | FW-001 | A host firewall is active | high | no host firewall filters incoming traffic |
| N/A | FW-002 | Incoming traffic is denied by default | medium | no active firewall (see FW-001) |
| INFO | FW-003 | Listening network services (inventory) | info | 7 public and 2 local listening sockets |
| FAIL | FW-004 | Databases and internal services are not exposed | high | 2 internal service(s) reachable from the network |
| FAIL | FW-005 | fail2ban protects SSH | medium | fail2ban is not installed |

### Updates

| Status | ID | Check | Severity | Result |
| --- | --- | --- | --- | --- |
| FAIL | UPD-001 | Automatic security updates are enabled | high | unattended-upgrades is not installed |
| FAIL | UPD-002 | No pending security updates | high | 2 security update(s) pending |
| FAIL | UPD-003 | No reboot is pending | medium | a reboot is required to finish installing updates |
| WARN | UPD-004 | Package lists are recent | low | package lists are 40 days old; pending updates may be missed |
| PASS | UPD-005 | The Ubuntu release is supported | high | Ubuntu 22.04.5 LTS is a supported LTS release |

### Kernel

| Status | ID | Check | Severity | Result |
| --- | --- | --- | --- | --- |
| FAIL | KRN-001 | Network stack hardening (sysctl) | medium | 5 of 16 network settings are not hardened |
| WARN | KRN-002 | Kernel and filesystem hardening (sysctl) | low | 1 of 9 kernel settings are not hardened |
| WARN | KRN-003 | IP forwarding is off unless the host routes traffic | low | the host forwards packets but no container or VPN software was found |

### Users and files

| Status | ID | Check | Severity | Result |
| --- | --- | --- | --- | --- |
| FAIL | USR-001 | No account has an empty password | critical | 1 account(s) without a password |
| FAIL | USR-002 | Only root has UID 0 | critical | 1 other account(s) with UID 0 |
| FAIL | USR-003 | sudo asks for a password (no NOPASSWD rules) | medium | 2 NOPASSWD rule(s) allowing every command |
| FAIL | USR-004 | No world-writable files in web roots | high | 2 world-writable path(s) in web roots |
| FAIL | USR-005 | setuid/setgid programs (review list) | medium | 1 setuid/setgid program(s) writable by non-root users |

### Web server and PHP

| Status | ID | Check | Severity | Result |
| --- | --- | --- | --- | --- |
| FAIL | WEB-001 | nginx hides its version (server\_tokens off) | low | server\_tokens is not set; nginx sends its version (default on) |
| FAIL | WEB-002 | nginx allows only TLS 1.2 and 1.3 | high | old protocols enabled: TLSv1, TLSv1.1 |
| FAIL | WEB-003 | PHP does not advertise itself (expose\_php = Off) | low | X-Powered-By header sent by PHP 8.1 fpm |
| FAIL | WEB-004 | PHP does not display errors to visitors | medium | errors are shown to visitors by PHP 8.1 fpm |

### Databases

| Status | ID | Check | Severity | Result |
| --- | --- | --- | --- | --- |
| FAIL | DB-001 | MariaDB/MySQL is not listening on all interfaces | high | the database accepts connections from the network |
| FAIL | DB-002 | Redis is bound to localhost with protected mode on | high | Redis is reachable from the network: bound to a public address, protected-mode is off, reachable without a password |

### Housekeeping

| Status | ID | Check | Severity | Result |
| --- | --- | --- | --- | --- |
| WARN | HK-001 | Swap is configured | low | no swap: memory spikes end in the out-of-memory killer |
| FAIL | HK-002 | Disks have free space | medium | / 95% space used |
| WARN | HK-003 | Filesystems have free inodes | medium | / 85% inodes used |
| FAIL | HK-004 | The clock is synchronised (NTP) | medium | time synchronisation is off |
| WARN | HK-005 | The systemd journal has a size limit | low | the journal uses 3.5 GiB |
| FAIL | HK-006 | Root cron jobs do not run writable scripts | high | 2 root cron path(s) can be modified by other users |

## Evidence

**SSH-001 Root login over SSH is disabled**

- permitrootlogin yes
- source: sshd -T (effective configuration)

**SSH-002 Password authentication is disabled**

- passwordauthentication yes
- source: sshd -T (effective configuration)

**SSH-003 Keyboard-interactive authentication is disabled**

- kbdinteractiveauthentication yes
- usepam yes
- source: sshd -T (effective configuration)

**SSH-004 Empty passwords are refused**

- permitemptypasswords yes
- source: sshd -T (effective configuration)

**SSH-005 No weak ciphers, MACs or key exchange algorithms**

- ciphers: aes128-cbc
- ciphers: 3des-cbc
- macs: hmac-md5
- kexalgorithms: diffie-hellman-group14-sha1
- kexalgorithms: diffie-hellman-group1-sha1
- source: sshd -T (effective configuration)
- legacy but not broken: macs: hmac-sha1

**SSH-006 MaxAuthTries is 4 or lower**

- maxauthtries 6
- source: sshd -T (effective configuration)

**SSH-007 X11 forwarding is disabled**

- x11forwarding yes
- source: sshd -T (effective configuration)

**SSH-008 LoginGraceTime is 60 seconds or less**

- logingracetime 120
- source: sshd -T (effective configuration)

**SSH-009 SSH logins are limited to named users or groups**

- port 22
- source: sshd -T (effective configuration)

**FW-001 A host firewall is active**

- ufw: inactive

**FW-003 Listening network services (inventory)**

- reachable from the network: 7
- tcp 0.0.0.0:3306
- tcp \*:6379
- tcp 0.0.0.0:22
- tcp 0.0.0.0:80
- tcp 0.0.0.0:443
- tcp \[::\]:80
- tcp \[::\]:22
- local only: 2
- udp 127.0.0.53%lo:53
- tcp 127.0.0.53%lo:53

**FW-004 Databases and internal services are not exposed**

- tcp 0.0.0.0:3306 - MySQL/MariaDB
- tcp \*:6379 - Redis

**UPD-002 No pending security updates**

- 3 upgradable, 2 from -security
- libssl3
- openssl
- package lists updated 40.0 day(s) ago

**UPD-003 No reboot is pending**

- /var/run/reboot-required exists
- package: libssl3
- package: linux-base

**UPD-004 Package lists are recent**

- last update 40.0 day(s) ago (limit 7)

**KRN-001 Network stack hardening (sysctl)**

- net.ipv4.conf.all.accept\_redirects = 1 (recommended 0: ignore ICMP redirects)
- net.ipv4.conf.all.send\_redirects = 1 (recommended 0: a server is not a router)
- net.ipv4.conf.default.send\_redirects = 1 (recommended 0: a server is not a router)
- net.ipv4.conf.all.rp\_filter = 0 (recommended 1: reverse path filtering against spoofing)
- net.ipv4.conf.all.log\_martians = 0 (recommended 1: log impossible addresses)

**KRN-002 Kernel and filesystem hardening (sysctl)**

- kernel.dmesg\_restrict = 0 (recommended 1: only root reads the kernel log)

**KRN-003 IP forwarding is off unless the host routes traffic**

- net.ipv4.ip\_forward = 1
- net.ipv6.conf.all.forwarding = 0

**USR-001 No account has an empty password**

- account: deploy

**USR-002 Only root has UID 0**

- UID 0: toor
- login accounts (UID &gt;= 1000): admin, deploy

**USR-003 sudo asks for a password (no NOPASSWD rules)**

- /etc/sudoers.d/90-cloud-init-users: ubuntu ALL=(ALL) NOPASSWD:ALL
- /etc/sudoers.d/deploy: deploy ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx
- files read: 4

**USR-004 No world-writable files in web roots**

- /var/www/html/index.php (0o666)
- /var/www/html/wp-content/uploads (0o777, directory)
- web roots: /var/www
- entries checked: 5

**USR-005 setuid/setgid programs (review list)**

- /usr/local/bin/helper (setuid, world-writable)
- setuid/setgid programs: 7, not on the Ubuntu default list: 2
- /usr/local/bin/helper (setuid)
- /usr/local/bin/oldtool (setgid)
- known: mount, passwd, su, sudo, ssh-keysign

**WEB-001 nginx hides its version (server\_tokens off)**

- source: /etc/nginx/nginx.conf and includes (3 files)

**WEB-002 nginx allows only TLS 1.2 and 1.3**

- /etc/nginx/nginx.conf \[http\]: ssl\_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3
- TLS listeners: yes
- source: /etc/nginx/nginx.conf and includes (3 files)

**WEB-003 PHP does not advertise itself (expose\_php = Off)**

- PHP 8.1 fpm: expose\_php = On (/etc/php/8.1/fpm/php.ini)

**WEB-004 PHP does not display errors to visitors**

- PHP 8.1 fpm: display\_errors = on (/etc/php/8.1/fpm/pool.d/www.conf)

**DB-001 MariaDB/MySQL is not listening on all interfaces**

- bind-address = 0.0.0.0 (/etc/mysql/mariadb.conf.d/50-server.cnf)
- listening: tcp 0.0.0.0:3306

**DB-002 Redis is bound to localhost with protected mode on**

- listening publicly: tcp \*:6379
- bind (unset: all interfaces)
- protected-mode no
- password/ACL configured: no

**HK-001 Swap is configured**

- RAM 1.0 GiB, swap 0.0 GiB

**HK-002 Disks have free space**

- /: 95% space used (/dev/vda1)
- /var/lib/mysql: 82% space used (/dev/vdb1)

**HK-003 Filesystems have free inodes**

- /: 85% inodes used (/dev/vda1)

**HK-004 The clock is synchronised (NTP)**

- NTP=no
- NTPSynchronized=no
- Timezone=Etc/UTC

**HK-005 The systemd journal has a size limit**

- SystemMaxUse not set (default: 10% of the filesystem, at most 4G)
- journal size: 3584 MiB

**HK-006 Root cron jobs do not run writable scripts**

- /var/www/html/cron.sh: owned by uid 33 - from /etc/cron.d/wordpress: /bin/sh /var/www/html/cron.sh &gt; /dev/null 2&gt;&1
- /etc/cron.daily/backup: world-writable - from /etc/cron.daily: /etc/cron.daily/backup
- root cron jobs: 6, paths checked: 5

