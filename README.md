# ubuntu-server-audit

[![CI](https://github.com/saizul/ubuntu-server-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/ubuntu-server-audit/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A read-only security and best-practice audit for Ubuntu 22.04 and 24.04 web servers. It checks the things that
actually go wrong on a VPS running nginx, PHP-FPM, MariaDB and Redis: SSH settings, the firewall and open ports,
fail2ban, automatic security updates, pending updates and reboots, kernel network hardening, accounts and sudo
rules, world-writable files in web roots, setuid programs, nginx and PHP leaks, databases listening on public
addresses, disk and inode usage, time sync, journal size and root cron jobs that run scripts other users can edit.

Every check has an ID, a severity, the evidence it found and a concrete fix. The result is a score from 0 to 100,
as text, JSON, Markdown or a self-contained HTML page.

It never changes anything. It runs a fixed list of read-only commands (`sshd -T`, `ufw status verbose`,
`ss -tuln`, `apt-config dump`, `nginx -T`, ...) and reads configuration files. Run it with `sudo` for full
results; as a normal user, checks that need root are clearly marked **skipped (needs root)**, and permission
errors never crash it.

```console
$ ubuntu-server-audit
ubuntu-server-audit 0.1.0  web1  Ubuntu 22.04.5 LTS  kernel 6.8.0-48-generic  uptime 10d 0h
running as deploy (not root: some checks are skipped)

Firewall and network
  [SKIP]  FW-001   A host firewall is active - skipped (needs root)
  [SKIP]  FW-002   Incoming traffic is denied by default - skipped (needs root)
  [INFO]  FW-003   Listening network services (inventory)
           7 public and 2 local listening sockets
  [FAIL]  FW-004   Databases and internal services are not exposed (partial)
           2 internal service(s) listen on public addresses
             - tcp 0.0.0.0:3306 - MySQL/MariaDB
             - tcp *:6379 - Redis
...
Housekeeping
  [FAIL]  HK-006   Root cron jobs do not run writable scripts (partial)
           2 root cron path(s) can be modified by other users
             - /var/www/html/cron.sh: owned by uid 33 - from /etc/cron.d/wordpress: /bin/sh /var/www/html/cron.sh
             - /etc/cron.daily/backup: world-writable - from /etc/cron.daily: /etc/cron.daily/backup
             - unreadable: /var/spool/cron/crontabs/root

Fix first:
  CRITICAL USR-002  Give the extra account a normal UID (usermod -u) or delete it; use sudo for administrators.
  HIGH     DB-001   Set 'bind-address = 127.0.0.1' in /etc/mysql/mariadb.conf.d/50-server.cnf ...
  ...

Score 24/100 (grade F) from 33 scored checks; 19 fail, 10 warn, 4 pass, 4 skipped, 0 n/a, 0 error
4 check(s) skipped (needs root): run with sudo for full results.
```

(Output from the neglected test host in `tests/hosts.py`; see [`examples/sample-report.md`](examples/sample-report.md)
for a full root run.)

## Contents

- [Features](#features)
- [Installation](#installation)
- [Docker image](#docker-image)
- [Usage](#usage)
- [Checks](#checks)
- [Root and normal users](#root-and-normal-users)
- [Score](#score)
- [Configuration](#configuration)
- [Reports](#reports)
- [Examples](#examples)
- [Testing](#testing)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Features

- **39 checks** in eight areas: SSH, firewall and network, updates, kernel, users and files, web server and PHP,
  databases, housekeeping. `--list-checks` prints them.
- **Effective SSH configuration** from `sshd -T` (what sshd really uses after `Include` files), with a fallback
  to reading `sshd_config` and `sshd_config.d/*.conf` for normal users, using sshd's "first value wins" rule.
- **Evidence and fixes**: each finding lists what was seen (the setting and the file it came from, the listening
  socket, the cron line) and how to fix it, with links to the Ubuntu manpages and docs where relevant.
- **Partial results are labelled**: a check that could only read part of the data says `(partial)` and why.
- **Never crashes**: missing programs, permission errors, timeouts and unexpected output become `skipped`,
  `n/a` or `error` findings; the other checks still run.
- **Reports**: coloured text for the terminal, JSON (schema 1) for scripts, Markdown for tickets and wikis, and
  a single HTML file with no scripts or external resources.
- **CI and cron friendly**: `--fail-under SCORE` and `--fail-on SEVERITY` exit codes, `--only` / `--skip` by ID
  or category, a systemd timer example.
- **No dependencies** beyond the Python standard library. Python 3.10+ (Ubuntu 22.04 ships 3.10, 24.04 ships 3.12).
- `--print-sysctl` writes a `/etc/sysctl.d/60-hardening.conf` that satisfies the kernel checks.

## Installation

On the server:

```bash
sudo apt install pipx
pipx install "git+https://github.com/saizul/ubuntu-server-audit"
sudo ~/.local/bin/ubuntu-server-audit
```

or into a virtual environment (works on both releases without touching the system Python):

```bash
python3 -m venv ~/.venvs/audit
~/.venvs/audit/bin/pip install "git+https://github.com/saizul/ubuntu-server-audit"
sudo ~/.venvs/audit/bin/ubuntu-server-audit
```

For the systemd timer in `examples/systemd/`, install it system-wide for root, for example with
`sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install "git+https://github.com/saizul/ubuntu-server-audit"`.

The command is `ubuntu-server-audit` (also `python3 -m ubuntu_server_audit`).

## Docker image

A multi-arch image (linux/amd64, linux/arm64) is published to GitHub Packages:

```bash
docker pull ghcr.io/saizul/ubuntu-server-audit:latest
```

Inside a container the tool sees the container, not the server. To audit the host, mount its root filesystem
read-only, share the host's network and process namespaces, run as root in the container and pass
`--host-root`; commands then run as `chroot /host COMMAND`, so the host's own `sshd`, `ufw` and `nginx` are used:

```bash
docker run --rm --user 0 --net host --pid host -v /:/host:ro -v "$PWD:/work" \
  ghcr.io/saizul/ubuntu-server-audit:latest --host-root /host -f all -o /work/audit
```

This mode is meant for hosts where you prefer not to install Python packages. Installing with pipx is simpler and
sees exactly what the server sees. Release images are also tagged with the version
(`ghcr.io/saizul/ubuntu-server-audit:0.1.0`) and every build with its commit SHA. Without `--user 0` the
container runs as an unprivileged user (uid 10001).

## Usage

```text
ubuntu-server-audit [options]

  -f, --format FMT        text, json, markdown (md), html or all (default text); several formats need -o
  -o, --output DIR        write report files into DIR (server-audit.txt/.json/.md/.html)
  --basename NAME         report file name prefix (default server-audit)
  --only IDS              run only these IDs or categories, comma-separated, wildcards allowed (SSH-*, web)
  --skip IDS              skip these IDs or categories
  --web-root PATH         web root to scan, repeatable (default /var/www, /srv/www, /srv/http,
                          /usr/share/nginx/html plus nginx 'root' directives)
  --max-files N           stop each file walk after N entries (default 200000)
  --fail-under SCORE      exit 1 when the score is below SCORE
  --fail-on SEVERITY      exit 1 when a check of SEVERITY or higher fails (critical, high, medium, low)
  --require-root          exit 2 unless running as root
  --host-root DIR         audit a host filesystem mounted at DIR (see Docker image)
  --list-checks           list the checks
  --print-sysctl          print a sysctl hardening file
  --color auto|always|never, -v/--verbose (evidence for every check), -q/--quiet, --debug
```

Exit codes: **0** done (and thresholds met), **1** `--fail-under` or `--fail-on` threshold reached,
**2** usage error.

```bash
# Everything, as root, in the terminal
sudo ubuntu-server-audit

# All report formats into a directory
sudo ubuntu-server-audit -f all -o /root/audit-$(date +%F)

# Only SSH and the firewall, as JSON
sudo ubuntu-server-audit --only ssh,firewall -f json | jq '.findings[] | select(.status=="fail")'

# A deploy pipeline step: fail on any critical or high finding
sudo ubuntu-server-audit -q --fail-on high || echo "fix the server before deploying"

# Several sites in custom locations
sudo ubuntu-server-audit --only USR-004 --web-root /srv/sites --web-root /opt/app/public -v
```

## Checks

| ID | Severity | Check | Needs root |
| --- | --- | --- | --- |
| SSH-001 | high | Root login over SSH is disabled (`PermitRootLogin no`; key-only root login is a warning) | effective config |
| SSH-002 | high | Password authentication is disabled | effective config |
| SSH-003 | medium | Keyboard-interactive authentication is disabled (with `UsePAM yes` it accepts passwords) | effective config |
| SSH-004 | critical | Empty passwords are refused | effective config |
| SSH-005 | medium | No CBC/arcfour ciphers, MD5/SHA1-96 MACs or SHA1 key exchanges | effective config |
| SSH-006 | low | `MaxAuthTries` 4 or lower | effective config |
| SSH-007 | low | `X11Forwarding no` | effective config |
| SSH-008 | low | `LoginGraceTime` 60 seconds or less | effective config |
| SSH-009 | info | `AllowUsers` / `AllowGroups` in use, and the SSH port | |
| FW-001 | high | UFW is active, or nftables filters the input hook | yes |
| FW-002 | medium | Default incoming policy is deny/drop | yes |
| FW-003 | info | Inventory of listening sockets, public and local (`ss -tuln`) | process names |
| FW-004 | high | MySQL, PostgreSQL, Redis, Memcached, MongoDB, Elasticsearch, Docker API, PHP-FPM and others do not listen on public addresses (warning if UFW blocks them) | firewall rules |
| FW-005 | medium | fail2ban is installed, running and has an sshd jail | jail list |
| UPD-001 | high | `unattended-upgrades` installed, `APT::Periodic::Update-Package-Lists` and `APT::Periodic::Unattended-Upgrade` are "1", `apt-daily-upgrade.timer` enabled | |
| UPD-002 | high | No pending security updates (`/usr/lib/update-notifier/apt-check`, or `apt list --upgradable`) | |
| UPD-003 | medium | No `/var/run/reboot-required` (lists the packages from `reboot-required.pkgs`) | |
| UPD-004 | low | APT package lists updated in the last 7 days | |
| UPD-005 | high | The release is a supported LTS (22.04 and 24.04 are tested) | |
| KRN-001 | medium | Network sysctls: SYN cookies, no ICMP redirects, no source routing, reverse path filter, martian logging, ... | |
| KRN-002 | low | Kernel sysctls: ASLR, `kptr_restrict`, `dmesg_restrict`, ptrace scope, protected links/FIFOs/files, `suid_dumpable` | |
| KRN-003 | low | IP forwarding is off unless Docker, LXD, Incus, Podman or WireGuard is present | |
| USR-001 | critical | No account in `/etc/shadow` has an empty password field | yes |
| USR-002 | critical | Only `root` has UID 0 (also lists login accounts) | |
| USR-003 | medium | No `NOPASSWD` rules in `/etc/sudoers` and its include directories (fail if `NOPASSWD: ALL`) | yes |
| USR-004 | high | No world-writable files or directories (without the sticky bit) in web roots | unreadable dirs |
| USR-005 | medium | setuid/setgid programs outside Ubuntu's default list (review), and none writable by non-root (fail) | unreadable dirs |
| WEB-001 | low | nginx `server_tokens off` (unset means on) | `nginx -T` |
| WEB-002 | high | nginx `ssl_protocols` has no SSLv3, TLSv1 or TLSv1.1 (warning when unset) | `nginx -T` |
| WEB-003 | low | PHP `expose_php = Off` for FPM, Apache and CGI (CLI is ignored) | |
| WEB-004 | medium | PHP `display_errors` off, including `php_flag`/`php_admin_flag` in FPM pools | |
| DB-001 | high | MariaDB/MySQL is not listening on a public address (`ss` plus `bind-address` from `/etc/mysql`) | |
| DB-002 | high | Redis: no public listener, `bind` set to loopback, `protected-mode yes`, password or ACL present | `redis.conf` |
| HK-001 | low | Swap is configured | |
| HK-002 | medium | Disk usage below 80% (warn) and 90% (fail) | |
| HK-003 | medium | Inode usage below 80% / 90% | |
| HK-004 | medium | Clock synchronised (`timedatectl show`: `NTP`, `NTPSynchronized`) | |
| HK-005 | low | Journal below 2 GiB, `SystemMaxUse` not excessive | full usage |
| HK-006 | high | Every path run by root's cron jobs (`/etc/crontab`, `/etc/cron.d`, root's crontab, `/etc/cron.{hourly,daily,weekly,monthly}`) and its directory is owned and writable by root only | root's crontab |

"Effective config": as root, `sshd -T` is used. As a normal user `sshd -T` cannot read the host keys, so the files
are read instead and the result is marked partial (`Match` blocks are not evaluated in that mode).

The SSH option names and defaults follow [sshd_config(5) for Ubuntu 24.04](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html)
(`ChallengeResponseAuthentication` is treated as the deprecated alias of `KbdInteractiveAuthentication`), and the
unattended-upgrades paths and keys follow the [Ubuntu Server automatic updates guide](https://ubuntu.com/server/docs/how-to/software/automatic-updates/).

## Root and normal users

| As root | As a normal user |
| --- | --- |
| all 39 checks | FW-001, FW-002, USR-001 and USR-003 are **skipped (needs root)**; FW-005 is skipped if fail2ban is running |
| `sshd -T`, `nginx -T`, `ufw status`, `nft list ruleset`, `fail2ban-client status` | config files are read instead where possible; results marked `(partial)` |
| process names in the socket list | addresses and ports only |
| `redis.conf`, root's crontab, all of `/var/www` | readable parts only, marked `(partial)` |

The score only counts checks that ran, so a normal-user score is not comparable with a root score; the summary says
how many checks were skipped.

## Score

`score = 100 x (sum of weight x credit) / (sum of weight)` over checks with a pass, warn or fail result.
Weights: critical 10, high 6, medium 3, low 1, info 0. A pass earns full credit, a warning half, a failure none.
Skipped, not applicable, informational and errored checks do not count. Grades: A 90+, B 80+, C 70+, D 60+, F
below 60.

## Configuration

There is no configuration file: everything is a command-line option, so a cron job or systemd unit documents
its own settings. Thresholds that can be tuned from Python (`AuditOptions`): disk warn/fail percentages, journal
size limit, APT list age, file walk limit, number of listed items and the command timeout.

```python
from ubuntu_server_audit import AuditContext, AuditOptions, run_audit
from ubuntu_server_audit.system import RealFileSystem, SubprocessRunner

options = AuditOptions(disk_warn_percent=70, disk_fail_percent=85, web_roots=["/srv/sites"])
report = run_audit(AuditContext(SubprocessRunner(), RealFileSystem(), is_root=True, options=options))
```

## Reports

| Format | Contents |
| --- | --- |
| `text` | grouped by area, status labels, evidence for failures and warnings (`-v` for all), a "Fix first" list and the score |
| `json` | `host`, `score` (score, grade, scored and applicable checks, skipped-needs-root count), `counts`, and every finding with `id`, `title`, `category`, `severity`, `status`, `status_text`, `summary`, `evidence`, `fix`, `references`, `needs_root`, `partial`, `partial_reason`, `skipped_reason` |
| `markdown` | score, a "Fix first" table, every check by area and the evidence |
| `html` | the same as one offline page with a score ring, works in dark mode |

Status values: `pass`, `warn`, `fail`, `info`, `skipped`, `n/a` (the software is not installed) and `error`
(the check could not complete; the message says why).

## Examples

- [`examples/sample-report.md`](examples/sample-report.md) and [`examples/sample-report.json`](examples/sample-report.json):
  reports for the neglected test host
- [`examples/sshd-50-hardening.conf`](examples/sshd-50-hardening.conf): an `sshd_config.d` drop-in that passes
  the SSH checks
- [`examples/60-hardening.conf`](examples/60-hardening.conf): the output of `--print-sysctl`
- [`examples/systemd/`](examples/systemd/): a weekly service and timer that keep reports in
  `/var/lib/ubuntu-server-audit/`
- [`examples/library_usage.py`](examples/library_usage.py): selected checks from Python

## Testing

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

The tests never touch the real system. `tests/fakes.py` has a fake command runner (canned output for
`sshd -T`, `ufw`, `ss`, `apt`, `nginx -T`, ...) and an in-memory filesystem with modes, owners, symlinks and
unreadable paths. `tests/hosts.py` builds a hardened Ubuntu 24.04 host (score 100) and a neglected 22.04 host,
each as root and as a normal user. CI also runs the tool on the GitHub runner as an unprivileged user, with a
web root in `/tmp`, and checks that root-only checks are reported as skipped; it does not read `/home` or other
root-only paths.

## Security notes

- The audit is read-only: it runs a fixed list of commands without a shell (`LC_ALL=C`, stdin closed, a timeout
  each), reads files, and writes nothing except the reports you ask for with `-o`.
- Reports contain sensitive details about the server (open ports, user names, paths, weak settings). Keep them
  private; write them to a directory only root can read (the systemd example uses mode 0700).
- Secrets are not copied into reports: for Redis only the presence of `requirepass`/ACL users is reported, and
  password hashes from `/etc/shadow` are never included (only the names of accounts with an empty password).
- Text output strips control characters, and HTML and Markdown output escape everything taken from the system.
- Running as root is needed for full results. If you prefer, review the code first: the commands are in
  `src/ubuntu_server_audit/checks/`.

## Limitations

- Ubuntu 22.04 and 24.04 are tested; other Debian-based systems mostly work, other distributions do not.
- `sshd -T` shows the configuration for a connection without `Match` conditions; per-user or per-address `Match`
  blocks are not evaluated.
- The nginx reader is minimal: it follows `include` and block structure but does not evaluate variables, `if` or
  `map`. Apache is not checked.
- TLS checks look at the nginx configuration, not at what a client negotiates; use an external TLS scanner too.
- The firewall check reads UFW and the nftables input hook; rules from cloud provider firewalls or security groups
  are invisible from inside the server, so FW-001 may fail on hosts that are filtered upstream.
- `FW-004` with UFW active only knows simple port rules; complex rules may hide or allow a port in ways it does
  not see.
- The setuid list is a review aid: a program missing from Ubuntu's default list is not necessarily bad.
- In `--host-root` mode, absolute symlinks on the host resolve inside the container.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security problems: see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Saizul Amin.
