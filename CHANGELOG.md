# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-15

### Added

- 39 read-only checks for Ubuntu 22.04/24.04 web servers, each with an ID, severity, evidence and a fix hint:
  - SSH (SSH-001 to SSH-009): effective configuration from `sshd -T`, with a file-based fallback for normal users
    (`Include` files, first value wins): root login, password and keyboard-interactive authentication, empty
    passwords, weak ciphers/MACs/key exchanges, `MaxAuthTries`, X11 forwarding, `LoginGraceTime`, allow lists.
  - Firewall and network (FW-001 to FW-005): UFW or nftables, default incoming policy, listening sockets from
    `ss`, internal services on public addresses, fail2ban and its sshd jail.
  - Updates (UPD-001 to UPD-005): unattended-upgrades and the APT periodic settings, pending security updates,
    reboot-required, package list age, supported release.
  - Kernel (KRN-001 to KRN-003): network and kernel sysctl hardening, IP forwarding.
  - Users and files (USR-001 to USR-005): empty passwords, extra UID 0 accounts, sudo `NOPASSWD` rules,
    world-writable files in web roots (including nginx `root` directives), setuid/setgid review list.
  - Web and databases (WEB-001 to WEB-004, DB-001, DB-002): nginx `server_tokens` and `ssl_protocols`, PHP
    `expose_php` and `display_errors` (php.ini, conf.d and FPM pools), MariaDB/MySQL and Redis exposure.
  - Housekeeping (HK-001 to HK-006): swap, disk and inode usage, time sync, journal size, root cron jobs that run
    paths other users can modify.
- Root and normal-user modes: root-only checks are reported as "skipped (needs root)", partial results are
  labelled, and permission errors, missing programs and timeouts never stop the audit.
- Severity-weighted score (0-100) and grade.
- Text, JSON (schema 1), Markdown and self-contained HTML reports.
- `--only`/`--skip` by ID or category, `--web-root`, `--fail-under`, `--fail-on`, `--require-root`,
  `--list-checks`, `--print-sysctl`, `--host-root` for auditing a host from a container.
- Docker image published to `ghcr.io/saizul/ubuntu-server-audit`, systemd timer example.

[Unreleased]: https://github.com/saizul/ubuntu-server-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/ubuntu-server-audit/releases/tag/v0.1.0
