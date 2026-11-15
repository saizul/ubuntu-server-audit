# Contributing

Thanks for taking the time to improve ubuntu-server-audit. New checks, better
fix hints, support for more setups and documentation fixes are all welcome.

## Reporting a bug

Open an issue with:

- the Ubuntu release (`lsb_release -ds`) and the tool version
- whether you ran it as root or as a normal user
- the finding as JSON (`ubuntu-server-audit --only ID -f json`), with host names,
  user names and IP addresses replaced
- for a wrong result: the relevant command output or configuration snippet
  (for example the `sshd -T` lines, or the nginx block)

Never paste private keys, password hashes, tokens or full reports from a
production server into an issue.

## Development setup

You need Python 3.10 or newer. Development works on any OS; the tests do not
touch the real system.

```console
$ git clone https://github.com/saizul/ubuntu-server-audit.git
$ cd ubuntu-server-audit
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e ".[dev]"
```

Before every commit:

```console
$ ruff check .
$ ruff format --check .
$ pytest
```

All three must pass; CI runs them on Python 3.10 to 3.13.

## Adding a check

1. Pick the module in `src/ubuntu_server_audit/checks/` and the next free ID in
   that area (`SSH-010`, `HK-007`, ...). IDs are never reused or renumbered.
2. Register it with `@check(...)`: title (phrased as the good state), category,
   severity, a fix hint that someone can copy and run, `needs_root=True` if it
   cannot produce any result without root, and references to official docs.
3. Return an `Outcome` with evidence. Raise `NotApplicable` when the software is
   not installed and `NeedsRoot` when only root can answer; use
   `ctx.try_read`/`ctx.run` so permission errors become results, not crashes.
4. Set `partial=True` (with a reason) when part of the data was unreadable.
5. Add tests in `tests/test_checks.py` for pass, fail and the normal-user case,
   and update the hosts in `tests/hosts.py` if the end-to-end expectations
   change. Add the check to the table in the README.

## Guidelines

- **Read-only, always.** A check never writes, restarts, installs or changes
  anything, and never runs a shell. Commands are fixed argument lists.
- **Tests never use the real system.** Use `FakeRunner` and `FakeFS` from
  `tests/fakes.py`. Real command output in `tests/fixtures/` must be
  anonymised.
- **Sources for settings.** Option names and defaults come from Ubuntu manpages
  or upstream docs; link them in `references`.
- **No secrets in evidence.** Report that a password is set, never its value.
- **The JSON report is a contract.** Do not rename keys without a changelog
  entry and a schema bump.
- Add a line to the `Unreleased` section of `CHANGELOG.md` for anything a user
  would notice.

## Project layout

```text
src/ubuntu_server_audit/
    system.py         command runner, filesystem access, safe directory walk, host-root mode
    context.py        AuditContext: caching, NeedsRoot / NotApplicable, options
    registry.py       @check registration
    engine.py         runs checks, turns exceptions into findings, host info
    parsers.py        sshd, ss, ufw, nft, apt, passwd/shadow, sudoers, ini, redis, df, cron
    nginx_conf.py     minimal nginx configuration reader
    checks/           ssh, firewall, updates, kernel, accounts, web, database, housekeeping
    kernel_values.py  recommended sysctl values (--print-sysctl)
    scoring.py        score and grade
    report/           text, json, markdown, html
    cli.py            command-line interface
tests/                fakes, fake hosts, fixtures and the test suite
examples/             sample reports, sshd and sysctl drop-ins, systemd timer, library use
```

## Pull requests

- Keep each pull request focused on one change.
- Describe what changed and why, and how you tested it (on which Ubuntu
  release, if you also ran it on a real server).
- Do not bump the version number; that happens at release time.

By contributing you agree that your work is released under the MIT License.
