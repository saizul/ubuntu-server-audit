# Security policy

## Supported versions

Security fixes are made for the latest release. Please upgrade before reporting.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting instead: open the **Security** tab of
https://github.com/saizul/ubuntu-server-audit and choose **Report a
vulnerability**.

Include what you found, how to reproduce it and what an attacker could do with
it. You should get an answer within a week. Once a fix is released you will be
credited in the changelog unless you prefer otherwise.

Do not include audit reports from real servers, password hashes, keys or
tokens. Use made-up host names and addresses.

## Scope

This tool is usually run as root, so these are in scope:

- anything that makes the audit change the system (writes, restarts, package
  operations) or run a command other than the fixed, read-only ones
- command or path injection through file contents, file names or command output
- secrets copied into reports or logs (password hashes, `requirepass` values,
  keys)
- injection into reports: HTML (cross-site scripting), Markdown, terminal
  escape sequences in text output
- crashes, hangs or excessive resource use caused by unusual files (huge
  configs, deep or looping directory trees, symlink tricks)
- the `--host-root` container mode reaching outside the mounted host root

Out of scope: false negatives in the checks themselves (please open a normal
issue), and the security of the software being audited.
