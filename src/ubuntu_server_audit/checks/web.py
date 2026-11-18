"""nginx and PHP settings."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from ubuntu_server_audit import nginx_conf
from ubuntu_server_audit.certs import Certificate, CertificateError, parse_pem
from ubuntu_server_audit.checks._common import cap
from ubuntu_server_audit.context import AuditContext, NeedsRoot, NotApplicable
from ubuntu_server_audit.model import Outcome, Severity, Status
from ubuntu_server_audit.parsers import parse_ini, php_bool
from ubuntu_server_audit.registry import check

NGINX_MAIN = "/etc/nginx/nginx.conf"
NGINX_DOC = "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"
NGINX_SSL_DOC = "https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols"
NGINX_CERT_DOC = "https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate"
CERTBOT_DOC = "https://eff-certbot.readthedocs.io/en/stable/using.html#automated-renewals"
PHP_DOC = "https://www.php.net/manual/en/ini.core.php"
OLD_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


@dataclass
class NginxInfo:
    config: nginx_conf.NginxConfig
    source: str
    partial: bool = False


def nginx_config(ctx: AuditContext) -> NginxInfo:
    def load() -> NginxInfo:
        if not (ctx.has_command("nginx") or ctx.exists("/usr/sbin/nginx")) and not ctx.exists(NGINX_MAIN):
            raise NotApplicable("nginx is not installed")
        result = ctx.run("nginx", "-T")
        if result.ok and "# configuration file" in result.stdout:
            return NginxInfo(nginx_conf.load_from_dump(result.stdout), "nginx -T")

        def read(path: str) -> str | None:
            r = ctx.try_read(path)
            return r.text if r.ok else None

        config = nginx_conf.load(NGINX_MAIN, read, ctx.glob)
        if not config.files:
            if not ctx.is_root:
                raise NeedsRoot(f"cannot read {NGINX_MAIN}")
            raise RuntimeError(result.describe())
        source = f"{NGINX_MAIN} and includes ({len(config.files)} files)"
        return NginxInfo(config, source, partial=bool(config.errors))

    return ctx.memo("nginx", load)


def _where(d: nginx_conf.Directive) -> str:
    ctx = "/".join(c for c in d.context if c) or "main"
    return f"{d.file} [{ctx}]: {d.name} {' '.join(d.args)}"


@check(
    "WEB-001",
    "nginx hides its version (server_tokens off)",
    category="web",
    severity=Severity.LOW,
    fix="Add 'server_tokens off;' to the http block of /etc/nginx/nginx.conf (Ubuntu ships it commented out), "
    "then 'sudo nginx -t && sudo systemctl reload nginx'.",
    references=(NGINX_DOC,),
)
def server_tokens(ctx: AuditContext) -> Outcome:
    info = nginx_config(ctx)
    directives = info.config.find("server_tokens")
    evidence = [*[_where(d) for d in directives], f"source: {info.source}", *info.config.errors[:5]]
    values = {(d.args[0] if d.args else "").lower() for d in directives}
    if not directives:
        return Outcome(
            Status.FAIL,
            "server_tokens is not set; nginx sends its version (default on)",
            evidence,
            partial=info.partial,
        )
    if values == {"off"}:
        return Outcome(Status.PASS, "nginx does not reveal its version", evidence, partial=info.partial)
    return Outcome(Status.FAIL, "server_tokens is on in at least one place", evidence, partial=info.partial)


@check(
    "WEB-002",
    "nginx allows only TLS 1.2 and 1.3",
    category="web",
    severity=Severity.HIGH,
    fix="Set 'ssl_protocols TLSv1.2 TLSv1.3;' in the http block (Ubuntu 22.04's nginx.conf still lists TLSv1 "
    "and TLSv1.1) and in any server block that overrides it.",
    references=(NGINX_SSL_DOC,),
)
def tls_protocols(ctx: AuditContext) -> Outcome:
    info = nginx_config(ctx)
    directives = info.config.find("ssl_protocols")
    tls = nginx_conf.listens_with_tls(info.config)
    evidence = [*[_where(d) for d in directives], f"TLS listeners: {'yes' if tls else 'no'}", f"source: {info.source}"]
    old = sorted({a for d in directives for a in d.args if a in OLD_PROTOCOLS})
    if old:
        return Outcome(Status.FAIL, f"old protocols enabled: {', '.join(old)}", evidence, partial=info.partial)
    if directives:
        return Outcome(Status.PASS, "only modern TLS versions are enabled", evidence, partial=info.partial)
    if tls:
        return Outcome(
            Status.WARN,
            "ssl_protocols is not set; the nginx and OpenSSL defaults apply",
            evidence,
            partial=info.partial,
        )
    raise NotApplicable("nginx has no TLS listeners")


def _cert_path(path: str) -> str:
    # nginx resolves relative paths against its prefix/conf directory.
    return path if path.startswith("/") else posixpath.join("/etc/nginx", path)


@check(
    "WEB-005",
    "TLS certificates used by nginx are not about to expire",
    category="web",
    severity=Severity.HIGH,
    fix="Renew the certificate before it expires. For Let's Encrypt run 'sudo certbot renew --dry-run' to find out "
    "why automatic renewal stopped, check 'systemctl list-timers' for certbot, then 'sudo nginx -t && sudo "
    "systemctl reload nginx' so nginx loads the new file.",
    references=(NGINX_CERT_DOC, CERTBOT_DOC),
)
def certificate_expiry(ctx: AuditContext) -> Outcome:
    info = nginx_config(ctx)
    paths: list[str] = []
    for d in info.config.find("ssl_certificate"):
        if d.args and d.args[0] not in paths:
            paths.append(d.args[0])
    if not paths:
        raise NotApplicable("nginx has no ssl_certificate directives")
    warn_days, fail_days = ctx.options.cert_warn_days, ctx.options.cert_fail_days
    evidence: list[str] = []
    checked: list[tuple[str, Certificate]] = []
    problems: list[str] = []
    unreadable: list[str] = []
    dynamic = [p for p in paths if "$" in p]
    for path in (p for p in paths if "$" not in p):
        full = _cert_path(path)
        read = ctx.try_read(full)
        if read.denied:
            unreadable.append(full)
            evidence.append(f"{full}: cannot read (permission denied)")
            continue
        if not read.ok:
            problems.append(f"{full} is {read.error}")
            evidence.append(f"{full}: {read.error}")
            continue
        try:
            chain = parse_pem(read.text or "")
        except CertificateError as exc:
            problems.append(f"{full} could not be parsed")
            evidence.append(f"{full}: {exc}")
            continue
        earliest = min(chain, key=lambda c: c.not_after)
        checked.append((full, earliest))
        leaf = chain[0]
        days = earliest.days_left(ctx.now)
        when = "expired" if days < 0 else f"{int(days)} days left"
        name = leaf.subject or "(no CN)"
        note = "" if earliest is leaf else f", chain certificate {earliest.subject or '(no CN)'} expires first"
        evidence.append(f"{full}: {name} valid until {earliest.not_after:%Y-%m-%d %H:%M} UTC ({when}{note})")
    evidence += [f"{p}: skipped (uses a variable)" for p in dynamic]
    evidence.append(f"source: {info.source}")
    partial = info.partial or bool(unreadable) or bool(dynamic)
    reason = "some certificate files could not be read" if unreadable else ""
    if not checked and not problems:
        if unreadable and not ctx.is_root:
            raise NeedsRoot(f"cannot read {unreadable[0]}")
        raise NotApplicable("every ssl_certificate path uses a variable")

    expired = [(p, c) for p, c in checked if c.days_left(ctx.now) < 0]
    failing = [(p, c) for p, c in checked if 0 <= c.days_left(ctx.now) < fail_days]
    warning = [(p, c) for p, c in checked if fail_days <= c.days_left(ctx.now) < warn_days]

    def names(items: list[tuple[str, Certificate]]) -> str:
        return ", ".join(c.subject or p for p, c in items)

    if expired or failing or problems:
        parts = []
        if expired:
            parts.append(f"expired: {names(expired)}")
        if failing:
            parts.append(f"expires within {fail_days} days: {names(failing)}")
        parts += problems
        return Outcome(Status.FAIL, "; ".join(parts), cap(evidence, ctx.options.max_listed), partial, reason)
    if warning:
        return Outcome(
            Status.WARN,
            f"expires within {warn_days} days: {names(warning)}",
            cap(evidence, ctx.options.max_listed),
            partial,
            reason,
        )
    soonest = min(c.days_left(ctx.now) for _p, c in checked)
    return Outcome(
        Status.PASS,
        f"{len(checked)} certificate file(s) valid for at least {int(soonest)} more days",
        cap(evidence, ctx.options.max_listed),
        partial,
        reason,
    )


@dataclass
class PhpSapi:
    version: str
    sapi: str
    files: list[str]
    settings: dict[str, tuple[str, str]]  # key -> (value, file)


def php_sapis(ctx: AuditContext) -> list[PhpSapi]:
    def load() -> list[PhpSapi]:
        sapis = []
        for ini in ctx.glob("/etc/php/*/*/php.ini"):
            parts = ini.split("/")
            version, sapi = parts[3], parts[4]
            if sapi == "cli":
                continue  # command-line PHP does not serve web requests
            files = [ini, *ctx.glob(posixpath.join(posixpath.dirname(ini), "conf.d", "*.ini"))]
            settings: dict[str, tuple[str, str]] = {}
            for path in files:
                read = ctx.try_read(path)
                if not read.ok:
                    continue
                # php.ini keys live in the [PHP] section; conf.d files often have none. Later files win.
                for section in parse_ini(read.text or "").values():
                    for key, value in section.items():
                        settings[key] = (value, path)
            if sapi == "fpm":
                for pool in ctx.glob(f"/etc/php/{version}/fpm/pool.d/*.conf"):
                    read = ctx.try_read(pool)
                    for line in (read.text or "").splitlines():
                        m = re.match(r"^\s*php_(?:admin_)?(?:flag|value)\[(\w+)\]\s*=\s*(\S+)", line)
                        if m:
                            settings[m.group(1).lower()] = (m.group(2), pool)
                    files.append(pool)
            sapis.append(PhpSapi(version, sapi, files, settings))
        if not sapis:
            raise NotApplicable("PHP for a web server (fpm, apache2, cgi) is not installed")
        return sapis

    return ctx.memo("php", load)


def _php_flag(ctx: AuditContext, key: str, *, want_on: bool, default: bool) -> tuple[list[str], list[str]]:
    bad, evidence = [], []
    for sapi in php_sapis(ctx):
        value, path = sapi.settings.get(key, ("", "(default)"))
        on = php_bool(value) if value else default
        evidence.append(f"PHP {sapi.version} {sapi.sapi}: {key} = {value or ('On' if default else 'Off')} ({path})")
        if on is None:
            continue
        if on != want_on:
            bad.append(f"PHP {sapi.version} {sapi.sapi}")
    return bad, evidence


@check(
    "WEB-003",
    "PHP does not advertise itself (expose_php = Off)",
    category="web",
    severity=Severity.LOW,
    fix="Set 'expose_php = Off' in /etc/php/VERSION/fpm/php.ini (or a conf.d override) and restart PHP-FPM.",
    references=(PHP_DOC,),
)
def expose_php(ctx: AuditContext) -> Outcome:
    bad, evidence = _php_flag(ctx, "expose_php", want_on=False, default=True)
    if bad:
        return Outcome(Status.FAIL, f"X-Powered-By header sent by {', '.join(bad)}", evidence)
    return Outcome(Status.PASS, "PHP version is not exposed", evidence)


@check(
    "WEB-004",
    "PHP does not display errors to visitors",
    category="web",
    severity=Severity.MEDIUM,
    fix="Set 'display_errors = Off' and 'log_errors = On' in php.ini and in pool files "
    "(php_admin_flag[display_errors] = off), then restart PHP-FPM.",
    references=(PHP_DOC,),
)
def display_errors(ctx: AuditContext) -> Outcome:
    # The built-in default is "1"; Ubuntu's php.ini (production) sets Off.
    bad, evidence = _php_flag(ctx, "display_errors", want_on=False, default=True)
    if bad:
        return Outcome(
            Status.FAIL, f"errors are shown to visitors by {', '.join(bad)}", cap(evidence, ctx.options.max_listed)
        )
    return Outcome(Status.PASS, "errors are not displayed", cap(evidence, ctx.options.max_listed))
