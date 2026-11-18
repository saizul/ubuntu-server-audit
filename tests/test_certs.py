"""Certificate parsing and the WEB-005 expiry check."""

from datetime import datetime, timedelta, timezone

import pytest

from fakes import make_cert_der, make_pem, ok
from hosts import NOW, hardened_host
from ubuntu_server_audit.certs import CertificateError, parse_der, parse_pem
from ubuntu_server_audit.engine import run_check
from ubuntu_server_audit.model import Status
from ubuntu_server_audit.registry import REGISTRY, all_checks

all_checks()

CERT = "/etc/letsencrypt/live/example.com/fullchain.pem"


def run(ctx):
    return run_check(REGISTRY["WEB-005"], ctx)


def nginx(*certs: str) -> str:
    lines = "".join(f"ssl_certificate {c};" for c in certs)
    return f"# configuration file /etc/nginx/nginx.conf:\nhttp {{ server {{ listen 443 ssl; {lines} }} }}\n"


def with_cert(days_left: float, *, path: str = CERT, cn: str = "example.com"):
    ctx = hardened_host()
    ctx.runner.set("nginx -T", ok(nginx(path)))
    pem = make_pem(make_cert_der(cn, NOW - timedelta(days=60), NOW + timedelta(days=days_left)))
    ctx.fs.add_file(path if path.startswith("/") else "/etc/nginx/" + path, pem)
    return ctx


def test_parse_der_reads_subject_and_validity():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 4, 1, 12, 30, tzinfo=timezone.utc)
    cert = parse_der(make_cert_der("shop.example.com", start, end))
    assert cert.subject == "shop.example.com"
    assert cert.not_before == start and cert.not_after == end
    assert cert.days_left(datetime(2026, 3, 31, 12, 30, tzinfo=timezone.utc)) == pytest.approx(1.0)


def test_parse_der_generalized_time_and_utc_pivot():
    cert = parse_der(make_cert_der("x", datetime(1999, 1, 1, tzinfo=timezone.utc),
                                   datetime(2051, 6, 1, tzinfo=timezone.utc)))
    assert cert.not_before.year == 1999 and cert.not_after.year == 2051


def test_parse_pem_bundle_keeps_order():
    pem = make_pem(make_cert_der("leaf", NOW, NOW + timedelta(days=90)),
                   make_cert_der("intermediate", NOW, NOW + timedelta(days=900)))
    assert [c.subject for c in parse_pem("junk before\n" + pem)] == ["leaf", "intermediate"]


@pytest.mark.parametrize("text", ["", "not a certificate",
                                  "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----"])
def test_parse_pem_rejects_garbage(text):
    with pytest.raises(CertificateError):
        parse_pem(text)


@pytest.mark.parametrize("der", [b"", b"\x02\x01\x00", b"\x30\x05\x30\x03\x02\x01", b"\x30\x82\xff\xff"])
def test_parse_der_rejects_garbage(der):
    with pytest.raises(CertificateError):
        parse_der(der)


def test_hardened_host_passes():
    finding = run(hardened_host())
    assert finding.status is Status.PASS
    assert "valid for at least 60 more days" in finding.summary
    assert any("example.com valid until" in e for e in finding.evidence)


@pytest.mark.parametrize(
    ("days", "status", "text"),
    [
        (90, Status.PASS, "at least 90 more days"),
        (20, Status.WARN, "expires within 30 days: example.com"),
        (3, Status.FAIL, "expires within 7 days: example.com"),
        (-2, Status.FAIL, "expired: example.com"),
    ],
)
def test_expiry_thresholds(days, status, text):
    finding = run(with_cert(days))
    assert finding.status is status
    assert text in finding.summary


def test_thresholds_come_from_options():
    ctx = with_cert(20)
    ctx.options.cert_warn_days = 14
    assert run(ctx).status is Status.PASS


def test_earliest_certificate_in_chain_decides():
    ctx = hardened_host()
    ctx.runner.set("nginx -T", ok(nginx(CERT)))
    ctx.fs.add_file(CERT, make_pem(make_cert_der("example.com", NOW, NOW + timedelta(days=80)),
                                   make_cert_der("Old CA", NOW, NOW + timedelta(days=5))))
    finding = run(ctx)
    assert finding.status is Status.FAIL
    assert "Old CA" in finding.summary
    assert any("chain certificate Old CA expires first" in e for e in finding.evidence)


def test_relative_path_resolves_against_etc_nginx():
    finding = run(with_cert(90, path="ssl/site.pem"))
    assert finding.status is Status.PASS
    assert any(e.startswith("/etc/nginx/ssl/site.pem:") for e in finding.evidence)


def test_missing_and_unparseable_files_fail():
    ctx = hardened_host()
    ctx.runner.set("nginx -T", ok(nginx("/etc/ssl/missing.pem", "/etc/ssl/bad.pem")))
    ctx.fs.add_file("/etc/ssl/bad.pem", "hello")
    finding = run(ctx)
    assert finding.status is Status.FAIL
    assert "/etc/ssl/missing.pem is missing" in finding.summary
    assert "/etc/ssl/bad.pem could not be parsed" in finding.summary


def test_unreadable_certificate_needs_root_for_normal_user():
    ctx = with_cert(90)
    ctx.fs.deny("/etc/letsencrypt")
    ctx.is_root = False
    assert run(ctx).status is Status.SKIPPED


def test_partially_readable_is_marked_partial():
    ctx = hardened_host()
    ctx.runner.set("nginx -T", ok(nginx(CERT, "/etc/ssl/private/other.pem")))
    ctx.fs.add_file("/etc/ssl/private/other.pem", "x")
    ctx.fs.deny("/etc/ssl/private")
    finding = run(ctx)
    assert finding.status is Status.PASS and finding.partial


def test_variable_paths_are_skipped_and_no_certificates_is_na():
    ctx = hardened_host()
    ctx.runner.set("nginx -T", ok(nginx("/etc/ssl/$ssl_server_name.pem")))
    assert run(ctx).status is Status.NOT_APPLICABLE
    ctx = hardened_host()
    ctx.runner.set("nginx -T", ok(nginx()))
    assert run(ctx).status is Status.NOT_APPLICABLE
