"""End-to-end audits of the fake hosts."""

import pytest

from hosts import hardened_host, neglected_host
from ubuntu_server_audit.engine import run_audit
from ubuntu_server_audit.model import Status
from ubuntu_server_audit.registry import all_checks
from ubuntu_server_audit.scoring import compute


def statuses(ctx):
    report = run_audit(ctx)
    return {f.id: f for f in report.findings}, report


def test_every_check_has_metadata():
    checks = all_checks()
    ids = [c.spec.id for c in checks]
    assert len(ids) == len(set(ids)) >= 35
    for c in checks:
        assert c.spec.fix and c.spec.title and c.spec.severity
        assert c.spec.id.split("-")[0] in ("SSH", "FW", "UPD", "KRN", "USR", "WEB", "DB", "HK")


def test_hardened_host_as_root_scores_100():
    found, report = statuses(hardened_host())
    problems = {
        i: (f.status.value, f.summary)
        for i, f in found.items()
        if f.status in (Status.FAIL, Status.WARN, Status.ERROR, Status.SKIPPED)
    }
    assert problems == {}
    score = compute(report.findings)
    assert score.score == 100 and score.grade == "A"
    assert found["SSH-009"].status is Status.INFO
    assert found["FW-003"].status is Status.INFO
    assert report.host.hostname == "web1" and report.host.os_version == "24.04"


EXPECTED_NEGLECTED = {
    "SSH-001": Status.FAIL,
    "SSH-002": Status.FAIL,
    "SSH-003": Status.FAIL,
    "SSH-004": Status.FAIL,
    "SSH-005": Status.FAIL,
    "SSH-006": Status.WARN,
    "SSH-007": Status.WARN,
    "SSH-008": Status.WARN,
    "FW-001": Status.FAIL,
    "FW-002": Status.NOT_APPLICABLE,
    "FW-004": Status.FAIL,
    "FW-005": Status.FAIL,
    "UPD-001": Status.FAIL,
    "UPD-002": Status.FAIL,
    "UPD-003": Status.FAIL,
    "UPD-004": Status.WARN,
    "UPD-005": Status.PASS,
    "KRN-001": Status.FAIL,
    "KRN-002": Status.WARN,
    "KRN-003": Status.WARN,
    "USR-001": Status.FAIL,
    "USR-002": Status.FAIL,
    "USR-003": Status.FAIL,
    "USR-004": Status.FAIL,
    "USR-005": Status.FAIL,
    "WEB-001": Status.FAIL,
    "WEB-002": Status.FAIL,
    "WEB-003": Status.FAIL,
    "WEB-004": Status.FAIL,
    "DB-001": Status.FAIL,
    "DB-002": Status.FAIL,
    "HK-001": Status.WARN,
    "HK-002": Status.FAIL,
    "HK-003": Status.WARN,
    "HK-004": Status.FAIL,
    "HK-005": Status.WARN,
    "HK-006": Status.FAIL,
}


def test_neglected_host_as_root():
    found, report = statuses(neglected_host())
    got = {i: found[i].status for i in EXPECTED_NEGLECTED}
    assert got == EXPECTED_NEGLECTED
    score = compute(report.findings)
    assert score.score < 25 and score.grade == "F"
    assert not report.by_status(Status.ERROR)


def test_neglected_host_evidence():
    found, _ = statuses(neglected_host())
    assert "ciphers: aes128-cbc" in found["SSH-005"].evidence
    assert "macs: hmac-md5" in found["SSH-005"].evidence
    assert any("diffie-hellman-group1-sha1" in e for e in found["SSH-005"].evidence)
    assert any("legacy" in e and "hmac-sha1" in e for e in found["SSH-005"].evidence)
    assert any("3306" in e for e in found["FW-004"].evidence)
    assert any("6379" in e for e in found["FW-004"].evidence)
    assert "account: deploy" in found["USR-001"].evidence
    assert any("toor" in e for e in found["USR-002"].evidence)
    nopasswd = " ".join(found["USR-003"].evidence)
    assert "90-cloud-init-users" in nopasswd and "old.bak" not in nopasswd
    ww = " ".join(found["USR-004"].evidence)
    assert "/var/www/html/index.php" in ww and "uploads" in ww
    suid = " ".join(found["USR-005"].evidence)
    assert "/usr/local/bin/helper" in suid and "world-writable" in suid
    assert "TLSv1, TLSv1.1" in found["WEB-002"].summary
    assert "server_tokens is not set" in found["WEB-001"].summary
    assert "php_flag[display_errors]" not in found["WEB-004"].summary
    assert any("pool.d/www.conf" in e for e in found["WEB-004"].evidence)
    assert "protected-mode is off" in found["DB-002"].summary
    assert any("password/ACL configured: no" in e for e in found["DB-002"].evidence)
    cron = " ".join(found["HK-006"].evidence)
    assert "/var/www/html/cron.sh" in cron and "/etc/cron.daily/backup" in cron
    assert "wp-cron.php" not in cron  # www-data's job, not root's
    assert any("package: linux-base" in e for e in found["UPD-003"].evidence)
    assert "2 security update(s)" in found["UPD-002"].summary
    assert "95%" in found["HK-002"].summary


def test_redis_secret_never_in_evidence():
    found, _ = statuses(hardened_host())
    text = " ".join(found["DB-002"].evidence)
    assert "REDIS_PASSWORD" not in text and "password/ACL configured: yes" in text


@pytest.mark.parametrize("host", [hardened_host, neglected_host])
def test_normal_user_never_crashes_and_marks_skips(host):
    found, report = statuses(host(root=False))
    assert not report.by_status(Status.ERROR), [(f.id, f.summary) for f in report.by_status(Status.ERROR)]
    for check_id in ("FW-001", "FW-002", "USR-001", "USR-003"):
        assert found[check_id].status is Status.SKIPPED
        assert found[check_id].skipped_reason == "needs root"
        assert found[check_id].status_text == "skipped (needs root)"
    assert found["FW-005"].status in (Status.SKIPPED, Status.FAIL)
    # sshd -T is refused, so SSH checks fall back to the files and say so
    assert found["SSH-001"].partial
    assert "configuration files" in " ".join(found["SSH-001"].evidence)
    assert compute(report.findings).skipped_needs_root >= 4


def test_normal_user_fallbacks_on_hardened_host():
    found, _ = statuses(hardened_host(root=False))
    # sshd_config: KbdInteractiveAuthentication no, X11Forwarding yes, Match block ignored
    assert found["SSH-003"].status is Status.PASS
    assert found["SSH-007"].status is Status.WARN
    assert any("Match blocks" in e for e in found["SSH-001"].evidence)
    assert found["FW-005"].status is Status.SKIPPED  # active, jails need root
    assert found["DB-002"].partial and found["DB-002"].status is Status.PASS
    assert found["HK-006"].partial
    # nginx -T fails for a normal user; nginx.conf is read directly
    assert found["WEB-001"].status is Status.PASS
    assert "nginx.conf and includes" in " ".join(found["WEB-001"].evidence)


def test_normal_user_neglected_host_still_finds_public_problems():
    found, _ = statuses(neglected_host(root=False))
    assert found["FW-004"].status is Status.FAIL and found["FW-004"].partial
    assert found["DB-002"].status is Status.FAIL and found["DB-002"].partial
    assert found["USR-004"].status is Status.FAIL
    assert found["WEB-002"].status is Status.FAIL
