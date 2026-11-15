import os
import stat
import sys

import pytest

from fakes import FakeFS, FakeRunner
from hosts import NOW, hardened_host
from ubuntu_server_audit.context import AuditContext, AuditOptions, NeedsRoot, NotApplicable
from ubuntu_server_audit.engine import run_audit, run_check, select_checks
from ubuntu_server_audit.model import CheckSpec, Finding, Outcome, Severity, Status
from ubuntu_server_audit.registry import Check, all_checks, check
from ubuntu_server_audit.scoring import compute, worst_failure
from ubuntu_server_audit.system import RealFileSystem, SubprocessRunner, WalkStats, walk


def spec(**kw):
    base = {"id": "T-001", "title": "t", "category": "ssh", "severity": Severity.HIGH, "fix": "f"}
    base.update(kw)
    return CheckSpec(**base)


def ctx(root=True):
    return AuditContext(FakeRunner(), FakeFS(), root, AuditOptions(), now=NOW)


@pytest.mark.parametrize(
    ("exc", "root", "status", "reason"),
    [
        (NeedsRoot("x"), False, Status.SKIPPED, "needs root"),
        (NotApplicable("not installed"), True, Status.NOT_APPLICABLE, ""),
        (PermissionError("denied"), False, Status.SKIPPED, "needs root"),
        (PermissionError("denied"), True, Status.ERROR, ""),
        (ZeroDivisionError("bug"), True, Status.ERROR, ""),
        (OSError(5, "I/O error"), True, Status.ERROR, ""),
    ],
)
def test_exceptions_become_findings(exc, root, status, reason):
    def boom(_ctx):
        raise exc

    finding = run_check(Check(spec(), boom), ctx(root))
    assert finding.status is status
    assert finding.skipped_reason == reason


def test_needs_root_skips_without_running():
    called = []

    def fn(_ctx):
        called.append(1)
        return Outcome(Status.PASS, "ok")

    finding = run_check(Check(spec(needs_root=True), fn), ctx(root=False))
    assert finding.status is Status.SKIPPED and finding.status_text == "skipped (needs root)" and not called
    assert run_check(Check(spec(needs_root=True), fn), ctx(root=True)).status is Status.PASS


def test_outcome_fix_override_and_partial():
    finding = run_check(Check(spec(), lambda _c: Outcome(Status.FAIL, "s", ["e"], True, "why", fix="custom")), ctx())
    assert finding.fix == "custom" and finding.partial and finding.status_text == "fail (partial)"


def test_register_rejects_duplicates_and_bad_category():
    all_checks()
    with pytest.raises(ValueError):
        check("SSH-001", "dup", category="ssh", severity=Severity.LOW, fix="x")(lambda c: None)
    with pytest.raises(ValueError):
        check("X-1", "x", category="nope", severity=Severity.LOW, fix="x")


def test_select_checks():
    checks = all_checks()
    assert {c.spec.id for c in select_checks(checks, ["SSH-00*"])} == {f"SSH-00{i}" for i in range(1, 10)}
    assert {c.spec.category for c in select_checks(checks, ["web", "database"])} == {"web", "database"}
    assert "SSH-001" not in {c.spec.id for c in select_checks(checks, None, ["ssh-001"])}
    assert len(select_checks(checks)) == len(checks)


def test_runner_that_raises_does_not_crash_audit():
    class Exploding(FakeRunner):
        def run(self, argv, timeout=30.0):
            raise RuntimeError("runner exploded")

    c = hardened_host()
    c.runner = Exploding(available=c.runner.available)
    report = run_audit(c)
    assert len(report.findings) == len(all_checks())
    assert report.by_status(Status.ERROR)


def test_filesystem_errors_do_not_crash_audit():
    c = hardened_host()
    c.fs.broken.update({"/etc/ssh/sshd_config", "/etc/passwd", "/proc/meminfo", "/etc/os-release"})
    report = run_audit(c)
    assert len(report.findings) == len(all_checks())


def test_memo_caches_errors():
    c = ctx()
    calls = []

    def fn():
        calls.append(1)
        raise ValueError("x")

    for _ in range(2):
        with pytest.raises(ValueError):
            c.memo("k", fn)
    assert calls == [1]


def test_context_read_semantics():
    fs = FakeFS().add_file("/etc/a", "A").add_file("/etc/secret", "S").deny("/etc/secret")
    user = AuditContext(FakeRunner(), fs, False)
    assert user.read("/etc/a") == "A" and user.read("/etc/missing") is None
    with pytest.raises(NeedsRoot):
        user.read("/etc/secret")
    root = AuditContext(FakeRunner(), fs, True)
    with pytest.raises(PermissionError):
        root.read("/etc/secret")
    assert user.try_read("/etc").error == "is a directory"


def finding(sev, status):
    return Finding("X", "x", "ssh", sev, status, "", [], "")


def test_score_weights():
    assert compute([]).score == 100
    s = compute([finding(Severity.CRITICAL, Status.PASS), finding(Severity.CRITICAL, Status.FAIL)])
    assert s.score == 50 and s.grade == "F"
    s = compute([finding(Severity.HIGH, Status.WARN), finding(Severity.LOW, Status.PASS)])
    assert s.score == round(100 * (3 + 1) / 7)
    s = compute(
        [
            finding(Severity.HIGH, Status.SKIPPED),
            finding(Severity.INFO, Status.FAIL),
            finding(Severity.LOW, Status.PASS),
            finding(Severity.MEDIUM, Status.NOT_APPLICABLE),
        ]
    )
    assert s.score == 100 and s.scored == 1 and s.total == 2
    assert worst_failure([finding(Severity.LOW, Status.FAIL), finding(Severity.HIGH, Status.FAIL)]) is Severity.HIGH
    assert worst_failure([finding(Severity.LOW, Status.PASS)]) is None


@pytest.mark.parametrize(("value", "grade"), [(95, "A"), (85, "B"), (75, "C"), (65, "D"), (10, "F")])
def test_grades(value, grade):
    findings = [finding(Severity.LOW, Status.PASS)] * value + [finding(Severity.LOW, Status.FAIL)] * (100 - value)
    assert compute(findings).grade == grade


def test_subprocess_runner_real_commands():
    runner = SubprocessRunner()
    result = runner.run([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"])
    assert result.returncode == 3 and result.stdout.strip() == "out" and "err" in result.stderr
    assert not result.ok
    missing = runner.run(["definitely-not-a-real-command-xyz"])
    assert missing.missing and "command not found" in missing.describe()
    slow = runner.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2)
    assert slow.error == "timeout"
    env = runner.run([sys.executable, "-c", "import os; print(os.environ['LC_ALL'])"])
    assert env.stdout.strip() == "C"


def test_command_result_denied_markers():
    runner = SubprocessRunner()
    r = runner.run([sys.executable, "-c", "import sys; sys.stderr.write('ERROR: You need to be root'); sys.exit(1)"])
    assert r.denied


def test_real_filesystem_and_walk(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f").write_text("x")
    (tmp_path / "a" / "ww").write_text("y")
    os.chmod(tmp_path / "a" / "ww", 0o666)
    (tmp_path / "link").symlink_to(tmp_path / "a")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "inner").write_text("z")
    fs = RealFileSystem()
    assert fs.read_text(str(tmp_path / "a" / "f")) == "x"
    assert fs.exists(str(tmp_path / "link")) and fs.is_dir(str(tmp_path / "a"))
    st = fs.stat(str(tmp_path / "a" / "ww"))
    assert st.world_writable and st.is_file and stat.S_IMODE(st.mode) == 0o666
    assert fs.stat(str(tmp_path / "link"), follow_symlinks=False).is_link
    assert fs.glob(str(tmp_path / "a" / "*")) == [str(tmp_path / "a" / "f"), str(tmp_path / "a" / "ww")]
    os.chmod(locked, 0)
    try:
        stats = WalkStats()
        paths = [p for p, _ in walk(fs, str(tmp_path), stats=stats)]
        assert str(tmp_path / "a" / "ww") in paths
        assert str(tmp_path / "a" / "f") in paths
        assert not any(p.startswith(str(tmp_path / "link") + "/") for p in paths)  # symlinks are not followed
        if os.geteuid() != 0:
            assert stats.errors and "permission denied" in stats.errors[0]
    finally:
        os.chmod(locked, 0o755)
    with pytest.raises(FileNotFoundError):
        fs.read_text(str(tmp_path / "nope"))


def test_walk_limits():
    fs = FakeFS()
    for i in range(10):
        fs.add_file(f"/w/d{i}/f", "")
    stats = WalkStats()
    assert len(list(walk(fs, "/w", max_entries=5, stats=stats))) == 5 and stats.truncated
    assert all(p.count("/") <= 2 for p, _ in walk(fs, "/w", max_depth=0))
    assert [p for p, _ in walk(fs, "/w", skip=("/w/d1",)) if p.startswith("/w/d1")] == []


def test_host_root_filesystem(tmp_path):
    from ubuntu_server_audit.system import HostRootFileSystem

    (tmp_path / "etc" / "ssh").mkdir(parents=True)
    (tmp_path / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin no\n")
    (tmp_path / "etc" / "os-release").write_text("ID=ubuntu\n")
    fs = HostRootFileSystem(str(tmp_path))
    assert fs.read_text("/etc/os-release") == "ID=ubuntu\n"
    assert fs.exists("/etc/ssh/sshd_config") and fs.is_dir("/etc/ssh")
    assert fs.listdir("/etc") == ["os-release", "ssh"]
    assert fs.glob("/etc/ssh/*") == ["/etc/ssh/sshd_config"]
    assert fs.stat("/etc/os-release").is_file


def test_chroot_runner_not_found(tmp_path):
    from ubuntu_server_audit.system import ChrootRunner

    runner = ChrootRunner(str(tmp_path))
    assert runner.which("sshd") is None
    assert runner.run(["sshd", "-T"]).missing


def test_host_root_cli_errors(tmp_path):
    from ubuntu_server_audit.cli import EXIT_ERROR, main

    assert main(["--host-root", str(tmp_path / "missing")], is_root=True) == EXIT_ERROR
    (tmp_path / "etc").mkdir()
    assert main(["--host-root", str(tmp_path)], is_root=False) == EXIT_ERROR
