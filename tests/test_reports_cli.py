import io
import json

import pytest

from hosts import hardened_host, neglected_host
from ubuntu_server_audit.cli import EXIT_ERROR, EXIT_FAIL, EXIT_OK, _formats, main
from ubuntu_server_audit.engine import run_audit
from ubuntu_server_audit.model import Status
from ubuntu_server_audit.report import render, write_reports
from ubuntu_server_audit.report.markdown import md


def cli(args, host=neglected_host, root=True):
    ctx = host(root=root)
    out = io.StringIO()
    code = main(args, stdout=out, runner=ctx.runner, fs=ctx.fs, is_root=root)
    return code, out.getvalue()


def test_json_report_schema():
    report = run_audit(neglected_host())
    data = json.loads(render(report, "json"))
    assert data["tool"] == "ubuntu-server-audit" and data["schema"] == 1
    assert data["host"]["hostname"] == "web1" and data["host"]["is_root"] is True
    assert data["score"]["grade"] == "F"
    first = data["findings"][0]
    assert {"id", "severity", "status", "status_text", "evidence", "fix", "needs_root", "partial"} <= first.keys()
    assert sum(data["counts"].values()) == len(data["findings"])


def test_normal_user_reports_say_needs_root():
    report = run_audit(neglected_host(root=False))
    data = json.loads(render(report, "json"))
    skipped = [f for f in data["findings"] if f["status"] == "skipped"]
    assert skipped and all(f["status_text"] == "skipped (needs root)" for f in skipped)
    text = render(report, "text")
    assert "skipped (needs root)" in text and "run with sudo" in text
    assert "SKIP (needs root)" in render(report, "markdown")
    assert "SKIP (needs root)" in render(report, "html")


def test_text_report_content():
    text = render(run_audit(neglected_host()), "text")
    assert "Fix first:" in text and "Score " in text and "[FAIL]  SSH-001" in text
    assert "\033[" not in text
    assert "\033[31m" in render(run_audit(neglected_host()), "text", color=True)
    clean = render(run_audit(hardened_host()), "text")
    assert "Fix first:" not in clean and "Score 100/100 (grade A)" in clean


def test_html_and_markdown_escape_system_data():
    ctx = neglected_host()
    ctx.fs.add_file("/proc/sys/kernel/hostname", "<script>alert(1)</script>|x\n")
    report = run_audit(ctx)
    html = render(report, "html")
    assert "<script>" not in html and "&lt;script&gt;" in html
    markdown = render(report, "markdown")
    assert "<script>" not in markdown
    assert md("a|b*c") == "a\\|b\\*c"


def test_text_report_strips_control_characters():
    ctx = neglected_host()
    ctx.fs.add_file("/etc/os-release", 'PRETTY_NAME="Evil\x1b[2J"\nID=ubuntu\nVERSION_ID="22.04"\n')
    assert "\x1b[2J" not in render(run_audit(ctx), "text")


def test_write_reports(tmp_path):
    paths = write_reports(run_audit(hardened_host()), ["text", "json", "markdown", "html"], tmp_path)
    assert sorted(p.name for p in paths) == [
        "server-audit.html",
        "server-audit.json",
        "server-audit.md",
        "server-audit.txt",
    ]
    assert all(p.stat().st_size > 200 for p in paths)


def test_formats():
    assert _formats(["md,html"]) == ["markdown", "html"]
    assert _formats(["all"]) == ["text", "json", "markdown", "html"]
    with pytest.raises(ValueError):
        _formats(["pdf"])


def test_cli_default_text_and_exit_codes():
    code, out = cli([])
    assert code == EXIT_OK and "Score" in out
    assert cli(["--fail-under", "90", "-q"])[0] == EXIT_FAIL
    assert cli(["--fail-under", "90", "-q"], host=hardened_host)[0] == EXIT_OK
    assert cli(["--fail-on", "critical", "-q"])[0] == EXIT_FAIL
    assert cli(["--fail-on", "low", "-q"], host=hardened_host)[0] == EXIT_OK
    assert cli(["--only", "HK-001", "--fail-on", "high", "-q"])[0] == EXIT_OK  # HK-001 is a low warn


def test_cli_json_stdout_and_selection():
    _, out = cli(["-f", "json", "--only", "ssh", "--skip", "SSH-009"])
    data = json.loads(out)
    assert {f["id"] for f in data["findings"]} == {f"SSH-00{i}" for i in range(1, 9)}


def test_cli_output_dir(tmp_path):
    code, out = cli(["-f", "all", "-o", str(tmp_path), "--basename", "web1"])
    assert code == EXIT_OK and "reports:" in out
    assert (tmp_path / "web1.json").exists() and (tmp_path / "web1.html").exists()


@pytest.mark.parametrize(
    "args",
    [
        ["-f", "json,html"],
        ["-f", "pdf"],
        ["--only", "NOPE-*"],
        ["--fail-under", "101"],
        ["--max-files", "0"],
        ["--require-root"],
    ],
)
def test_cli_errors(args):
    assert cli(args, root=False)[0] == EXIT_ERROR


def test_cli_web_root_option(tmp_path):
    _, out = cli(["-f", "json", "--only", "USR-004", "--web-root", "/var/www/html/"])
    data = json.loads(out)
    assert data["findings"][0]["status"] == "fail"
    assert "web roots: /var/www/html" in data["findings"][0]["evidence"]


def test_list_checks_and_print_sysctl(capsys):
    code, out = cli(["--list-checks"])
    assert code == EXIT_OK and "USR-001" in out and "(needs root)" in out
    code, out = cli(["--print-sysctl"])
    assert "net.ipv4.tcp_syncookies = 1" in out and "kernel.randomize_va_space = 2" in out


def test_print_sysctl_satisfies_kernel_checks():
    from ubuntu_server_audit.kernel_values import HARDENED_SYSCTL

    ctx = neglected_host()
    for key, value in HARDENED_SYSCTL.items():
        ctx.fs.add_file("/proc/sys/" + key.replace(".", "/"), value + "\n")
    found = {f.id: f.status for f in run_audit(ctx).findings}
    assert found["KRN-001"] is Status.PASS and found["KRN-002"] is Status.PASS and found["KRN-003"] is Status.PASS


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0 and "0.1.0" in capsys.readouterr().out
