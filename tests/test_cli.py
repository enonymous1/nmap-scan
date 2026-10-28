import io
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from nmap_scan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_help_works_without_scanner_deps(capsys):
    # --help must not require nmap or python-nmap (v1 failed here).
    with pytest.raises(SystemExit) as exc:
        main(["parse", "--help"])
    assert exc.value.code == 0
    assert "Markdown" in capsys.readouterr().out


def test_parse_markdown_to_stdout(capsys):
    assert main(["parse", str(FIXTURES / "multi-host.xml")]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.10" in out
    assert "203.0.113.11" in out


def test_parse_json_and_csv(tmp_path):
    json_out = tmp_path / "report.json"
    args = ["parse", str(FIXTURES / "multi-host.xml"), "--format", "json"]
    assert main([*args, "--output", str(json_out)]) == 0
    assert "203.0.113.10" in json_out.read_text(encoding="utf-8")
    csv_out = tmp_path / "report.csv"
    args = ["parse", str(FIXTURES / "multi-host.xml"), "--format", "csv"]
    assert main([*args, "--output", str(csv_out)]) == 0
    assert "443" in csv_out.read_text(encoding="utf-8")


def test_parse_missing_file_exits_nonzero(capsys):
    assert main(["parse", str(FIXTURES / "nope.xml")]) == 2
    assert "Error" in capsys.readouterr().err


def test_parse_malformed_file_exits_nonzero(tmp_path, capsys):
    bad = tmp_path / "bad.xml"
    bad.write_text("<nmaprun><unclosed>", encoding="utf-8")
    assert main(["parse", str(bad)]) == 2


def test_parse_stdin(capsys, monkeypatch):
    xml_text = (FIXTURES / "no-open-ports.xml").read_text(encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", io.StringIO(xml_text))
    assert main(["parse", "-"]) == 0
    assert "203.0.113.20" in capsys.readouterr().out


def test_scan_dry_run_runs_nothing(capsys):
    assert (
        main(["scan", "--target", "203.0.113.10", "--dry-run", "--profile", "service"]) == 0
    )
    assert "nmap -oX - 203.0.113.10 -sV" in capsys.readouterr().out


def test_scan_aggressive_without_confirmation_fails(capsys):
    assert main(["scan", "--target", "203.0.113.10", "--profile", "aggressive"]) == 1
    assert "confirm-aggressive" in capsys.readouterr().err


def test_scan_requires_target():
    with pytest.raises(SystemExit) as exc:
        main(["scan"])
    assert exc.value.code == 2


def test_scan_missing_nmap_binary_fails_cleanly(monkeypatch, capsys):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert main(["scan", "--target", "203.0.113.10"]) == 1
    assert "nmap" in capsys.readouterr().err.lower()


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap binary not installed")
def test_scan_localhost_connect(tmp_path):
    out = tmp_path / "scan.xml"
    code = main(
        [
            "scan",
            "--target",
            "127.0.0.1",
            "--profile",
            "connect",
            "--ports",
            "22",
            "--timeout",
            "60",
            "--output",
            str(out),
            "--summary-format",
            "none",
        ]
    )
    assert code == 0
    assert out.exists()
    assert "<nmaprun" in out.read_text(encoding="utf-8")


def test_entrypoint_via_subprocess():
    result = subprocess.run(
        [sys.executable, "-m", "nmap_scan", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "2.0.0" in result.stdout
