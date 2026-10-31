"""Tests for the v2.0.1 staff-review fixes."""

import os
from pathlib import Path

import pytest

import nmap_scan.scanner as scanner_module
from nmap_scan.cli import main
from nmap_scan.errors import NmapScanError
from nmap_scan.parser import (
    ScriptResult,
    filter_result,
    parse_file,
    parse_nmap_xml,
)
from nmap_scan.reporting import _fence_for, scan_to_csv, scan_to_json, scan_to_markdown
from nmap_scan.scanner import (
    ScanRun,
    is_privileged,
    run_scan,
    validate_scan_args,
    write_text_file,
    write_xml,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    "args",
    [
        "-oX-",
        "-oN foo",
        "-oG-",
        "-oA out",
        "-sVoX",
        "--append-output=foo",
        "--append-out",
        "--resume",
    ],
)
def test_validator_rejects_output_options(args):
    with pytest.raises(NmapScanError):
        validate_scan_args(args)


def test_validator_accepts_non_output_options():
    assert validate_scan_args("-sV -Pn --script=smb-os-discovery") == [
        "-sV",
        "-Pn",
        "--script=smb-os-discovery",
    ]


def test_host_scripts_parsed_and_rendered():
    result = parse_file(FIXTURES / "multi-host.xml")
    host = result.hosts[0]
    assert [s.script_id for s in host.host_scripts] == ["smb-os-discovery"]
    markdown = scan_to_markdown(result)
    assert "Host script `smb-os-discovery`" in markdown
    assert "OS: Linux 5.15" in markdown
    assert "smb-os-discovery" in scan_to_json(result)
    # CSV rows are ports, so host scripts deliberately do not appear there.
    assert "smb-os-discovery" not in scan_to_csv(result)


def test_markdown_escaping_backticks_and_fences():
    result = parse_file(FIXTURES / "multi-host.xml")
    host = result.hosts[0]
    host.ports[0].service.name = "we`ird"
    host.ports[0].scripts.append(ScriptResult(script_id="x", output="a\n```\nb"))
    markdown = scan_to_markdown(result)
    assert "we\\`ird" in markdown
    assert "````" in markdown  # fence grows past the ``` inside the output


def test_fence_for():
    assert _fence_for("plain") == "```"
    assert _fence_for("a ``` b") == "````"
    assert _fence_for("````") == "`````"


def test_write_xml_atomic(tmp_path):
    out = tmp_path / "sub" / "scan.xml"
    out.parent.mkdir()
    out.write_text("<old/>", encoding="utf-8")
    write_xml("<new/>", out)
    assert out.read_text(encoding="utf-8") == "<new/>"
    assert not (tmp_path / "sub" / "scan.xml.tmp").exists()


def test_write_text_file_creates_parents(tmp_path):
    out = tmp_path / "a" / "b" / "report.md"
    write_text_file("# hi\n", out)
    assert out.read_text(encoding="utf-8") == "# hi\n"


def test_filter_result_open_only_and_host():
    result = parse_file(FIXTURES / "multi-host.xml")
    filtered = filter_result(result, open_only=True)
    assert all(p.state == "open" for h in filtered.hosts for p in h.ports)
    assert filtered.runstats is not None  # run stats describe the original scan
    by_host = filter_result(result, host="203.0.113.11")
    assert [h.address for h in by_host.hosts] == ["203.0.113.11"]
    by_name = filter_result(result, host="example-a.test")
    assert [h.address for h in by_name.hosts] == ["203.0.113.10"]


def test_parse_filters_via_cli(capsys):
    assert (
        main(["parse", str(FIXTURES / "multi-host.xml"), "--host", "203.0.113.11"]) == 0
    )
    out = capsys.readouterr().out
    assert "## 203.0.113.11" in out
    assert "## 203.0.113.10" not in out


def test_scan_flow_with_fake_scanner(monkeypatch, tmp_path, capsys):
    xml_text = (FIXTURES / "multi-host.xml").read_text(encoding="utf-8")

    def fake_run_scan(target, *, arguments, ports=None, timeout=0, scanner_factory=None):
        return ScanRun(
            target=target, arguments=arguments, xml=xml_text, command_line="nmap ..."
        )

    monkeypatch.setattr(scanner_module, "run_scan", fake_run_scan)
    out = tmp_path / "scan.xml"
    assert (
        main(["scan", "--target", "203.0.113.10", "--output", str(out), "--summary-format", "json"])
        == 0
    )
    assert out.read_text(encoding="utf-8") == xml_text
    assert "203.0.113.10" in capsys.readouterr().out


def test_privilege_fallback_without_geteuid(monkeypatch):
    # Simulates Windows: no os.geteuid, and ctypes has no windll here.
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert is_privileged() is False


def test_negative_timeout_and_indent(capsys):
    with pytest.raises(NmapScanError):
        run_scan("203.0.113.10", arguments="-sV", timeout=-1)
    assert main(["scan", "--target", "203.0.113.10", "--timeout", "-1"]) == 2
    assert (
        main(["parse", str(FIXTURES / "multi-host.xml"), "--indent", "-1"]) == 2
    )


def test_parse_nmap_xml_deprecated():
    with pytest.warns(DeprecationWarning, match="parse_file"):
        result = parse_nmap_xml(FIXTURES / "multi-host.xml")
    assert result.hosts[0].address == "203.0.113.10"
