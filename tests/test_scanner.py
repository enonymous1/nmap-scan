import pytest

from nmap_scan.errors import NmapScanError
from nmap_scan.scanner import (
    dry_run_command,
    is_privileged,
    resolve_arguments,
    run_scan,
    validate_scan_args,
    write_xml,
)

SAMPLE_XML = (
    '<?xml version="1.0"?><nmaprun version="7.95" args="nmap -sT x">'
    "<host><status state='up'/><address addr='203.0.113.10' addrtype='ipv4'/></host>"
    "</nmaprun>"
)


class FakeScanner:
    def __init__(self, xml=SAMPLE_XML):
        self.xml = xml
        self.calls = []

    def scan(self, hosts, ports, arguments, timeout=0):
        self.calls.append((hosts, ports, arguments, timeout))

    def get_nmap_last_output(self):
        return self.xml.encode("utf-8")

    def command_line(self):
        return "nmap -oX - 203.0.113.10 -sT"


def test_validate_rejects_output_options():
    for args in ("-sV -oX out.xml", "-oN results.txt", "-oA base", "--append-output", "-oG-"):
        with pytest.raises(NmapScanError):
            validate_scan_args(args)


def test_validate_accepts_ordinary_args():
    assert validate_scan_args("-sV -p 22,80") == ["-sV", "-p", "22,80"]


def test_resolve_default_profile_follows_privilege():
    assert resolve_arguments("default", None, confirm_aggressive=False, privileged=True) == "-sS"
    assert resolve_arguments("default", None, confirm_aggressive=False, privileged=False) == "-sT"


def test_aggressive_requires_confirmation():
    with pytest.raises(NmapScanError):
        resolve_arguments("aggressive", None, confirm_aggressive=False)
    assert (
        resolve_arguments("aggressive", None, confirm_aggressive=True) == "-A -sV"
    )
    with pytest.raises(NmapScanError):
        resolve_arguments("service", "-A -sV", confirm_aggressive=False)
    assert (
        resolve_arguments("service", "-A -sV", confirm_aggressive=True) == "-A -sV"
    )


def test_unknown_profile_rejected():
    with pytest.raises(NmapScanError):
        resolve_arguments("stealth", None, confirm_aggressive=False)


def test_custom_args_override_profile():
    assert (
        resolve_arguments("connect", "-sV -Pn", confirm_aggressive=False) == "-sV -Pn"
    )


def test_is_privileged_returns_bool_without_crashing():
    assert isinstance(is_privileged(), bool)


def test_run_scan_uses_fake_scanner_once_and_decodes_bytes():
    fake = FakeScanner()
    run = run_scan(
        "203.0.113.10", arguments="-sT", scanner_factory=lambda: fake
    )
    assert run.xml == SAMPLE_XML
    assert run.command_line == "nmap -oX - 203.0.113.10 -sT"
    assert fake.calls == [("203.0.113.10", None, "-sT", 0)]


def test_run_scan_failure_is_wrapped():
    class FailingScanner(FakeScanner):
        def scan(self, hosts, ports, arguments, timeout=0):
            raise RuntimeError("boom")

    with pytest.raises(NmapScanError, match="Nmap scan failed"):
        run_scan("203.0.113.10", arguments="-sT", scanner_factory=FailingScanner)


def test_run_scan_empty_output_rejected():
    with pytest.raises(NmapScanError, match="no output"):
        run_scan("203.0.113.10", arguments="-sT", scanner_factory=lambda: FakeScanner(""))


def test_write_xml_creates_parent_dirs(tmp_path):
    path = write_xml(SAMPLE_XML, tmp_path / "nested" / "out.xml")
    assert path.read_text(encoding="utf-8") == SAMPLE_XML


def test_dry_run_command():
    assert dry_run_command("203.0.113.10", "-sT") == "nmap -oX - 203.0.113.10 -sT"
    assert "-p 22" in dry_run_command("203.0.113.10", "-sV", ports="22")
