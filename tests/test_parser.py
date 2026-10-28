from pathlib import Path

import pytest

from nmap_scan.errors import NmapParseError
from nmap_scan.parser import parse_file, parse_string

FIXTURES = Path(__file__).parent / "fixtures"


def test_multi_host_fixture():
    result = parse_file(FIXTURES / "multi-host.xml")
    assert result.nmap_version == "7.95"
    assert result.args == "nmap -A -sV -oX - 203.0.113.10 203.0.113.11"
    assert result.start_time == "2026-02-16T10:00:00+00:00"
    assert [info.scan_type for info in result.scaninfo] == ["syn", "service"]
    assert len(result.hosts) == 2

    first, second = result.hosts
    assert first.address == "203.0.113.10"
    assert first.hostnames == ["example-a.test"]
    assert first.status == "up"
    assert [p.portid for p in first.ports] == [22, 80, 443]
    assert [p.state for p in first.ports] == ["open", "filtered", "open"]
    ssh = first.ports[0]
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "9.0"
    assert ssh.service.cpe == ["cpe:/a:openbsd:openssh:9.0"]
    assert ssh.service.display() == "OpenSSH 9.0 (protocol 2.0)"
    https = first.ports[2]
    assert https.scripts[0].script_id == "http-title"
    assert first.extraports[0].state == "closed"
    assert first.extraports[0].count == 997
    assert first.os_matches[0].name == "Linux 5.15"
    assert first.os_matches[0].classes[0].vendor == "Linux"
    assert first.uptime_seconds == 86400
    assert len(first.trace) == 2
    assert first.open_ports()[0].portid == 22

    assert second.address == "203.0.113.11"
    assert second.status == "down"
    assert second.hostnames == []
    assert second.ports == []

    assert result.runstats is not None
    assert result.runstats.hosts_up == 1
    assert result.runstats.hosts_down == 1
    assert result.runstats.elapsed_seconds == 60.0


def test_no_open_ports_fixture():
    result = parse_file(FIXTURES / "no-open-ports.xml")
    assert len(result.hosts) == 1
    assert result.hosts[0].open_ports() == []
    assert result.hosts[0].extraports[0].count == 1000


def test_empty_nmaprun_has_no_hosts_not_an_error():
    result = parse_string('<nmaprun version="7.95" args="nmap x"></nmaprun>')
    assert result.hosts == []
    assert result.nmap_version == "7.95"


def test_malformed_xml_raises():
    with pytest.raises(NmapParseError):
        parse_string("<nmaprun><unclosed>")


def test_wrong_root_raises():
    with pytest.raises(NmapParseError):
        parse_string("<scan></scan>")


def test_missing_file_raises():
    with pytest.raises(NmapParseError):
        parse_file(FIXTURES / "does-not-exist.xml")


def test_to_dict_is_json_serializable():
    import json

    result = parse_file(FIXTURES / "multi-host.xml")
    assert json.loads(json.dumps(result.to_dict()))["hosts"][0]["address"] == "203.0.113.10"
