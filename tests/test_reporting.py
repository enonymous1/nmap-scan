import json
from pathlib import Path

from nmap_scan.parser import parse_file
from nmap_scan.reporting import render, scan_to_csv, scan_to_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def test_markdown_reports_what_was_found_and_nothing_else():
    text = scan_to_markdown(parse_file(FIXTURES / "multi-host.xml"))
    assert "203.0.113.10 (example-a.test)" in text
    assert "203.0.113.11" in text
    assert "OpenSSH 9.0 (protocol 2.0)" in text
    assert "Linux 5.15" in text
    assert "http-title" in text
    assert "997 ports" in text
    # The v1 hardcoded claims must not appear: this fixture was an -A/-sV
    # scan of TEST-NET addresses, not a local -sT scan.
    assert "-sT" not in text
    assert "your local machine" not in text
    assert "SSH, VNC" not in text
    assert "localhost" not in text


def test_markdown_down_host_and_no_ports():
    text = scan_to_markdown(parse_file(FIXTURES / "no-open-ports.xml"))
    assert "203.0.113.20" in text
    assert "No ports were reported for this host." in text
    assert "1000 ports" in text


def test_markdown_empty_scan():
    from nmap_scan.parser import parse_string

    text = scan_to_markdown(parse_string('<nmaprun version="7.95"></nmaprun>'))
    assert "No hosts were reported" in text


def test_json_round_trip():
    data = json.loads(render(parse_file(FIXTURES / "multi-host.xml"), "json"))
    assert data["hosts"][1]["status"] == "down"
    assert data["hosts"][0]["ports"][1]["state"] == "filtered"


def test_csv_one_row_per_port_plus_host_only_row():
    rows = scan_to_csv(parse_file(FIXTURES / "multi-host.xml")).strip().splitlines()
    assert rows[0].startswith("host,hostname,status,port,")
    assert len(rows) == 1 + 3 + 1  # header + 3 ports + down host with no ports
    assert "203.0.113.11" in rows[-1]
    assert "443" in rows[3]
