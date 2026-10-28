# nmap-scan

Run one Nmap scan and turn Nmap XML output into an honest report. One command, one scan, and a parser that reports every host it finds — nothing hardcoded, nothing invented.

> **Only scan systems you own or have explicit permission to scan.** Scanning other systems without authorization may be unlawful. `nmap-scan` prints this reminder before every real scan. Use `--dry-run` to check a command before it runs.

## Install

Requires Python 3.10+ and the `nmap` binary on PATH (for scanning only; parsing needs neither).

```powershell
pip install .
```

That installs the `nmap-scan` command. For development:

```powershell
pip install -e ".[dev]"
pytest -q
```

## Scan

```powershell
nmap-scan scan --target 203.0.113.10 --output scan-results.xml
```

The default profile uses `-sS` when privileged and `-sT` otherwise. Pick a profile explicitly instead of relying on the default:

| Profile | Arguments | Notes |
| --- | --- | --- |
| `default` | `-sS` / `-sT` | Privilege-aware, as above |
| `connect` | `-sT` | TCP connect scan, no privileges needed |
| `syn` | `-sS` | SYN scan, needs privileges |
| `service` | `-sV` | Version detection |
| `aggressive` | `-A -sV` | OS detection, scripts, traceroute — requires `--confirm-aggressive` |

```powershell
nmap-scan scan --target 203.0.113.10 --profile service --ports 22,80,443
nmap-scan scan --target 203.0.113.0/24 --profile aggressive --confirm-aggressive
nmap-scan scan --target 203.0.113.10 --scan-args "-sV -Pn" --timeout 120
```

Custom `--scan-args` override `--profile`. Nmap output options (`-oX`, `-oN`, `-oG`, `-oA`, `--append-output`) are rejected: this tool writes the XML itself, and `python-nmap` already forces `-oX -`. `--dry-run` prints the exact command and runs nothing:

```powershell
nmap-scan scan --target 203.0.113.10 --profile service --dry-run
# nmap -oX - 203.0.113.10 -sV
```

By default a scan also prints a Markdown summary. Use `--summary-format json|csv|none` and `--summary-output <file>` to change that.

## Parse

`parse` reads an existing Nmap XML file (or stdin with `-`) and renders it as Markdown, JSON, or CSV. It needs no Nmap install:

```powershell
nmap-scan parse scan-results.xml
nmap-scan parse scan-results.xml --format json --output report.json
nmap-scan parse scan-results.xml --format csv --output report.csv
Get-Content scan-results.xml | nmap-scan parse -
```

The report lists every host, every port state (open, filtered, closed counts via extraports), service product/version, OS matches, script output, and run statistics — only what the XML contains. A down host is reported as down; a scan with no open ports says so.

## Use it as a library

```python
from nmap_scan import parse_file, scan_to_json

result = parse_file("scan-results.xml")
for host in result.hosts:
    print(host.address, host.status, [p.portid for p in host.open_ports()])
print(scan_to_json(result))
```

Parse errors raise `NmapParseError`; scan failures raise `NmapScanError`. Neither returns an error string disguised as a result.

## Layout

```
src/nmap_scan/
  cli.py       # nmap-scan scan / parse
  scanner.py   # one-scan execution, profile resolution, argument validation
  parser.py    # Nmap XML -> dataclasses (all hosts, ports, OS, scripts)
  reporting.py # Markdown / JSON / CSV renderers
tests/
  fixtures/    # fictional TEST-NET-3 (RFC 5737) XML, not real scan results
```

## What changed in 2.0.0

The February 2026 original always ran two scans (including a silent `-A -sV`), parsed only the first host, hardcoded its summary prose, crashed on Windows (`os.geteuid`), and failed `--help` when Nmap was absent. See [CHANGELOG.md](CHANGELOG.md) for the full list. No real scan results are shipped with this repository; the test fixtures use fictional documentation addresses.

## License

MIT. See [LICENSE](LICENSE).
