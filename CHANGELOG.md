# Changelog

## 2.0.0 — 2026-10-28

Modernization of the February 2026 original (two scripts, no tests).

- One installable CLI, `nmap-scan`, with two subcommands: `scan` and `parse`.
- `scan` runs exactly one scan. The profile is chosen explicitly
  (`default`, `connect`, `syn`, `service`, `aggressive`); the aggressive
  profile and any custom `-A` arguments require `--confirm-aggressive`.
- Custom `--scan-args` are validated; Nmap output options (`-oX`, `-oN`,
  `-oG`, `-oA`, `--append-output`) are rejected because the tool owns the
  XML output. `--dry-run` prints the command without scanning.
- Windows-safe privilege detection (no `os.geteuid` crash); `--help` and
  `parse` work without the `nmap` binary or `python-nmap` installed.
- The parser handles every host in the XML, all port states, service
  product/version, OS matches, script output, traceroute hops, and
  extraports counts. Reports contain only what the scan found — no
  hardcoded scan-type, host, or port claims.
- Parse errors raise instead of returning error strings, and the CLI
  exits non-zero on missing or malformed input.
- Structured output: Markdown, JSON, and CSV renderers, plus a
  dataclass/JSON model (`nmap_scan.parser.ScanResult`).
- Pinned `python-nmap==0.7.1`, `pyproject.toml`, MIT LICENSE, CI,
  `.gitattributes` (LF), and 35 tests (plus one localhost integration test
  that runs only where the `nmap` binary is installed).

## 1.0.0 — 2026-02-18

Original: `main.py` (scan orchestration) and `parse_nmap_xml.py`
(XML-to-summary parser), with an unpinned `python-nmap` requirement.
