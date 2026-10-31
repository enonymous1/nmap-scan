# Changelog

## 2.0.1 — 2026-10-31

Staff-review fixes (review in `../nmap-scan-review.md`, not part of
the repository). Nothing in this release changes the scan model: one
scan per call, explicit profiles, no silent escalation.

- The custom-argument validator now rejects bundled short options
  (e.g. `-sVoX`), abbreviated long options (e.g. `--append-out`),
  and `--resume`, in addition to the output options rejected before.
  The trust boundary is documented in `SECURITY.md` and the scanner
  docstring: this is a local-operator guard, not a sandbox.
- Host-level `<script>` elements are no longer dropped. They are
  parsed into `Host.host_scripts` and rendered in Markdown and JSON
  (CSV rows are ports, so host scripts are not CSV rows, by design).
- Markdown rendering escapes backticks in code spans and table cells,
  and script blocks use a fence longer than any backtick run in the
  output, so scan data can no longer break out of its own formatting.
- XML output is written atomically (temp file in the same directory,
  then replace); summary/report writing shares one helper, and
  `*.tmp` is gitignored.
- `parse` gains `--open-only` and `--host` filters (a pure
  `filter_result()` function, so the library gets them too). Run
  statistics still describe the original scan when a filter is applied.
- Exit codes are documented and made consistent: scan profile and
  argument errors now exit 2 (usage), scan runtime failures exit 1,
  parse failures exit 2. Negative `--timeout` and `--indent` are
  rejected with exit 2, and scan failures name the target and ports.
- Version is single-sourced from `pyproject.toml` via
  `importlib.metadata`; `parse_nmap_xml` is deprecated (it returns a
  `ScanResult`, not the v1 Markdown string) and will be removed in
  v3.0.0.
- Lint and type checking: ruff now selects `I`, `UP`, and `B` in
  addition to `E` and `F`; mypy runs on `src` in CI; CI installs Nmap
  on Windows as well as Linux, and Dependabot updates pip and GitHub
  Actions weekly.
- README rewritten (Description, Prerequisites, Installation, Local
  Development, Deployment, exit codes, troubleshooting, security)
  with three visuals under `docs/assets/`: a demo GIF, an
  architecture diagram, and a terminal-parse image, all rendered from
  the fictional TEST-NET fixtures — no real scan output anywhere.

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
