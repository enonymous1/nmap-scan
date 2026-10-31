"""Command-line interface: ``nmap-scan scan`` and ``nmap-scan parse``.

Parsing is standard-library only, so ``nmap-scan parse`` works without
the ``python-nmap`` dependency or the ``nmap`` binary. The scanner
module itself is also standard-library only; only the `nmap` package
import is lazy, inside the scan command, so ``--help`` and ``parse``
never fail for a missing scanner dependency (the v1 ``--help`` bug).

Exit codes (documented here because they are part of the interface):
0 = success. 1 = a scan ran and failed, or a scan output file could
not be written. 2 = a usage error (argparse, an invalid profile or
timeout, or a parse input failure). The authorization warning goes to
stderr so stdout stays machine-readable when a JSON summary is piped
to another tool — do not move it to stdout in a tidy-up.

``--output`` and ``--summary-output`` overwrite an existing file
without asking. That is the documented policy: this is a local tool,
and a prompt would break scripting. Check before reusing a filename
you care about.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .errors import NmapParseError, NmapScanError
from .parser import filter_result, parse_file, parse_string
from .reporting import render
from .scanner import write_text_file

AUTHORIZATION_WARNING = (
    "Only scan systems you own or have explicit permission to scan. "
    "Scanning other systems without authorization may be unlawful."
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nmap-scan",
        description="Run Nmap scans and report on Nmap XML output.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Run one Nmap scan and write its XML output.",
        description="Run one Nmap scan and write its XML output.",
    )
    scan.add_argument("--target", required=True, help="Target IP, hostname, or CIDR.")
    scan.add_argument(
        "--output",
        default="scan-results.xml",
        help="Output XML file (default: scan-results.xml).",
    )
    scan.add_argument(
        "--profile",
        choices=["default", "connect", "syn", "service", "aggressive"],
        default="default",
        help="Scan profile. 'default' uses -sS when privileged, -sT otherwise. "
        "'aggressive' (-A -sV) requires --confirm-aggressive.",
    )
    scan.add_argument(
        "--scan-args",
        default=None,
        help="Custom Nmap arguments; overrides --profile. Nmap output "
        "options (-oX, -oN, -oG, -oA, --append-output) are rejected.",
    )
    scan.add_argument("--ports", default=None, help="Port spec, e.g. '22,80,443' or '1-1024'.")
    scan.add_argument("--timeout", type=int, default=0, help="Scan timeout in seconds (0 = none).")
    scan.add_argument(
        "--confirm-aggressive",
        action="store_true",
        help="Confirm an aggressive (-A) scan: OS detection, script scanning, traceroute.",
    )
    scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the Nmap command that would run, without scanning.",
    )
    scan.add_argument(
        "--summary-format",
        choices=["markdown", "json", "csv", "none"],
        default="markdown",
        help="Summary rendered from the scan output (default: markdown).",
    )
    scan.add_argument(
        "--summary-output",
        default=None,
        help="Write the summary to this file instead of stdout.",
    )

    parse = subparsers.add_parser(
        "parse",
        help="Render an Nmap XML file as Markdown, JSON, or CSV.",
        description="Render an Nmap XML file as Markdown, JSON, or CSV.",
    )
    parse.add_argument("input", help="Nmap XML file, or '-' to read from stdin.")
    parse.add_argument(
        "--format",
        choices=["markdown", "json", "csv"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    parse.add_argument(
        "--output",
        default=None,
        help="Write the report to this file instead of stdout.",
    )
    parse.add_argument(
        "--open-only",
        action="store_true",
        help="Only include hosts' open ports in the report.",
    )
    parse.add_argument(
        "--host",
        default=None,
        help="Only include this host address or hostname in the report.",
    )
    parse.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indent (default: 2).",
    )
    return parser


def _emit(text: str, output: str | None) -> None:
    """Print text, or write it to a file (creating parents as needed)."""
    if output:
        path = write_text_file(text, output)
        print(f"Report saved to {path}")
    else:
        print(text, end="" if text.endswith("\n") else "\n")


def _run_scan(args: argparse.Namespace) -> int:
    from .scanner import dry_run_command, resolve_arguments, run_scan, write_xml

    try:
        arguments = resolve_arguments(
            args.profile,
            args.scan_args,
            confirm_aggressive=args.confirm_aggressive,
        )
    except NmapScanError as exc:
        # Invalid profile or arguments is a usage error, not a scan
        # failure, so it exits 2 like an argparse error.
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.timeout < 0:
        print(f"Error: scan timeout must not be negative: {args.timeout}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(dry_run_command(args.target, arguments, args.ports))
        return 0

    print(AUTHORIZATION_WARNING, file=sys.stderr)
    try:
        run = run_scan(
            args.target,
            arguments=arguments,
            ports=args.ports,
            timeout=args.timeout,
        )
    except NmapScanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        write_xml(run.xml, args.output)
    except OSError as exc:
        print(f"Error: could not write {args.output}: {exc}", file=sys.stderr)
        return 1
    print(f"Scan complete. Results saved to {args.output}")

    if args.summary_format == "none":
        return 0
    try:
        result = parse_string(run.xml)
        summary = render(result, args.summary_format)
    except NmapParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    try:
        _emit(summary, args.summary_output)
    except OSError as exc:
        print(f"Error: could not write summary: {exc}", file=sys.stderr)
        return 1
    return 0


def _run_parse(args: argparse.Namespace) -> int:
    """Render an Nmap XML file. Exit 2 on any input or output failure."""
    if args.indent < 0:
        print(f"Error: JSON indent must not be negative: {args.indent}", file=sys.stderr)
        return 2
    try:
        if args.input == "-":
            result = parse_string(sys.stdin.read())
        else:
            result = parse_file(args.input)
    except NmapParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    result = filter_result(result, open_only=args.open_only, host=args.host)
    try:
        _emit(render(result, args.format, indent=args.indent), args.output)
    except OSError as exc:
        print(f"Error: could not write report: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the chosen subcommand."""
    args = _build_parser().parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    return _run_parse(args)


def entrypoint() -> None:
    """Console-script entry point: exit with the subcommand's code."""
    sys.exit(main())
