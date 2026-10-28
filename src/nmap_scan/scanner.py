"""Run a single Nmap scan through python-nmap.

Exactly one scan is run per call. The caller chooses the scan profile
explicitly; nothing silently escalates to an aggressive scan. Custom
arguments are validated before they reach Nmap: options that would make
Nmap write its own output files are rejected, because this wrapper owns
the XML output and python-nmap already forces ``-oX -``.
"""

from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Union

from .errors import NmapScanError

# python-nmap rejects -oX/-oA itself; reject the rest of Nmap's own output
# options here so the wrapper, not a stray flag, decides where files go.
_BLOCKED_TOKENS = {
    "-oN",
    "-oG",
    "-oS",
    "-oA",
    "-oX",
    "--append-output",
}
_BLOCKED_PREFIXES = ("-oN", "-oG", "-oS", "-oA", "-oX", "--append-output=")

PROFILES = {
    "default": None,  # resolved from privilege: -sS privileged, -sT otherwise
    "connect": "-sT",
    "syn": "-sS",
    "service": "-sV",
    "aggressive": "-A -sV",
}


@dataclass
class ScanRun:
    target: str
    arguments: str
    xml: str
    command_line: str


def is_privileged() -> bool:
    """True when the process can run raw-packet scans.

    Windows has no ``os.geteuid``; fall back to the Win32 admin check
    instead of crashing with AttributeError (the v1 bug).
    """
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except OSError:
            return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def validate_scan_args(arguments: str) -> list[str]:
    """Split custom Nmap arguments and reject output-redirecting ones."""
    if not arguments or not arguments.strip():
        raise NmapScanError("Custom scan arguments must not be empty.")
    try:
        tokens = shlex.split(arguments)
    except ValueError as exc:
        raise NmapScanError(f"Could not parse scan arguments: {exc}") from exc
    for token in tokens:
        if token in _BLOCKED_TOKENS or token.startswith(_BLOCKED_PREFIXES):
            raise NmapScanError(
                f"Scan argument {token!r} is not allowed: this tool writes "
                "the XML output itself, so Nmap output options are rejected."
            )
    return tokens


def resolve_arguments(
    profile: str,
    scan_args: str | None,
    *,
    confirm_aggressive: bool,
    privileged: bool | None = None,
) -> str:
    """Pick the argument string for one scan.

    ``scan_args`` overrides ``profile`` when given. An aggressive scan
    (``-A``, whether from the profile or custom arguments) requires an
    explicit opt-in, because it runs OS detection, version detection,
    script scanning, and traceroute.
    """
    if scan_args:
        tokens = validate_scan_args(scan_args)
        if "-A" in tokens and not confirm_aggressive:
            raise NmapScanError(
                "Custom arguments include -A (aggressive scan). Re-run with "
                "--confirm-aggressive to confirm you intend OS detection, "
                "script scanning, and traceroute against this target."
            )
        return scan_args
    if profile not in PROFILES:
        raise NmapScanError(
            f"Unknown scan profile {profile!r}; expected one of: {', '.join(PROFILES)}."
        )
    if profile == "aggressive" and not confirm_aggressive:
        raise NmapScanError(
            "The aggressive profile runs -A -sV (OS detection, version "
            "detection, script scanning, traceroute). Re-run with "
            "--confirm-aggressive to confirm it."
        )
    if profile == "default":
        if privileged is None:
            privileged = is_privileged()
        return "-sS" if privileged else "-sT"
    profile_args = PROFILES[profile]
    assert profile_args is not None  # default/aggressive handled above
    return profile_args


def dry_run_command(target: str, arguments: str, ports: str | None = None) -> str:
    """The command python-nmap would run, without running it."""
    parts = ["nmap", "-oX", "-", target]
    if ports:
        parts += ["-p", ports]
    parts += shlex.split(arguments)
    return shlex.join(parts)


def _default_scanner():
    try:
        import nmap
    except ImportError as exc:
        raise NmapScanError(
            "The 'python-nmap' package is required to run scans. "
            "Install it with: pip install python-nmap==0.7.1"
        ) from exc
    if shutil.which("nmap") is None:
        raise NmapScanError(
            "The 'nmap' executable was not found in PATH. Install Nmap "
            "and ensure it is on PATH."
        )
    try:
        return nmap.PortScanner()
    except Exception as exc:  # PortScannerError when nmap is missing/broken
        raise NmapScanError(f"Could not start Nmap: {exc}") from exc


def run_scan(
    target: str,
    *,
    arguments: str,
    ports: str | None = None,
    timeout: int = 0,
    scanner_factory: Callable[[], object] | None = None,
) -> ScanRun:
    """Run one scan and return its raw XML output."""
    if not target or not target.strip():
        raise NmapScanError("A scan target is required.")
    validate_scan_args(arguments)
    scanner = scanner_factory() if scanner_factory is not None else _default_scanner()
    try:
        scanner.scan(hosts=target, ports=ports, arguments=arguments, timeout=timeout)
    except Exception as exc:
        raise NmapScanError(f"Nmap scan failed: {exc}") from exc
    try:
        raw = scanner.get_nmap_last_output()
    except Exception as exc:
        raise NmapScanError(f"Could not read Nmap output: {exc}") from exc
    if isinstance(raw, bytes):
        xml_text = raw.decode("utf-8", errors="replace")
    else:
        xml_text = str(raw)
    if not xml_text.strip():
        raise NmapScanError("Nmap produced no output.")
    try:
        command_line = scanner.command_line()
    except Exception:
        command_line = dry_run_command(target, arguments, ports)
    return ScanRun(
        target=target,
        arguments=arguments,
        xml=xml_text,
        command_line=str(command_line),
    )


def write_xml(xml_text: str, output: Union[str, Path]) -> Path:
    """Write raw XML, creating parent directories as needed."""
    path = Path(output)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(xml_text, encoding="utf-8")
    return path
