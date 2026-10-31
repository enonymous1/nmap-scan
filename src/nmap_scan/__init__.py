"""nmap-scan: run Nmap scans and report on Nmap XML output."""

from importlib.metadata import PackageNotFoundError, version

from .parser import ScanResult, parse_file, parse_string
from .reporting import render, scan_to_csv, scan_to_json, scan_to_markdown

# Single source of truth: the version lives in pyproject.toml.
# Running from a source checkout that was never installed has no
# package metadata, so it reports a clearly-marked unknown version
# rather than a stale hardcoded one.
try:
    __version__ = version("nmap-scan")
except PackageNotFoundError:  # pragma: no cover - installed in CI and by users
    __version__ = "0.0.0+unknown"

__all__ = [
    "ScanResult",
    "parse_file",
    "parse_string",
    "render",
    "scan_to_csv",
    "scan_to_json",
    "scan_to_markdown",
    "__version__",
]
