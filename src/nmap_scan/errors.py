"""Errors raised by nmap_scan."""


class NmapScanError(Exception):
    """A scan could not be started, completed, or read back."""


class NmapParseError(Exception):
    """Nmap XML input was missing, unreadable, or malformed."""
