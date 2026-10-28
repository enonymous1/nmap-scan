"""Render a parsed Nmap scan as Markdown, JSON, or CSV.

Every renderer reports only what the parser found. Scan-type claims come
from the recorded command line and <scaninfo> entries, never from a
hardcoded description of one particular scan.
"""

from __future__ import annotations

import csv
import io
import json

from .parser import ScanResult

_FORMATS = ("markdown", "json", "csv")


def _escape_table_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def scan_to_markdown(result: ScanResult) -> str:
    lines: list[str] = ["# Nmap Scan Summary", ""]
    if result.nmap_version:
        lines.append(f"- **Nmap version:** `{result.nmap_version}`")
    if result.args:
        lines.append(f"- **Scan command:** `{result.args}`")
    if result.start_time:
        lines.append(f"- **Scan start:** `{result.start_time}`")
    for info in result.scaninfo:
        detail = ", ".join(
            part
            for part in (
                f"type `{info.scan_type}`" if info.scan_type else None,
                f"protocol `{info.protocol}`" if info.protocol else None,
                f"{info.numservices} services" if info.numservices is not None else None,
            )
            if part
        )
        if detail:
            lines.append(f"- **Scan info:** {detail}")
    lines.append("")

    if not result.hosts:
        lines.append("No hosts were reported in this scan.")
        lines.append("")
    for host in result.hosts:
        heading = host.address or "(unknown address)"
        if host.hostnames:
            heading += f" ({', '.join(host.hostnames)})"
        lines.append(f"## {heading}")
        lines.append("")
        lines.append(f"- **Status:** `{host.status}`")
        if host.addresses:
            lines.append(f"- **Addresses:** {', '.join(host.addresses)}")
        for extra in host.extraports:
            lines.append(f"- **{extra.count} ports:** `{extra.state}`")
        lines.append("")
        if host.ports:
            lines.append("| Port | Protocol | State | Service | Version |")
            lines.append("| --- | --- | --- | --- | --- |")
            for port in host.ports:
                service = port.service.name or ""
                version = port.service.display()
                lines.append(
                    "| `{}` | {} | {} | {} | {} |".format(
                        port.portid,
                        _escape_table_cell(port.protocol),
                        _escape_table_cell(port.state),
                        _escape_table_cell(service),
                        _escape_table_cell(version),
                    )
                )
            lines.append("")
            for port in host.ports:
                for script in port.scripts:
                    lines.append(f"### Script `{script.script_id}` on port {port.portid}")
                    lines.append("")
                    lines.append("```")
                    lines.append(script.output)
                    lines.append("```")
                    lines.append("")
        else:
            lines.append("No ports were reported for this host.")
            lines.append("")
        for match in host.os_matches:
            accuracy = f" ({match.accuracy}% accuracy)" if match.accuracy is not None else ""
            lines.append(f"- **OS match:** {match.name}{accuracy}")
        if host.os_matches:
            lines.append("")

    if result.runstats is not None:
        stats = result.runstats
        lines.append("## Run statistics")
        lines.append("")
        if stats.end_time:
            lines.append(f"- **Scan end:** `{stats.end_time}`")
        if stats.elapsed_seconds is not None:
            lines.append(f"- **Duration:** `{stats.elapsed_seconds}` seconds")
        if stats.hosts_total is not None:
            lines.append(
                f"- **Hosts:** {stats.hosts_up} up, {stats.hosts_down} down, "
                f"{stats.hosts_total} total"
            )
        if stats.exit_status:
            lines.append(f"- **Exit status:** `{stats.exit_status}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def scan_to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent) + "\n"


def scan_to_csv(result: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["host", "hostname", "status", "port", "protocol", "state",
         "service", "product", "version", "extrainfo"]
    )
    for host in result.hosts:
        hostname = host.hostnames[0] if host.hostnames else ""
        if not host.ports:
            writer.writerow([host.address, hostname, host.status, "", "", "", "", "", "", ""])
            continue
        for port in host.ports:
            writer.writerow(
                [
                    host.address,
                    hostname,
                    host.status,
                    port.portid,
                    port.protocol,
                    port.state,
                    port.service.name or "",
                    port.service.product or "",
                    port.service.version or "",
                    port.service.extrainfo or "",
                ]
            )
    return buffer.getvalue()


def render(result: ScanResult, fmt: str, indent: int = 2) -> str:
    if fmt == "markdown":
        return scan_to_markdown(result)
    if fmt == "json":
        return scan_to_json(result, indent=indent)
    if fmt == "csv":
        return scan_to_csv(result)
    raise ValueError(f"Unknown format {fmt!r}; expected one of: {', '.join(_FORMATS)}")
