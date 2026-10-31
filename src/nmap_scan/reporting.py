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
    """Escape a value placed in a Markdown table cell.

    Pipes would split the cell, newlines would split the row, and a
    backtick could open a code span that swallows the rest of the row.
    Backslashes are escaped first so an existing backslash is not
    mistaken for an escape introduced here.
    """
    return (
        value.replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("|", "\\|")
        .replace("\n", " ")
    )


def _escape_code_span(value: str) -> str:
    """Escape a value placed inside backticks in Markdown.

    A lone backtick opens a code span that swallows the rest of the
    line, so the rendered report no longer matches the data.
    Backslash-escaping the backtick keeps the data visible and the
    span closed.
    """
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("\n", " ")


def _fence_for(output: str) -> str:
    """A fence longer than any backtick run in the output.

    A fixed ``` fence is only safe if the output can never contain one.
    Growing the fence by one guarantees the block cannot be closed early.
    """
    longest = 0
    run = 0
    for ch in output:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def scan_to_markdown(result: ScanResult) -> str:
    lines: list[str] = ["# Nmap Scan Summary", ""]
    if result.nmap_version:
        lines.append(f"- **Nmap version:** `{_escape_code_span(result.nmap_version)}`")
    if result.args:
        lines.append(f"- **Scan command:** `{_escape_code_span(result.args)}`")
    if result.start_time:
        lines.append(f"- **Scan start:** `{_escape_code_span(result.start_time)}`")
    for info in result.scaninfo:
        detail = ", ".join(
            part
            for part in (
                f"type `{_escape_code_span(info.scan_type)}`" if info.scan_type else None,
                f"protocol `{_escape_code_span(info.protocol)}`" if info.protocol else None,
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
        heading = _escape_code_span(host.address) or "(unknown address)"
        if host.hostnames:
            heading += f" ({', '.join(_escape_code_span(h) for h in host.hostnames)})"
        lines.append(f"## {heading}")
        lines.append("")
        lines.append(f"- **Status:** `{_escape_code_span(host.status)}`")
        if host.addresses:
            lines.append(
                f"- **Addresses:** {', '.join(_escape_code_span(a) for a in host.addresses)}"
            )
        for extra in host.extraports:
            lines.append(f"- **{extra.count} ports:** `{_escape_code_span(extra.state)}`")
        lines.append("")
        if host.ports:
            lines.append("| Port | Protocol | State | Service | Version |")
            lines.append("| --- | --- | --- | --- | --- |")
            for port in host.ports:
                service = port.service.name or ""
                version = port.service.display()
                lines.append(
                    f"| `{port.portid}` | {_escape_table_cell(port.protocol)} "
                    f"| {_escape_table_cell(port.state)} | {_escape_table_cell(service)} "
                    f"| {_escape_table_cell(version)} |"
                )
            lines.append("")
            for port in host.ports:
                for script in port.scripts:
                    fence = _fence_for(script.output)
                    lines.append(
                        f"### Script `{_escape_code_span(script.script_id)}` "
                        f"on port {port.portid}"
                    )
                    lines.append("")
                    lines.append(fence)
                    lines.append(script.output)
                    lines.append(fence)
                    lines.append("")
        else:
            lines.append("No ports were reported for this host.")
            lines.append("")
        # Host scripts are independent of ports: a host can run them
        # with no open ports at all, so they render outside the
        # if/else above, not inside it.
        for script in host.host_scripts:
            fence = _fence_for(script.output)
            lines.append(f"### Host script `{_escape_code_span(script.script_id)}`")
            lines.append("")
            lines.append(fence)
            lines.append(script.output)
            lines.append(fence)
            lines.append("")
        for match in host.os_matches:
            accuracy = f" ({match.accuracy}% accuracy)" if match.accuracy is not None else ""
            lines.append(f"- **OS match:** {_escape_code_span(match.name)}{accuracy}")
        if host.os_matches:
            lines.append("")

    if result.runstats is not None:
        stats = result.runstats
        lines.append("## Run statistics")
        lines.append("")
        if stats.end_time:
            lines.append(f"- **Scan end:** `{_escape_code_span(stats.end_time)}`")
        if stats.elapsed_seconds is not None:
            lines.append(f"- **Duration:** `{stats.elapsed_seconds}` seconds")
        if stats.hosts_total is not None:
            lines.append(
                f"- **Hosts:** {stats.hosts_up} up, {stats.hosts_down} down, "
                f"{stats.hosts_total} total"
            )
        if stats.exit_status:
            lines.append(f"- **Exit status:** `{_escape_code_span(stats.exit_status)}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def scan_to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent) + "\n"


def scan_to_csv(result: ScanResult) -> str:
    """One row per port. Host scripts are intentionally not rows here:
    a CSV row is a port, and inventing a port column value for a host
    script would corrupt that meaning. Host scripts appear in Markdown
    and JSON, which can represent them without a port."""
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
