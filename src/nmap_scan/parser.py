"""Parse Nmap XML output into structured data.

The parser reports what the XML actually contains: every host, every port
state, and the service, OS, and script data Nmap recorded. It never invents
a scan type, a port count, or a plain-language conclusion — callers render
only what was parsed.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .errors import NmapParseError

_XMLPath = str | Path


@dataclass
class Service:
    """A service detected on one port.

    `name` is Nmap's service name (e.g. "ssh"). `product` and `version`
    come from version detection and are only present when the scan
    asked for them; their absence means "not detected", not "none".
    """

    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    cpe: list[str] = field(default_factory=list)

    def display(self) -> str:
        """Human-readable service description, omitting missing parts."""
        parts = [p for p in (self.product, self.version) if p]
        if self.extrainfo:
            parts.append(f"({self.extrainfo})")
        return " ".join(parts)


@dataclass
class ScriptResult:
    script_id: str
    output: str


@dataclass
class Port:
    portid: int
    protocol: str
    state: str
    reason: str | None = None
    service: Service = field(default_factory=Service)
    scripts: list[ScriptResult] = field(default_factory=list)


@dataclass
class ExtraPorts:
    state: str
    count: int


@dataclass
class OsClass:
    os_type: str | None = None
    vendor: str | None = None
    osfamily: str | None = None
    osgen: str | None = None
    accuracy: int | None = None


@dataclass
class OsMatch:
    name: str
    accuracy: int | None = None
    line: str | None = None
    classes: list[OsClass] = field(default_factory=list)


@dataclass
class TraceHop:
    ttl: int | None = None
    ipaddr: str | None = None
    rtt: str | None = None
    host: str | None = None


@dataclass
class Host:
    """One host from an Nmap scan.

    `address` is the primary address: the IPv4 address when the host
    has one, otherwise the first address Nmap reported. `addresses`
    keeps every address because a host can be reached over IPv4 and
    IPv6, and dropping the second one would make the report lie about
    which interface was scanned. `host_scripts` holds scripts that ran
    against the host itself (e.g. OS/SMB discovery), as distinct from
    the per-port scripts on each `Port`.
    """

    address: str
    addresses: list[str] = field(default_factory=list)
    address_types: dict[str, str] = field(default_factory=dict)
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"
    status_reason: str | None = None
    ports: list[Port] = field(default_factory=list)
    extraports: list[ExtraPorts] = field(default_factory=list)
    os_matches: list[OsMatch] = field(default_factory=list)
    host_scripts: list[ScriptResult] = field(default_factory=list)
    uptime_seconds: int | None = None
    trace: list[TraceHop] = field(default_factory=list)

    def open_ports(self) -> list[Port]:
        """Ports whose state is exactly "open".

        "open|filtered" is deliberately excluded: it is not an open
        port, it is an uncertain one, and counting it as open would
        overstate the result.
        """
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanInfo:
    scan_type: str | None = None
    protocol: str | None = None
    numservices: int | None = None
    services: str | None = None


@dataclass
class RunStats:
    end_time: str | None = None
    elapsed_seconds: float | None = None
    hosts_up: int | None = None
    hosts_down: int | None = None
    hosts_total: int | None = None
    exit_status: str | None = None


@dataclass
class ScanResult:
    """A complete, parsed Nmap run.

    Times are ISO-8601 UTC strings derived from Nmap's epoch attributes,
    not the locale-dependent `startstr` text — see `_time_string`.
    An empty `hosts` list is a valid result (e.g. a scan that found
    nothing), not an error; callers must not treat it as one.
    """

    nmap_version: str | None = None
    args: str | None = None
    start_time: str | None = None
    scaninfo: list[ScanInfo] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    runstats: RunStats | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def filter_result(
    result: ScanResult,
    *,
    open_only: bool = False,
    host: str | None = None,
) -> ScanResult:
    """Return a filtered copy of a parsed scan, for large scans.

    This is a pure function on the parsed result, so the library gets
    it for free and the CLI is a thin wrapper around it. Filtering
    never rewrites run statistics: they describe the original scan,
    and changing them to match the filter would make the report lie
    about what was scanned.
    """
    hosts = result.hosts
    if host is not None:
        hosts = [h for h in hosts if h.address == host or host in h.hostnames]
    if open_only:
        hosts = [
            Host(
                address=h.address,
                addresses=h.addresses,
                address_types=h.address_types,
                hostnames=h.hostnames,
                status=h.status,
                status_reason=h.status_reason,
                ports=h.open_ports(),
                extraports=h.extraports,
                os_matches=h.os_matches,
                host_scripts=h.host_scripts,
                uptime_seconds=h.uptime_seconds,
                trace=h.trace,
            )
            for h in hosts
        ]
    return ScanResult(
        nmap_version=result.nmap_version,
        args=result.args,
        start_time=result.start_time,
        scaninfo=result.scaninfo,
        hosts=hosts,
        runstats=result.runstats,
    )


def _int_or_none(value: str | None) -> int | None:
    """Parse an integer attribute, returning None instead of raising.

    Malformed numeric attributes in a real Nmap file are a data-quality
    problem, not a reason to discard the whole scan, so the parser
    degrades to None and the renderer omits the field.
    """
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _float_or_none(value: str | None) -> float | None:
    """Parse a float attribute, returning None instead of raising.

    See `_int_or_none` for why malformed numbers degrade to None.
    """
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _time_string(epoch: str | None, timestr: str | None) -> str | None:
    """Prefer the epoch attribute (unambiguous); fall back to the raw string."""
    epoch_int = _int_or_none(epoch)
    if epoch_int is not None:
        return datetime.fromtimestamp(epoch_int, tz=timezone.utc).isoformat()
    return timestr


def _parse_service(element: ET.Element | None) -> Service:
    if element is None:
        return Service()
    return Service(
        name=element.get("name"),
        product=element.get("product"),
        version=element.get("version"),
        extrainfo=element.get("extrainfo"),
        cpe=[cpe.text or "" for cpe in element.findall("cpe") if cpe.text],
    )


def _parse_host(element: ET.Element) -> Host:
    addresses: list[str] = []
    address_types: dict[str, str] = {}
    for address in element.findall("address"):
        addr = address.get("addr")
        if addr:
            addresses.append(addr)
            if address.get("addrtype"):
                address_types[addr] = address.get("addrtype", "")
    # Prefer an IPv4 address as the primary address, else the first listed.
    primary = next(
        (a for a in addresses if address_types.get(a) == "ipv4"),
        addresses[0] if addresses else "",
    )

    hostnames: list[str] = []
    hostnames_el = element.find("hostnames")
    if hostnames_el is not None:
        for hostname in hostnames_el.findall("hostname"):
            name = hostname.get("name")
            if name:
                hostnames.append(name)

    status_el = element.find("status")
    status = status_el.get("state", "unknown") if status_el is not None else "unknown"
    status_reason = status_el.get("reason") if status_el is not None else None

    ports: list[Port] = []
    extraports: list[ExtraPorts] = []
    ports_el = element.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            portid = _int_or_none(port_el.get("portid"))
            if portid is None:
                continue
            state_el = port_el.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            reason = state_el.get("reason") if state_el is not None else None
            scripts = [
                ScriptResult(script_id=s.get("id", ""), output=s.get("output", ""))
                for s in port_el.findall("script")
                if s.get("id")
            ]
            ports.append(
                Port(
                    portid=portid,
                    protocol=port_el.get("protocol", ""),
                    state=state,
                    reason=reason,
                    service=_parse_service(port_el.find("service")),
                    scripts=scripts,
                )
            )
        for extra in ports_el.findall("extraports"):
            count = _int_or_none(extra.get("count"))
            if extra.get("state") and count is not None:
                extraports.append(ExtraPorts(state=extra.get("state", ""), count=count))

    os_matches: list[OsMatch] = []
    os_el = element.find("os")
    if os_el is not None:
        for match_el in os_el.findall("osmatch"):
            classes = []
            for class_el in match_el.findall("osclass"):
                classes.append(
                    OsClass(
                        os_type=class_el.get("type"),
                        vendor=class_el.get("vendor"),
                        osfamily=class_el.get("osfamily"),
                        osgen=class_el.get("osgen"),
                        accuracy=_int_or_none(class_el.get("accuracy")),
                    )
                )
            os_matches.append(
                OsMatch(
                    name=match_el.get("name", ""),
                    accuracy=_int_or_none(match_el.get("accuracy")),
                    line=match_el.get("line"),
                    classes=classes,
                )
            )

    uptime_seconds = None
    uptime_el = element.find("uptime")
    if uptime_el is not None:
        uptime_seconds = _int_or_none(uptime_el.get("seconds"))

    # Host-level scripts (e.g. smb-os-discovery) live directly under
    # <host>, not under <ports>. They were dropped before v2.0.1;
    # dropping them made reports claim full script coverage they did
    # not have.
    host_scripts = [
        ScriptResult(script_id=s.get("id", ""), output=s.get("output", ""))
        for s in element.findall("script")
        if s.get("id")
    ]

    trace: list[TraceHop] = []
    trace_el = element.find("trace")
    if trace_el is not None:
        for hop_el in trace_el.findall("hop"):
            trace.append(
                TraceHop(
                    ttl=_int_or_none(hop_el.get("ttl")),
                    ipaddr=hop_el.get("ipaddr"),
                    rtt=hop_el.get("rtt"),
                    host=hop_el.get("host"),
                )
            )

    return Host(
        address=primary,
        addresses=addresses,
        address_types=address_types,
        hostnames=hostnames,
        status=status,
        status_reason=status_reason,
        ports=ports,
        extraports=extraports,
        os_matches=os_matches,
        host_scripts=host_scripts,
        uptime_seconds=uptime_seconds,
        trace=trace,
    )


def parse_root(root: ET.Element) -> ScanResult:
    if root.tag != "nmaprun":
        raise NmapParseError(f"Expected an <nmaprun> document, got <{root.tag}>.")

    scaninfo = [
        ScanInfo(
            scan_type=el.get("type"),
            protocol=el.get("protocol"),
            numservices=_int_or_none(el.get("numservices")),
            services=el.get("services"),
        )
        for el in root.findall("scaninfo")
    ]

    runstats = None
    runstats_el = root.find("runstats")
    if runstats_el is not None:
        finished = runstats_el.find("finished")
        hosts_el = runstats_el.find("hosts")
        runstats = RunStats(
            end_time=_time_string(
                finished.get("time") if finished is not None else None,
                finished.get("timestr") if finished is not None else None,
            ),
            elapsed_seconds=_float_or_none(
                finished.get("elapsed") if finished is not None else None
            ),
            hosts_up=_int_or_none(hosts_el.get("up")) if hosts_el is not None else None,
            hosts_down=_int_or_none(hosts_el.get("down")) if hosts_el is not None else None,
            hosts_total=_int_or_none(hosts_el.get("total")) if hosts_el is not None else None,
            exit_status=finished.get("exit") if finished is not None else None,
        )

    return ScanResult(
        nmap_version=root.get("version"),
        args=root.get("args"),
        start_time=_time_string(root.get("start"), root.get("startstr")),
        scaninfo=scaninfo,
        hosts=[_parse_host(host_el) for host_el in root.findall("host")],
        runstats=runstats,
    )


def parse_string(xml_text: str) -> ScanResult:
    """Parse Nmap XML text. Raises NmapParseError on malformed input."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapParseError(f"Could not parse Nmap XML: {exc}") from exc
    return parse_root(root)


def parse_file(path: _XMLPath) -> ScanResult:
    """Parse an Nmap XML file. Raises NmapParseError on missing/malformed input."""
    file_path = Path(path)
    try:
        tree = ET.parse(file_path)
    except FileNotFoundError as exc:
        raise NmapParseError(f"Nmap XML file not found: {file_path}") from exc
    except OSError as exc:
        raise NmapParseError(f"Could not read Nmap XML file {file_path}: {exc}") from exc
    except ET.ParseError as exc:
        raise NmapParseError(f"Could not parse Nmap XML file {file_path}: {exc}") from exc
    return parse_root(tree.getroot())


def parse_nmap_xml(xml_file_path: _XMLPath) -> ScanResult:
    """Deprecated alias for :func:`parse_file`.

    The name is backwards-compatible with v1; the return type is not —
    v1 returned a Markdown string, v2 returns a `ScanResult`. Use
    `parse_file` for new code. This alias will be removed in v3.0.0.
    """
    import warnings

    warnings.warn(
        "parse_nmap_xml is deprecated, use parse_file instead; "
        "it will be removed in v3.0.0.",
        DeprecationWarning,
        stacklevel=2,
    )
    return parse_file(xml_file_path)
