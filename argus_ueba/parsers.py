from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .models import Event

SYSLOG_TS = "%b %d %H:%M:%S"
AUTH_PREFIX_RE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<body>.*)$")
SSH_ACCEPT_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")
SSH_FAIL_RE = re.compile(r"Failed \S+ for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SUDO_RE = re.compile(r"sudo: \s*(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$")
AUDIT_RE = re.compile(r"^type=(?P<kind>\w+).*?msg=audit\((?P<epoch>\d+)(?:\.\d+)?:\d+\):(?P<body>.*)$")
QUOTED_FIELD_RE = re.compile(r'\b(?P<key>\w+)="(?P<value>[^"]*)"')
PLAIN_FIELD_RE = re.compile(r"\b(?P<key>\w+)=(?P<value>[^\s]+)")


def parse_files(paths: list[str], year: int | None = None) -> list[Event]:
    events: list[Event] = []
    for path in paths:
        events.extend(parse_file(Path(path), year=year))
    return sorted(events, key=lambda event: event.timestamp)


def parse_file(path: Path, year: int | None = None) -> list[Event]:
    events: list[Event] = []
    if not path.exists():
        raise FileNotFoundError(path)

    for line in path.read_text(errors="replace").splitlines():
        event = parse_line(line, year=year)
        if event is not None:
            events.append(event)
    return events


def parse_line(line: str, year: int | None = None) -> Event | None:
    return parse_auth_line(line, year=year) or parse_audit_line(line)


def parse_auth_line(line: str, year: int | None = None) -> Event | None:
    match = AUTH_PREFIX_RE.match(line)
    if not match:
        return None

    timestamp = _parse_syslog_timestamp(match.group("ts"), year)
    host = match.group("host")
    body = match.group("body")

    if ssh := SSH_ACCEPT_RE.search(body):
        return Event(
            timestamp=timestamp,
            host=host,
            user=ssh.group("user"),
            event_type="auth",
            action="ssh_login_success",
            source_ip=ssh.group("ip"),
            raw=line,
        )

    if ssh := SSH_FAIL_RE.search(body):
        return Event(
            timestamp=timestamp,
            host=host,
            user=ssh.group("user"),
            event_type="auth",
            action="ssh_login_failed",
            source_ip=ssh.group("ip"),
            raw=line,
        )

    if sudo := SUDO_RE.search(body):
        command = sudo.group("cmd").strip()
        return Event(
            timestamp=timestamp,
            host=host,
            user=sudo.group("user"),
            event_type="process",
            action="sudo_command",
            command=command,
            process=command.split(" ", 1)[0] if command else "sudo",
            raw=line,
        )

    return None


def parse_audit_line(line: str) -> Event | None:
    match = AUDIT_RE.match(line)
    if not match:
        return None

    fields = _audit_fields(match.group("body"))
    timestamp = datetime.fromtimestamp(int(match.group("epoch"))).astimezone()
    host = fields.get("node", fields.get("hostname", "localhost"))
    user = fields.get("acct") or fields.get("uid") or fields.get("auid") or "unknown"
    kind = match.group("kind")

    if kind in {"EXECVE", "SYSCALL"} and ("exe" in fields or "a0" in fields):
        command = _audit_command(fields)
        return Event(
            timestamp=timestamp,
            host=host,
            user=user,
            event_type="process",
            action="exec",
            command=command,
            process=fields.get("comm", fields.get("exe", "")),
            raw=line,
            metadata=fields,
        )

    if kind in {"PATH", "CWD"} and ("name" in fields or "cwd" in fields):
        target = fields.get("name", fields.get("cwd", ""))
        return Event(
            timestamp=timestamp,
            host=host,
            user=user,
            event_type="file",
            action="file_access",
            target=target,
            raw=line,
            metadata=fields,
        )

    return None


def _parse_syslog_timestamp(value: str, year: int | None) -> datetime:
    timestamp = datetime.strptime(f"{year or datetime.now().year} {value}", f"%Y {SYSLOG_TS}")
    return timestamp.astimezone()


def _audit_fields(body: str) -> dict[str, str]:
    fields = {match.group("key"): match.group("value") for match in QUOTED_FIELD_RE.finditer(body)}
    for match in PLAIN_FIELD_RE.finditer(body):
        fields.setdefault(match.group("key"), match.group("value"))
    return fields


def _audit_command(fields: dict[str, str]) -> str:
    argc = int(fields.get("argc", "0") or "0")
    args = [fields[f"a{index}"] for index in range(argc) if f"a{index}" in fields]
    if args:
        return " ".join(args)
    return fields.get("exe", fields.get("comm", ""))
