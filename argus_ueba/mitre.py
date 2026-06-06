from __future__ import annotations

from .models import Event


def mitre_tags_for(event: Event) -> list[str]:
    tags: list[str] = []
    command = event.command.lower()
    target = event.target.lower()

    if event.action in {"ssh_login_success", "ssh_login_failed"}:
        tags.append("T1021.004 Remote Services: SSH")
    if event.action == "sudo_command" or "sudo" in command:
        tags.append("T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching")
    if event.event_type == "process":
        tags.append("T1059 Command and Scripting Interpreter")
    if any(tool in command for tool in ("curl", "wget", "scp", "rsync")):
        tags.append("T1105 Ingress Tool Transfer")
    if any(tool in command for tool in ("nc", "ncat", "socat")):
        tags.append("T1095 Non-Application Layer Protocol")
    if target.startswith(("/etc/shadow", "/etc/passwd", "/etc/sudoers")):
        tags.append("T1003 OS Credential Dumping")
    if target.startswith("/home/"):
        tags.append("T1005 Data from Local System")

    return list(dict.fromkeys(tags))
