from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .models import Event, Finding
from .mitre import mitre_tags_for

SENSITIVE_PATHS = ("/etc/shadow", "/etc/sudoers", "/root/", "/var/log/auth", "/home/")
DANGEROUS_COMMANDS = ("nc", "ncat", "socat", "curl", "wget", "chmod", "chown", "useradd", "usermod")


@dataclass
class UserProfile:
    hours: Counter[int] = field(default_factory=Counter)
    source_ips: Counter[str] = field(default_factory=Counter)
    commands: Counter[str] = field(default_factory=Counter)
    paths: Counter[str] = field(default_factory=Counter)
    actions: Counter[str] = field(default_factory=Counter)


@dataclass
class Baseline:
    users: dict[str, UserProfile] = field(default_factory=dict)

    @classmethod
    def from_events(cls, events: list[Event]) -> "Baseline":
        profiles: dict[str, UserProfile] = defaultdict(UserProfile)
        for event in events:
            profile = profiles[event.user]
            profile.hours[event.timestamp.hour] += 1
            profile.actions[event.action] += 1
            if event.source_ip:
                profile.source_ips[event.source_ip] += 1
            if event.command:
                profile.commands[_command_name(event.command)] += 1
            if event.target:
                profile.paths[_path_bucket(event.target)] += 1
        return cls(users=dict(profiles))

    def evaluate(self, events: list[Event], threshold: int = 50) -> list[Finding]:
        findings = [finding for event in events if (finding := self.evaluate_event(event)).score >= threshold]
        return sorted(findings, key=lambda finding: (-finding.score, finding.event.timestamp))

    def evaluate_event(self, event: Event) -> Finding:
        profile = self.users.get(event.user)
        score = 0
        reasons: list[str] = []

        if profile is None:
            score += 45
            reasons.append(f"new user '{event.user}' not present in baseline")
        else:
            if event.timestamp.hour not in profile.hours:
                score += 25
                reasons.append(f"activity at unusual hour {event.timestamp.hour:02d}:00")
            if event.source_ip and event.source_ip not in profile.source_ips:
                score += 35
                reasons.append(f"new source IP {event.source_ip}")
            if event.command:
                command = _command_name(event.command)
                if command not in profile.commands:
                    score += 30
                    reasons.append(f"unusual command '{command}'")
            if event.target:
                bucket = _path_bucket(event.target)
                if bucket not in profile.paths:
                    score += 25
                    reasons.append(f"unusual file path '{event.target}'")
            if event.action not in profile.actions:
                score += 20
                reasons.append(f"unusual action '{event.action}'")

        command = _command_name(event.command)
        if event.timestamp.hour in {0, 1, 2, 3, 4, 5}:
            score += 10
            reasons.append("off-hours activity")
        if event.target and event.target.startswith(SENSITIVE_PATHS):
            score += 30
            reasons.append(f"sensitive path access '{event.target}'")
        if command in DANGEROUS_COMMANDS:
            score += 25
            reasons.append(f"dual-use command '{command}'")
        if event.action == "ssh_login_failed":
            score += 10
            reasons.append("failed authentication")

        return Finding(
            event=event,
            score=min(score, 100),
            reasons=reasons or ["matches baseline"],
            mitre_tags=mitre_tags_for(event),
        )


def _command_name(command: str) -> str:
    if not command:
        return ""
    return command.split(" ", 1)[0].rsplit("/", 1)[-1]


def _path_bucket(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 2:
        return "/" + "/".join(parts[:2])
    return path
