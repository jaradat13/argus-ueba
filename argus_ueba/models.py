from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    host: str
    user: str
    event_type: str
    action: str
    target: str = ""
    command: str = ""
    process: str = ""
    source_ip: str = ""
    raw: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str]:
        return (self.user, self.event_type, self.action)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "host": self.host,
            "user": self.user,
            "event_type": self.event_type,
            "action": self.action,
            "target": self.target,
            "command": self.command,
            "process": self.process,
            "source_ip": self.source_ip,
            "metadata": self.metadata,
            "raw": self.raw,
        }


@dataclass(frozen=True)
class Finding:
    event: Event
    score: int
    reasons: list[str]
    mitre_tags: list[str]

    @property
    def severity(self) -> str:
        if self.score >= 80:
            return "high"
        if self.score >= 50:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "reasons": self.reasons,
            "mitre_tags": self.mitre_tags,
            "event": self.event.to_dict(),
        }
