from __future__ import annotations

import json

from .models import Finding
from .ollama import fallback_summary


def json_report(findings: list[Finding], summary: str | None = None) -> str:
    return json.dumps(
        {
            "summary": summary or fallback_summary(findings),
            "findings": [finding.to_dict() for finding in findings],
        },
        indent=2,
    )


def timeline_report(findings: list[Finding], summary: str | None = None) -> str:
    lines = [summary or fallback_summary(findings), ""]
    for finding in sorted(findings, key=lambda item: item.event.timestamp):
        event = finding.event
        detail = event.command or event.target or event.source_ip
        lines.append(
            f"{event.timestamp.isoformat()} | {finding.severity.upper():6} | "
            f"{finding.score:3d} | {event.host} | {event.user} | {event.action} | {detail}"
        )
        lines.append(f"  reasons: {'; '.join(finding.reasons)}")
        if finding.mitre_tags:
            lines.append(f"  mitre: {', '.join(finding.mitre_tags)}")
    return "\n".join(lines).rstrip()
