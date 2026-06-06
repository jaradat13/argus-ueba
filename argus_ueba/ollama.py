from __future__ import annotations

import json
import urllib.error
import urllib.request

from .models import Finding


def summarize_with_ollama(findings: list[Finding], model: str, host: str = "http://localhost:11434") -> str:
    if not findings:
        return "No anomalous activity crossed the configured threshold."

    payload = {
        "model": model,
        "stream": False,
        "prompt": _prompt(findings),
    }
    request = urllib.request.Request(
        f"{host.rstrip('/')}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
            return body.get("response", "").strip() or fallback_summary(findings)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return fallback_summary(findings)


def fallback_summary(findings: list[Finding]) -> str:
    if not findings:
        return "No anomalous activity crossed the configured threshold."
    top = findings[0]
    return (
        f"{len(findings)} anomalous event(s) detected. Highest risk: {top.event.user} on "
        f"{top.event.host} scored {top.score}/{top.severity} for {', '.join(top.reasons)}."
    )


def _prompt(findings: list[Finding]) -> str:
    compact = [
        {
            "time": finding.event.timestamp.isoformat(),
            "user": finding.event.user,
            "host": finding.event.host,
            "action": finding.event.action,
            "target": finding.event.target,
            "command": finding.event.command,
            "score": finding.score,
            "severity": finding.severity,
            "reasons": finding.reasons,
            "mitre": finding.mitre_tags,
        }
        for finding in findings[:20]
    ]
    return (
        "You are a SOC analyst. Summarize these UEBA anomaly findings in concise natural language. "
        "Mention likely intent, highest risk user, affected host, and MITRE ATT&CK techniques. "
        f"Findings JSON: {json.dumps(compact)}"
    )
