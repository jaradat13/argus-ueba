# Argus UEBA-lite

Agentless insider-threat detection for small Linux environments. Argus reads SSH, sudo, auditd file-access, and process-execution logs, builds a local baseline of normal user behavior, scores anomalies, maps them to MITRE ATT&CK, and can ask a local Ollama model for a SOC-style summary.

## Quick Demo

```bash
python -m argus_ueba.cli \
  --baseline samples/baseline.log \
  --events samples/events.log \
  --threshold 50
```

JSON output:

```bash
python -m argus_ueba.cli \
  --baseline samples/baseline.log \
  --events samples/events.log \
  --format json
```

With Ollama:

```bash
ollama pull llama3.1
python -m argus_ueba.cli \
  --baseline samples/baseline.log \
  --events samples/events.log \
  --ollama-model llama3.1
```

## Inputs

Argus currently parses:

- SSH success and failed-login lines from syslog-style auth logs.
- `sudo` command lines from auth logs.
- auditd `PATH`, `CWD`, `EXECVE`, and `SYSCALL` style records.

On Ubuntu/Debian hosts, useful sources are usually:

- `/var/log/auth.log`
- `/var/log/audit/audit.log`

For a small network, collect logs centrally with syslog forwarding, SSH copy, or your SIEM/export pipeline, then pass the files into `--baseline` and `--events`.

## Detection Model

The baseline tracks each user's usual:

- Active hours.
- Source IPs.
- Commands.
- File path buckets.
- Event actions.

Events are scored for new users, unusual hours, new source IPs, unusual commands, sensitive file access, dual-use tools, failed authentication, and unseen action types.

## Notes

This is intentionally UEBA-lite: transparent heuristics plus optional local LLM summarization. It is suitable for demos, analyst triage, and small-lab experimentation, not as a replacement for full EDR/SIEM controls.
