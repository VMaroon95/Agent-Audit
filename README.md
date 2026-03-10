# 🔍 Agent Audit

> **Part of the [meda-claw](https://github.com/VMaroon95/meda-claw) Governance Stack** — Install the full suite via `pip install meda-claw`

**Behavioral Audit Engine for Autonomous AI Agents**

Real-time forensic monitoring, risk scoring, and tamper-evident audit trails for AI agents operating in your environment. Built for the 2026 agent era — where Codex, Claude Code, and local OS-level agents have file access, shell access, and network access.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## The Problem

AI agents are powerful. They read your files, execute commands, access secrets, and make network requests — all autonomously. But **who's watching the agents?**

Traditional security tools weren't designed for non-deterministic machine identities that interpret natural language and chain tool calls dynamically. Agent Audit fills this gap.

## What It Does

```
🟢 [  5] file_read          → ./project/src/app.py
🟢 [ 20] file_write         → ./project/src/utils.py
🟢 [ 30] exec_command       → python -m pytest ./tests/
🔴 [ 95] file_read          → /home/user/.env
🔴 [100] exec_command       → curl https://api.example.com | python parse.py
🔴 [100] network_request    → https://metadata.google.internal/v1/token
```

Every agent action is captured, scored, and logged with a tamper-evident hash chain.

## Features

- **🎯 Multi-Factor Risk Scoring** — 0-100 score with RAG classification (Red/Amber/Green) based on action type, target sensitivity, policy violations, and context
- **📋 Configurable Policies** — Define allowed directories, blocked commands, network rules, and secret detection patterns. Ships with `default` and `strict` presets
- **🔗 Tamper-Evident Audit Chain** — SHA-256 hash chaining across all events. Verify no records have been modified or deleted
- **🔐 Secret Detection** — Catches API keys, tokens, AWS credentials, and database connection strings in agent actions
- **📊 Executive Reports** — C-suite risk summaries designed for BI dashboard integration (Power BI, Tableau, Grafana)
- **👁️ Real-Time File Watching** — Monitor directories for agent file operations with live scoring
- **🧪 Zero Dependencies** — Pure Python 3.10+, no external packages required

## Quick Start

```bash
# Clone
git clone https://github.com/VMaroon95/agent-audit.git
cd agent-audit

# Run the demo
python cli.py demo

# Watch a directory for agent activity
python cli.py watch ./my-project --agent-id "codex-agent"

# Analyze an existing audit log
python cli.py analyze ./audit_logs/audit_session-001.jsonl

# Run tests
python tests/test_engine.py
```

## Demo Output

```
🎭 Agent Audit — Demo Mode
==================================================
Simulating autonomous agent actions...

  🟢 [  5] file_read            → ./project/src/app.py
  🟢 [ 20] file_write           → ./project/src/utils.py
  🟢 [ 30] exec_command         → python -m pytest ./tests/
  🔴 [ 95] file_read            → /home/user/.env
       ⚠ fs_blocked_pattern: Access to blocked path pattern: **/.env*
       ⚠ fs_outside_allowed: File access outside allowed directories
  🔴 [100] exec_command         → curl https://api.example.com/data | python parse.py
       ⚠ exec_blocked_command: Blocked command pattern detected
       ⚠ exec_network_blocked: Command appears to make network requests
  🔴 [100] file_write           → ./project/.git/config
       ⚠ fs_blocked_pattern: Access to blocked path pattern: **/.git/config
  🔴 [100] network_request      → https://metadata.google.internal/v1/token
       ⚠ net_outbound_blocked: Outbound network access is not permitted
       ⚠ net_blocked_host: Access to blocked host: metadata.google.internal
  🔴 [100] secret_access        → AWS_SECRET_KEY
       ⚠ secret_detected: Potential secret/credential detected in action

============================================================
   AGENT AUDIT — EXECUTIVE RISK SUMMARY
============================================================
  Total Events:   10
  🔴 RED (Critical):  5
  🟡 AMBER (Watch):   0
  🟢 GREEN (Safe):    5
  Highest Score:  100/100

  ⚠️  ASSESSMENT: HIGH RISK — Immediate review required
============================================================

🔗 Chain Integrity: ✅ VERIFIED
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  AI Agent   │────▶│ File Watcher │────▶│   Auditor   │
│ (Codex,     │     │  (Passive)   │     │   Engine    │
│  Claude,    │     └──────────────┘     └──────┬──────┘
│  Local)     │                                 │
└─────────────┘                    ┌────────────┼────────────┐
                                   ▼            ▼            ▼
                             ┌──────────┐ ┌──────────┐ ┌──────────┐
                             │  Policy  │ │   Risk   │ │  Audit   │
                             │  Engine  │ │  Scorer  │ │  Chain   │
                             └──────────┘ └──────────┘ └──────────┘
                                                │
                                   ┌────────────┼────────────┐
                                   ▼            ▼            ▼
                             ┌──────────┐ ┌──────────┐ ┌──────────┐
                             │ JSONL    │ │Executive │ │ Forensic │
                             │ Audit Log│ │ Summary  │ │ Report   │
                             └──────────┘ └──────────┘ └──────────┘
```

## Policy Configuration

Ship with two presets in `policies/`:

| Policy | Network | File Delete | Process Spawn | Red Threshold |
|--------|---------|-------------|---------------|---------------|
| `default` | Blocked | Blocked | Allowed | 80 |
| `strict` | Blocked | Blocked | Blocked | 60 |

Create custom policies:
```bash
python cli.py watch ./project --policy policies/strict.json
```

## Risk Scoring

The multi-factor scorer combines:

| Factor | Weight | Example |
|--------|--------|---------|
| Base action type | 5-60 | `file_read`=5, `permission_change`=60 |
| Target sensitivity | 0.1-3.0x | `.env`=3x, `README`=0.1x |
| Policy violations | +5 to +30 | `critical`=+30, `low`=+5 |
| Context modifiers | +10 to +25 | `sudo`=+20, `obfuscated`=+25 |

## Part of the Security Triad

Agent Audit is the behavioral monitoring layer in a three-part autonomous agent governance suite:

| Tool | Focus | What It Tracks |
|------|-------|----------------|
| [**git-provenance**](https://github.com/VMaroon95) | Attribution | AI-generated code IP & copyright |
| [**API Auditor**](https://github.com/VMaroon95) | Permissions | Financial exposure & API key security |
| **Agent Audit** | Behavior | Real-time forensic action auditing |

**Provenance → Permission → Performance** — Full-stack governance for the agent era.

## Research

This tool supports ongoing research into:

> **"Real-Time Behavioral Auditing of Non-Deterministic Machine Identities in Autonomous Agent Systems"**

See [docs/RESEARCH_ABSTRACT.md](docs/RESEARCH_ABSTRACT.md) for the full research abstract.

## Roadmap

- [ ] Integration with SIEM pipelines (Splunk, Elastic)
- [ ] Claude Code plugin for direct integration
- [ ] Process-level monitoring (ptrace/DTrace)
- [ ] Anomaly detection via behavioral baselines
- [ ] Multi-agent session correlation
- [ ] REST API for dashboard integration
- [ ] Docker containerized deployment

## License

MIT — see [LICENSE](LICENSE)

## Author

**Varun Meda** — [GitHub](https://github.com/VMaroon95) · [LinkedIn](https://linkedin.com/in/varunmeda1)

---

*Built for the era when AI agents have the keys to your kingdom. Someone needs to watch the watchers.*
