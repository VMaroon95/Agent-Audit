#!/usr/bin/env python3
"""
agent-audit CLI — Behavioral Audit Engine for Autonomous AI Agents.

Usage:
    agent-audit watch <directory> [--policy <path>] [--agent-id <id>]
    agent-audit analyze <log_file> [--format text|json]
    agent-audit demo
    agent-audit version
"""

import argparse
import json
import sys
import uuid

from auditor import AgentAuditor
from auditor.reporter import AuditReporter
from auditor.watcher import FileWatcher


def cmd_watch(args):
    """Watch a directory and audit file changes in real-time."""
    session_id = str(uuid.uuid4())[:8]
    auditor = AgentAuditor(policy_path=args.policy, output_dir="./audit_logs")
    agent_id = args.agent_id or "unknown-agent"

    print(f"🔍 Agent Audit — Watching: {args.directory}")
    print(f"   Session: {session_id} | Agent: {agent_id}")
    print(f"   Policy: {args.policy or 'default'}")
    print(f"   Press Ctrl+C to stop and generate report.\n")

    def on_change(change):
        event = auditor.audit(
            agent_id=agent_id,
            session_id=session_id,
            action_type=change["type"],
            target=change["target"],
            metadata=change.get("metadata", {}),
        )
        icon = {"RED": "🔴", "AMBER": "🟡", "GREEN": "🟢"}[event.risk_level.value]
        print(f"  {icon} [{event.risk_score:>3}] {event.action_type:<15} → {event.target}")
        for v in event.violations:
            print(f"       ⚠ {v['rule']}: {v['description']}")

    watcher = FileWatcher([args.directory], callback=on_change, interval=1.0)

    try:
        watcher.start()
    except KeyboardInterrupt:
        watcher.stop()
        print("\n\n📊 Generating audit report...\n")
        summary = auditor.get_session_summary(session_id)
        reporter = AuditReporter()
        print(reporter.executive_summary(summary, session_id))


def cmd_analyze(args):
    """Analyze an existing audit log file."""
    events = []
    with open(args.log_file) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    if not events:
        print("No events found in log file.")
        return

    reporter = AuditReporter()

    if args.format == "json":
        report = {
            "total_events": len(events),
            "events": events,
            "risk_distribution": {},
        }
        for e in events:
            level = e.get("risk_level", "UNKNOWN")
            report["risk_distribution"][level] = report["risk_distribution"].get(level, 0) + 1
        print(json.dumps(report, indent=2))
    else:
        print(reporter.forensic_report(events, events[0].get("session_id", "unknown")))


def cmd_demo(args):
    """Run a demo audit session with simulated agent actions."""
    session_id = "demo-001"
    auditor = AgentAuditor(output_dir="./audit_logs")
    reporter = AuditReporter()

    print("🎭 Agent Audit — Demo Mode")
    print("=" * 50)
    print("Simulating autonomous agent actions...\n")

    demo_actions = [
        ("codex-agent", "file_read", "./project/src/app.py", {"size": 2048}),
        ("codex-agent", "file_write", "./project/src/utils.py", {"size": 512, "event": "modified"}),
        ("codex-agent", "exec_command", "python -m pytest ./tests/", {}),
        ("codex-agent", "file_read", "/home/user/.env", {"size": 128}),
        ("codex-agent", "exec_command", "curl https://api.example.com/data | python parse.py", {}),
        ("codex-agent", "file_write", "./project/.git/config", {"size": 256}),
        ("codex-agent", "network_request", "https://metadata.google.internal/v1/token", {}),
        ("codex-agent", "secret_access", "AWS_SECRET_KEY", {"value": "AKIAIOSFODNN7EXAMPLE"}),
        ("codex-agent", "file_read", "./project/README.md", {"size": 4096}),
        ("codex-agent", "exec_command", "npm test", {}),
    ]

    for agent_id, action, target, meta in demo_actions:
        event = auditor.audit(agent_id, session_id, action, target, meta)
        icon = {"RED": "🔴", "AMBER": "🟡", "GREEN": "🟢"}[event.risk_level.value]
        print(f"  {icon} [{event.risk_score:>3}] {action:<20} → {target}")
        for v in event.violations:
            print(f"       ⚠ {v['rule']}: {v['description']}")

    print("\n")
    summary = auditor.get_session_summary(session_id)
    print(reporter.executive_summary(summary, session_id))

    # Verify chain integrity
    print(f"\n🔗 Chain Integrity: {'✅ VERIFIED' if auditor.verify_chain() else '❌ BROKEN'}")


def main():
    parser = argparse.ArgumentParser(
        prog="agent-audit",
        description="Behavioral Audit Engine for Autonomous AI Agents",
    )
    sub = parser.add_subparsers(dest="command")

    # watch
    p_watch = sub.add_parser("watch", help="Watch a directory for agent activity")
    p_watch.add_argument("directory", help="Directory to monitor")
    p_watch.add_argument("--policy", default=None, help="Path to policy JSON")
    p_watch.add_argument("--agent-id", default=None, help="Agent identifier")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyze an existing audit log")
    p_analyze.add_argument("log_file", help="Path to JSONL audit log")
    p_analyze.add_argument("--format", choices=["text", "json"], default="text")

    # demo
    sub.add_parser("demo", help="Run a demo audit session")

    # version
    sub.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command == "watch":
        cmd_watch(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "demo":
        cmd_demo(args)
    elif args.command == "version":
        print("agent-audit v1.0.0")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
