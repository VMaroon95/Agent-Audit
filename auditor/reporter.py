"""
Audit Reporter — Generates human-readable and machine-parseable audit reports.

Produces executive summaries (C-suite BI feed), detailed forensic reports,
and structured JSON for dashboard integration.
"""

import json
import time
from pathlib import Path
from typing import Optional


class AuditReporter:
    """Generates audit reports from session event data."""

    def __init__(self, output_dir: str = "./audit_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def executive_summary(self, summary: dict, session_id: str = "unknown") -> str:
        """
        Generate a C-suite risk summary.

        Designed for BI dashboards and executive reporting:
        total events, risk distribution, top violations, chain integrity.
        """
        total = summary.get("total_events", 0)
        red = summary.get("red_events", 0)
        amber = summary.get("amber_events", 0)
        green = summary.get("green_events", 0)
        highest = summary.get("highest_risk_score", 0)
        chain = "✅ INTACT" if summary.get("chain_intact", False) else "❌ TAMPERED"

        lines = [
            "=" * 60,
            "   AGENT AUDIT — EXECUTIVE RISK SUMMARY",
            "=" * 60,
            f"  Session:        {session_id}",
            f"  Generated:      {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"  Audit Chain:    {chain}",
            "",
            f"  Total Events:   {total}",
            f"  🔴 RED (Critical):  {red}",
            f"  🟡 AMBER (Watch):   {amber}",
            f"  🟢 GREEN (Safe):    {green}",
            f"  Highest Score:  {highest}/100",
            "",
        ]

        top_v = summary.get("top_violations", [])
        if top_v:
            lines.append("  TOP VIOLATIONS:")
            for v in top_v[:5]:
                lines.append(f"    • {v['rule']}: {v['count']} occurrences")
        else:
            lines.append("  No violations detected.")

        lines.extend(["", "=" * 60])

        # Risk assessment
        if red > 0:
            lines.append("  ⚠️  ASSESSMENT: HIGH RISK — Immediate review required")
        elif amber > 0:
            lines.append("  ⚠️  ASSESSMENT: MODERATE RISK — Monitor closely")
        else:
            lines.append("  ✅ ASSESSMENT: LOW RISK — Agent operating within policy")

        lines.append("=" * 60)
        return "\n".join(lines)

    def forensic_report(self, events: list, session_id: str = "unknown") -> str:
        """Generate a detailed forensic event log."""
        lines = [
            f"FORENSIC AUDIT LOG — Session: {session_id}",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"Total Events: {len(events)}",
            "-" * 80,
        ]

        for e in events:
            d = e.to_dict() if hasattr(e, "to_dict") else e
            risk = d.get("risk_level", "UNKNOWN")
            icon = {"RED": "🔴", "AMBER": "🟡", "GREEN": "🟢"}.get(risk, "⚪")
            lines.append(
                f"{icon} [{d.get('risk_score', '?'):>3}] {d.get('action_type', '?'):<20} "
                f"→ {d.get('target', '?')}"
            )
            for v in d.get("violations", []):
                lines.append(f"       ⚠ {v.get('rule', '?')}: {v.get('description', '?')}")

        return "\n".join(lines)

    def save_json_report(self, summary: dict, events: list, session_id: str = "unknown") -> str:
        """Save structured JSON report for dashboard integration."""
        report = {
            "report_type": "agent_audit",
            "version": "1.0",
            "generated_at": time.time(),
            "session_id": session_id,
            "summary": summary,
            "events": [e.to_dict() if hasattr(e, "to_dict") else e for e in events],
        }
        path = self.output_dir / f"report_{session_id}_{int(time.time())}.json"
        with open(path, "w") as f:
            json.dumps(report, f, indent=2, default=str)
            f.write(json.dumps(report, indent=2, default=str))
        return str(path)
