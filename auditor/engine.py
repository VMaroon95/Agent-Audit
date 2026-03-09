"""
Core Auditor Engine — Passive Behavioral Monitoring for AI Agents.

Captures tool calls, file access, network activity, and system operations
from autonomous agents (Codex, Claude Code, local OS-level agents) and
produces a scored, tamper-evident audit trail.
"""

import json
import time
import hashlib
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from pathlib import Path

from .policy import PolicyEngine, PolicyViolation
from .scorer import RiskScorer, RiskLevel


@dataclass
class AuditEvent:
    """Single auditable action performed by an agent."""
    event_id: str
    timestamp: float
    agent_id: str
    session_id: str
    action_type: str
    target: str
    metadata: dict
    risk_level: RiskLevel
    risk_score: int
    violations: list
    integrity_hash: str
    parent_event_id: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class ActionType(str, Enum):
    """Categorized agent actions."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    EXEC_COMMAND = "exec_command"
    NETWORK_REQUEST = "network_request"
    ENV_ACCESS = "env_access"
    TOOL_CALL = "tool_call"
    SECRET_ACCESS = "secret_access"
    PERMISSION_CHANGE = "permission_change"
    PROCESS_SPAWN = "process_spawn"
    UNKNOWN = "unknown"


class AgentAuditor:
    """
    Behavioral Audit Engine for autonomous AI agents.

    Monitors agent actions in real-time, evaluates them against configurable
    security policies, scores risk using multi-factor heuristics, and produces
    a tamper-evident audit log suitable for forensic analysis and C-suite
    risk dashboards.
    """

    def __init__(self, policy_path: Optional[str] = None, output_dir: str = "./audit_logs"):
        self.policy_engine = PolicyEngine(policy_path)
        self.risk_scorer = RiskScorer()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._chain_hash = hashlib.sha256(b"genesis").hexdigest()
        self._event_count = 0
        self._session_events: list[AuditEvent] = []

    def audit(
        self,
        agent_id: str,
        session_id: str,
        action_type: str,
        target: str,
        metadata: Optional[dict] = None,
        parent_event_id: Optional[str] = None,
    ) -> AuditEvent:
        """
        Audit a single agent action.

        Returns an AuditEvent with risk scoring, policy violations,
        and a chained integrity hash for tamper detection.
        """
        metadata = metadata or {}

        # Check policy violations
        violations = self.policy_engine.evaluate(action_type, target, metadata)

        # Calculate risk score
        risk_score, risk_level = self.risk_scorer.score(
            action_type=action_type,
            target=target,
            metadata=metadata,
            violations=violations,
        )

        # Build integrity chain (each event hash includes the previous)
        event_id = str(uuid.uuid4())
        raw = f"{self._chain_hash}:{event_id}:{agent_id}:{action_type}:{target}:{json.dumps(metadata, sort_keys=True, default=str)}"
        integrity_hash = hashlib.sha256(raw.encode()).hexdigest()
        self._chain_hash = integrity_hash

        event = AuditEvent(
            event_id=event_id,
            timestamp=time.time(),
            agent_id=agent_id,
            session_id=session_id,
            action_type=action_type,
            target=target,
            metadata=metadata,
            risk_level=risk_level,
            risk_score=risk_score,
            violations=[v.to_dict() for v in violations],
            integrity_hash=integrity_hash,
            parent_event_id=parent_event_id,
        )

        self._event_count += 1
        self._session_events.append(event)
        self._write_event(event)

        return event

    def get_session_summary(self, session_id: Optional[str] = None) -> dict:
        """Generate a risk summary for the current or specified session."""
        events = self._session_events
        if session_id:
            events = [e for e in events if e.session_id == session_id]

        if not events:
            return {"total_events": 0, "risk_distribution": {}, "top_violations": []}

        risk_dist = {}
        violation_counts: dict[str, int] = {}
        for e in events:
            level = e.risk_level.value
            risk_dist[level] = risk_dist.get(level, 0) + 1
            for v in e.violations:
                rule = v.get("rule", "unknown")
                violation_counts[rule] = violation_counts.get(rule, 0) + 1

        top_violations = sorted(violation_counts.items(), key=lambda x: -x[1])[:10]

        return {
            "total_events": len(events),
            "risk_distribution": risk_dist,
            "highest_risk_score": max(e.risk_score for e in events),
            "red_events": risk_dist.get("RED", 0),
            "amber_events": risk_dist.get("AMBER", 0),
            "green_events": risk_dist.get("GREEN", 0),
            "top_violations": [{"rule": r, "count": c} for r, c in top_violations],
            "chain_intact": self.verify_chain(),
        }

    def verify_chain(self) -> bool:
        """Verify the integrity chain has not been tampered with."""
        check_hash = hashlib.sha256(b"genesis").hexdigest()
        for event in self._session_events:
            raw = (
                f"{check_hash}:{event.event_id}:{event.agent_id}:{event.action_type}:"
                f"{event.target}:{json.dumps(event.metadata, sort_keys=True, default=str)}"
            )
            expected = hashlib.sha256(raw.encode()).hexdigest()
            if expected != event.integrity_hash:
                return False
            check_hash = expected
        return True

    def _write_event(self, event: AuditEvent):
        """Append event to the JSONL audit log."""
        log_file = self.output_dir / f"audit_{event.session_id}.jsonl"
        with open(log_file, "a") as f:
            f.write(event.to_json() + "\n")
