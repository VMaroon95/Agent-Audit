"""
Risk Scorer — Multi-factor behavioral risk scoring for agent actions.

Produces a 0-100 risk score and RAG (Red/Amber/Green) classification
using weighted heuristics across action type, target sensitivity,
policy violations, and temporal patterns.
"""

from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"


# Base risk weights by action type
ACTION_WEIGHTS = {
    "file_read": 5,
    "file_write": 20,
    "file_delete": 40,
    "exec_command": 30,
    "network_request": 35,
    "env_access": 15,
    "tool_call": 10,
    "secret_access": 50,
    "permission_change": 60,
    "process_spawn": 25,
    "unknown": 20,
}

# Sensitivity multipliers for target paths/patterns
SENSITIVE_TARGETS = {
    ".env": 3.0,
    ".ssh": 3.0,
    ".aws": 3.0,
    ".gnupg": 3.0,
    "credentials": 3.0,
    "secrets": 3.0,
    "id_rsa": 3.0,
    "/etc/passwd": 2.5,
    "/etc/shadow": 3.0,
    "node_modules": 0.5,
    ".git/config": 2.0,
    "package.json": 0.3,
    "README": 0.1,
}


class RiskScorer:
    """
    Multi-factor risk scoring engine.

    Combines:
    - Base action weight
    - Target sensitivity multiplier
    - Policy violation severity escalation
    - Metadata context modifiers
    """

    def __init__(self, red_threshold: int = 80, amber_threshold: int = 40):
        self.red_threshold = red_threshold
        self.amber_threshold = amber_threshold

    def score(
        self,
        action_type: str,
        target: str,
        metadata: dict,
        violations: list,
    ) -> tuple[int, RiskLevel]:
        """
        Calculate risk score (0-100) and RAG level.

        Returns:
            (score, RiskLevel)
        """
        # 1. Base weight from action type
        base = ACTION_WEIGHTS.get(action_type, 20)

        # 2. Target sensitivity multiplier
        multiplier = self._target_multiplier(target)
        score = int(base * multiplier)

        # 3. Violation escalation
        for v in violations:
            sev = v.severity if hasattr(v, "severity") else v.get("severity", "low")
            if sev == "critical":
                score += 30
            elif sev == "high":
                score += 20
            elif sev == "medium":
                score += 10
            else:
                score += 5

        # 4. Metadata modifiers
        if metadata.get("elevated") or metadata.get("sudo"):
            score += 20
        if metadata.get("piped"):
            score += 10
        if metadata.get("obfuscated"):
            score += 25

        # Clamp to 0-100
        score = max(0, min(100, score))

        # Classify
        if score >= self.red_threshold:
            level = RiskLevel.RED
        elif score >= self.amber_threshold:
            level = RiskLevel.AMBER
        else:
            level = RiskLevel.GREEN

        return score, level

    def _target_multiplier(self, target: str) -> float:
        """Find the highest sensitivity multiplier matching the target."""
        best = 1.0
        target_lower = target.lower()
        for pattern, mult in SENSITIVE_TARGETS.items():
            if pattern.lower() in target_lower:
                best = max(best, mult)
        return best
