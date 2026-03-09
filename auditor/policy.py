"""
Policy Engine — Configurable security policies for agent behavior.

Policies define boundaries: allowed directories, blocked syscalls,
network restrictions, secret access rules, and escalation thresholds.
"""

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


@dataclass
class PolicyViolation:
    """A single policy violation detected during evaluation."""
    rule: str
    severity: str  # critical, high, medium, low
    description: str
    context: dict

    def to_dict(self) -> dict:
        return asdict(self)


# Default security policy
DEFAULT_POLICY = {
    "version": "1.0",
    "name": "default",
    "filesystem": {
        "allowed_dirs": ["./project", "./src", "./tests", "./docs"],
        "blocked_patterns": [
            "**/.env*", "**/credentials*", "**/.ssh/*", "**/.aws/*",
            "**/id_rsa*", "**/.gnupg/*", "**/secrets*", "**/.git/config",
        ],
        "allow_delete": False,
        "max_file_size_mb": 10,
    },
    "execution": {
        "blocked_commands": [
            "rm -rf /", "curl.*\\|.*sh", "wget.*\\|.*sh", "chmod 777",
            "sudo", "mkfs", "dd if=", ":(){ :|:& };:",
        ],
        "allow_network": False,
        "allow_process_spawn": True,
        "max_concurrent_processes": 5,
    },
    "network": {
        "allowed_hosts": [],
        "blocked_hosts": ["metadata.google.internal", "169.254.169.254"],
        "allow_outbound": False,
    },
    "secrets": {
        "detect_patterns": [
            r"(?i)(api[_-]?key|secret|token|password|credential)\s*[=:]\s*\S+",
            r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*",
            r"ghp_[a-zA-Z0-9]{36}",
            r"sk-[a-zA-Z0-9]{48}",
            r"AKIA[0-9A-Z]{16}",
        ],
        "block_exfiltration": True,
    },
    "escalation": {
        "red_threshold": 80,
        "amber_threshold": 40,
        "auto_block_on_red": False,
        "alert_webhook": None,
    },
}


class PolicyEngine:
    """Evaluates agent actions against a configurable security policy."""

    def __init__(self, policy_path: Optional[str] = None):
        if policy_path and Path(policy_path).exists():
            with open(policy_path) as f:
                self.policy = json.load(f)
        else:
            self.policy = DEFAULT_POLICY.copy()

    def evaluate(self, action_type: str, target: str, metadata: dict) -> list[PolicyViolation]:
        """Evaluate an action against all policy rules. Returns list of violations."""
        violations = []

        if action_type in ("file_read", "file_write", "file_delete"):
            violations.extend(self._check_filesystem(action_type, target, metadata))

        if action_type == "exec_command":
            violations.extend(self._check_execution(target, metadata))

        if action_type == "network_request":
            violations.extend(self._check_network(target, metadata))

        # Always check for secret leakage in metadata
        violations.extend(self._check_secrets(action_type, target, metadata))

        return violations

    def _check_filesystem(self, action: str, target: str, metadata: dict) -> list[PolicyViolation]:
        violations = []
        fs_policy = self.policy.get("filesystem", {})

        # Check blocked patterns
        for pattern in fs_policy.get("blocked_patterns", []):
            if self._glob_match(pattern, target):
                violations.append(PolicyViolation(
                    rule="fs_blocked_pattern",
                    severity="critical",
                    description=f"Access to blocked path pattern: {pattern}",
                    context={"target": target, "pattern": pattern},
                ))

        # Check allowed directories
        allowed = fs_policy.get("allowed_dirs", [])
        if allowed:
            in_allowed = any(
                target.startswith(d) or Path(target).is_relative_to(Path(d))
                for d in allowed
                if d
            )
            if not in_allowed:
                violations.append(PolicyViolation(
                    rule="fs_outside_allowed",
                    severity="high",
                    description=f"File access outside allowed directories",
                    context={"target": target, "allowed": allowed},
                ))

        # Check delete policy
        if action == "file_delete" and not fs_policy.get("allow_delete", False):
            violations.append(PolicyViolation(
                rule="fs_delete_blocked",
                severity="high",
                description="File deletion is not permitted by policy",
                context={"target": target},
            ))

        return violations

    def _check_execution(self, target: str, metadata: dict) -> list[PolicyViolation]:
        violations = []
        exec_policy = self.policy.get("execution", {})

        for pattern in exec_policy.get("blocked_commands", []):
            if re.search(pattern, target, re.IGNORECASE):
                violations.append(PolicyViolation(
                    rule="exec_blocked_command",
                    severity="critical",
                    description=f"Blocked command pattern detected: {pattern}",
                    context={"command": target, "pattern": pattern},
                ))

        if not exec_policy.get("allow_network", False):
            network_indicators = ["curl", "wget", "fetch", "http", "socket", "nc ", "netcat"]
            if any(ind in target.lower() for ind in network_indicators):
                violations.append(PolicyViolation(
                    rule="exec_network_blocked",
                    severity="high",
                    description="Command appears to make network requests (blocked by policy)",
                    context={"command": target},
                ))

        return violations

    def _check_network(self, target: str, metadata: dict) -> list[PolicyViolation]:
        violations = []
        net_policy = self.policy.get("network", {})

        if not net_policy.get("allow_outbound", False):
            violations.append(PolicyViolation(
                rule="net_outbound_blocked",
                severity="high",
                description="Outbound network access is not permitted",
                context={"target": target},
            ))

        for host in net_policy.get("blocked_hosts", []):
            if host in target:
                violations.append(PolicyViolation(
                    rule="net_blocked_host",
                    severity="critical",
                    description=f"Access to blocked host: {host}",
                    context={"target": target, "host": host},
                ))

        return violations

    def _check_secrets(self, action: str, target: str, metadata: dict) -> list[PolicyViolation]:
        violations = []
        secrets_policy = self.policy.get("secrets", {})
        content = json.dumps(metadata, default=str) + " " + target

        for pattern in secrets_policy.get("detect_patterns", []):
            if re.search(pattern, content):
                violations.append(PolicyViolation(
                    rule="secret_detected",
                    severity="critical",
                    description="Potential secret/credential detected in action",
                    context={"pattern": pattern, "action": action},
                ))

        return violations

    @staticmethod
    def _glob_match(pattern: str, path: str) -> bool:
        """Simple glob-style matching."""
        regex = pattern.replace("**", ".*").replace("*", "[^/]*")
        return bool(re.search(regex, path))
