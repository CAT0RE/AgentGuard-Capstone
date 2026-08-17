from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple

from .models import Decision, Finding, RiskLevel


@dataclass
class MonitorPolicy:
    """Maps evidence into a risk score and an intervention decision."""

    log_threshold: float = 20.0
    verify_threshold: float = 38.0
    confirm_threshold: float = 58.0
    block_threshold: float = 78.0
    block_critical: bool = True

    def aggregate(self, findings: Iterable[Finding]) -> float:
        """Noisy-OR aggregation rewards corroborating, independent evidence."""
        residual = 1.0
        for finding in findings:
            probability = min(0.99, max(0.0, finding.contribution / 100.0))
            residual *= 1.0 - probability
        return round(100.0 * (1.0 - residual), 2)

    def decide(self, score: float, findings: Iterable[Finding]) -> Tuple[RiskLevel, Decision]:
        items = list(findings)
        if self.block_critical and any(item.critical and item.confidence >= 0.75 for item in items):
            return RiskLevel.CRITICAL, Decision.BLOCK
        if score >= self.block_threshold:
            return RiskLevel.CRITICAL, Decision.BLOCK
        if score >= self.confirm_threshold:
            return RiskLevel.HIGH, Decision.CONFIRM
        if score >= self.verify_threshold:
            return RiskLevel.MEDIUM, Decision.VERIFY
        if score >= self.log_threshold:
            return RiskLevel.LOW, Decision.LOG
        return RiskLevel.LOW, Decision.ALLOW

    def to_dict(self):
        return {
            "log_threshold": self.log_threshold,
            "verify_threshold": self.verify_threshold,
            "confirm_threshold": self.confirm_threshold,
            "block_threshold": self.block_threshold,
            "block_critical": self.block_critical,
        }


def profile_policy(name: str) -> MonitorPolicy:
    profiles = {
        "balanced": MonitorPolicy(),
        "strict": MonitorPolicy(15, 30, 48, 68, True),
        "permissive": MonitorPolicy(30, 48, 68, 88, True),
    }
    try:
        return profiles[name]
    except KeyError as exc:
        raise ValueError(f"Unknown policy profile: {name}") from exc

