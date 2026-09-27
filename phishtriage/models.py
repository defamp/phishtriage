"""Data models for PhishTriage."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        return {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1,
                RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}[self]

    @staticmethod
    def from_score(score: int) -> "RiskLevel":
        if score >= 12:
            return RiskLevel.CRITICAL
        if score >= 7:
            return RiskLevel.HIGH
        if score >= 3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


# Point weights per finding severity — summed into the overall risk score.
class Weight(int, Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 3
    HIGH = 5


@dataclass
class Finding:
    """A single phishing indicator detected in the message."""

    check: str
    title: str
    weight: int
    detail: str = ""
    evidence: List[str] = field(default_factory=list)

    def __post_init__(self):
        # Accept a Weight enum member but always store a plain int.
        self.weight = int(self.weight)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "title": self.title,
            "weight": self.weight,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class EmailMeta:
    from_header: Optional[str] = None
    from_addr: Optional[str] = None
    from_name: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    to: Optional[str] = None


@dataclass
class Report:
    source: str
    meta: EmailMeta
    findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)

    @property
    def verdict(self) -> RiskLevel:
        return RiskLevel.from_score(self.score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "verdict": self.verdict.value,
            "score": self.score,
            "from": self.meta.from_header,
            "subject": self.meta.subject,
            "findings": [f.to_dict() for f in self.findings],
        }
