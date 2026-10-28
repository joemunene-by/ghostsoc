"""The one finding shape every adapter normalises into.

Each ghostsuite tool speaks its own JSON or SARIF. Nothing downstream wants to
know that, so adapters translate into Finding and the rest of ghostsoc only
ever sees this.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: object) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, (int, float)):
            return _from_score(float(value))
        name = str(value).strip().lower()
        return _ALIASES.get(name, cls.INFO)

    def __str__(self) -> str:
        return self.name


_ALIASES = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
    "none": Severity.INFO,
    "low": Severity.LOW,
    "warning": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
}


def _from_score(score: float) -> Severity:
    # CVSS-style 0-10 band, the common case when a tool hands us a number
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: Severity
    asset: str
    category: str = "unknown"
    description: str = ""
    evidence: dict = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)

    @property
    def fingerprint(self) -> str:
        """Identity of the thing found, stable across reruns.

        Tool plus rule plus asset, not evidence: the same leaked key seen twice
        is one finding, even if the line number drifted between scans.
        """
        seed = f"{self.tool}|{self.rule_id}|{self.asset}".lower()
        return hashlib.sha1(seed.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = str(self.severity)
        d["fingerprint"] = self.fingerprint
        return d
