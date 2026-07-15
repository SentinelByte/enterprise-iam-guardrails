"""Shared finding/severity model used by every check in this package."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    """Risk severity, ordered low to critical."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass(frozen=True, slots=True)
class Finding:
    """A single, actionable result produced by a check.

    Every finding carries a remediation so the tool reads as guidance,
    not just a list of complaints.
    """

    check_id: str
    resource: str
    severity: Severity
    message: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "resource": self.resource,
            "severity": self.severity.value,
            "message": self.message,
            "remediation": self.remediation,
        }


def worst_severity(findings: list[Finding]) -> Severity | None:
    """Return the highest-ranked severity among findings, or None if empty."""
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: s.rank)
