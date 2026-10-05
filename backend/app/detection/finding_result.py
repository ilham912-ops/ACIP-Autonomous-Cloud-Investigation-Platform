"""
Structure de resultat emise par les regles de detection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FindingResult:
    finding_type: str
    data_source_type: str
    severity: Severity
    confidence_score: float

    evidence_event_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    scoring_method: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError(
                f"confidence_score doit etre entre 0.0 et 1.0, recu: {self.confidence_score}"
            )
