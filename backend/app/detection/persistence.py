"""
Adaptateur de persistance : convertit les FindingResult produits par les
regles de detection en lignes FindingModel, et les enregistre en base.

Utilise les modeles valides en Phase 1 (backend/app/models/finding.py,
DataSourceType, IncidentPriority).
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.models.finding import FindingModel, FindingType
from app.models.finding import FindingModel, FindingType
from app.models.data_source_type import DataSourceType
from app.domain.models.incident import IncidentPriority
from .finding_result import FindingResult, Severity

# Mapping entre la Severity du module de detection et IncidentPriority
# utilisee par le schema RDS (cf. finding.py : severity = Column(SQLEnum(IncidentPriority))).
_SEVERITY_TO_PRIORITY = {
    Severity.LOW: IncidentPriority.LOW,
    Severity.MEDIUM: IncidentPriority.MEDIUM,
    Severity.HIGH: IncidentPriority.HIGH,
    Severity.CRITICAL: IncidentPriority.CRITICAL,
}


def persist_finding(db: Session, case_id: UUID, result: FindingResult) -> FindingModel:
    """Enregistre un FindingResult en base, rattache a un investigation_case
    existant (case_id doit deja exister, cf. Phase 1 - investigation_cases).
    """
    finding = FindingModel(
        case_id=case_id,
        finding_type=FindingType(result.finding_type),
        data_source_type=DataSourceType(result.data_source_type),
        severity=_SEVERITY_TO_PRIORITY[result.severity],
        confidence_score=result.confidence_score,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def persist_findings(db: Session, case_id: UUID, results: list[FindingResult]) -> list[FindingModel]:
    """Version batch de persist_finding, pour enregistrer tous les findings
    produits par un run de detection (ex: detect_brute_force + detect_privilege_escalation)
    en une seule transaction.
    """
    findings = []
    try:
        for result in results:
            finding = FindingModel(
                case_id=case_id,
                finding_type=FindingType(result.finding_type),
                data_source_type=DataSourceType(result.data_source_type),
                severity=_SEVERITY_TO_PRIORITY[result.severity],
                confidence_score=result.confidence_score,
            )
            db.add(finding)
            findings.append(finding)
        db.commit()
        for f in findings:
            db.refresh(f)
        return findings
    except Exception:
        db.rollback()
        raise
