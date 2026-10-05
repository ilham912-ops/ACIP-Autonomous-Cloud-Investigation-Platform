"""
SQLAlchemy model for findings produced by detection rules
(cf. Phase 2 - detect_brute_force, detect_mass_download, etc.)
"""
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ..core.database import Base
import uuid
import enum

from .data_source_type import DataSourceType
from app.domain.models.incident import IncidentPriority


class FindingType(str, enum.Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    MASS_DOWNLOAD = "MASS_DOWNLOAD"
    UNUSUAL_EGRESS = "UNUSUAL_EGRESS"
    SECURITY_GROUP_OPEN = "SECURITY_GROUP_OPEN"
    CRYPTOMINING = "CRYPTOMINING"
    PORT_SCAN = "PORT_SCAN"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SUSPICIOUS_CONNECTION = "SUSPICIOUS_CONNECTION"
    ANOMALOUS_LOGIN = "ANOMALOUS_LOGIN"

class AnalystVerdict(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class FindingModel(Base):
    """SQLAlchemy model for findings table"""
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_type_severity", "finding_type", "severity"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False)
    case = relationship("InvestigationCaseModel", back_populates="findings")

    finding_type = Column(SQLEnum(FindingType), nullable=False)
    data_source_type = Column(SQLEnum(DataSourceType), nullable=False)
    severity = Column(SQLEnum(IncidentPriority), nullable=False)
    confidence_score = Column(Float, nullable=True)  # 0.0 - 1.0

    analyst_verdict = Column(
    SQLEnum(
        AnalystVerdict,
        name="analystverdict",
        values_callable=lambda enum_class: [member.value for member in enum_class],
    ),
    nullable=False,
    default=AnalystVerdict.PENDING,
)

    verdict_updated_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Finding id={self.id} type={self.finding_type}>"

    def to_dict(self):
        return {
            "id": str(self.id),
            "case_id": str(self.case_id),
            "finding_type": (
                self.finding_type.value
                if self.finding_type
                else None
            ),
            "data_source_type": (
                self.data_source_type.value
                if self.data_source_type
                else None
            ),
            "severity": (
                self.severity.value
                if self.severity
                else None
            ),
            "confidence_score": self.confidence_score,
            "analyst_verdict": (
                self.analyst_verdict.value
                if self.analyst_verdict
                else None
            ),
            "verdict_updated_at": (
                self.verdict_updated_at.isoformat()
                if self.verdict_updated_at
                else None
            ),
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
        }