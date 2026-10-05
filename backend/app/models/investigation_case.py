"""
SQLAlchemy model for investigation cases.

Ce modèle manquait dans les fichiers fournis. Il correspond au bloc
"Investigation Case" de l'architecture ACIP (cf. schéma RDS de la Phase 1).

IMPORTANT: incident.py n'est PAS modifié. Le lien vers IncidentModel est
donc porté ici, côté investigation_cases (incident_id), et la navigation
inverse (incident.investigation_cases) est ajoutée dynamiquement via
`backref` -- cela configure la relation au niveau du mapper SQLAlchemy
à l'exécution, sans toucher au fichier incident.py.
"""
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ..core.database import Base
import uuid
import enum


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class InvestigationCaseModel(Base):
    """SQLAlchemy model for investigation_cases table"""
    __tablename__ = "investigation_cases"
    __table_args__ = (
        Index("ix_cases_status", "status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Lien vers l'incident d'origine. incident.py reste inchangé: la
    # navigation incident.investigation_cases est fournie par le backref.
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True)
    incident = relationship("IncidentModel", backref="investigation_cases")

    # Playbook choisi par l'Investigation Orchestrator (cf. Phase 3)
    playbook_id = Column(String(50), nullable=True, index=True)
    status = Column(SQLEnum(CaseStatus), default=CaseStatus.OPEN)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    closed_at = Column(DateTime(timezone=True), nullable=True)

    evidence = relationship("EvidenceModel", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="case", cascade="all, delete-orphan")
    tasks = relationship("TaskModel", back_populates="case", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<InvestigationCase id={self.id} status={self.status} playbook={self.playbook_id}>"

    def to_dict(self):
        return {
            "id": str(self.id),
            "incident_id": str(self.incident_id),
            "playbook_id": self.playbook_id,
            "status": self.status.value if self.status else "open",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }
