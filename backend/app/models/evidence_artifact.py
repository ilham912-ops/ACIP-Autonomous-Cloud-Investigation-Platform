"""
Legacy/compatibility SQLAlchemy model for evidence_artifacts.

This model exists because incident.py keeps its existing
EvidenceArtifact relationship unchanged.
"""

import uuid

from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey,
    JSON,
    Boolean,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from ..core.database import Base


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )

    artifact_type = Column(String(50), nullable=False)
    source = Column(String(50), nullable=False)
    provider = Column(String(20), default="aws")
    region = Column(String(50))
    collector = Column(String(100), nullable=False)

    collected_at = Column(
        DateTime,
        server_default=func.now(),
    )

    content = Column(JSONB, nullable=False)
    artifact_metadata = Column("metadata", JSONB)

    hash = Column(String(128))
    hash_algorithm = Column(String(20), default="SHA-256")

    collection_status = Column(
        String(20),
        default="PENDING",
    )

    error_message = Column(Text)

    integrity_verified = Column(
        Boolean,
        default=False,
    )

    verified_at = Column(DateTime)

    created_at = Column(
        DateTime,
        server_default=func.now(),
    )

    updated_at = Column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )

    incident = relationship(
        "IncidentModel",
        back_populates="evidence_artifacts",
    )

    def __repr__(self):
        return f"<EvidenceArtifact id={self.id} incident_id={self.incident_id}>"