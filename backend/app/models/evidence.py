"""
SQLAlchemy model for collected evidence (raw_data_s3_path pattern,
cf. Phase 1 - Semaine 2, organisation des buckets S3).
"""
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ..core.database import Base
import uuid
from .data_source_type import DataSourceType



class EvidenceModel(Base):
    """SQLAlchemy model for evidence table"""
    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_data_source_type", "data_source_type"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False)
    case = relationship("InvestigationCaseModel", back_populates="evidence")

    data_source_type = Column(SQLEnum(DataSourceType), nullable=False)
    # Convention de nommage: evidence/{case_id}/{data_source_type}/{filename}
    raw_data_s3_path = Column(String(500), nullable=False)

    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Evidence id={self.id} case_id={self.case_id} type={self.data_source_type}>"

    def to_dict(self):
        return {
            "id": str(self.id),
            "case_id": str(self.case_id),
            "data_source_type": self.data_source_type.value if self.data_source_type else None,
            "raw_data_s3_path": self.raw_data_s3_path,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
        }
