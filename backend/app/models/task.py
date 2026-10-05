"""
SQLAlchemy model for tasks published by the Investigation Orchestrator
and consumed by the workers (AWS Collector, Correlation Worker, ...).
"""
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ..core.database import Base
import uuid
import enum


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class WorkerName(str, enum.Enum):
    AWS_COLLECTOR = "aws_collector"
    CORRELATION_WORKER = "correlation_worker"
    TIMELINE_WORKER = "timeline_worker"
    AI_ANALYSIS_WORKER = "ai_analysis_worker"


class TaskModel(Base):
    """SQLAlchemy model for tasks table"""
    __tablename__ = "tasks"
    __table_args__ = (
        Index("ix_tasks_status", "status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False)
    case = relationship("InvestigationCaseModel", back_populates="tasks")

    worker_name = Column(SQLEnum(WorkerName), nullable=False)
    status = Column(SQLEnum(TaskStatus), default=TaskStatus.PENDING)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<Task id={self.id} worker={self.worker_name} status={self.status}>"

    def to_dict(self):
        return {
            "id": str(self.id),
            "case_id": str(self.case_id),
            "worker_name": self.worker_name.value if self.worker_name else None,
            "status": self.status.value if self.status else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
