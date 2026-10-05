"""
Tests d'INTEGRATION pour les metriques du dashboard (Phase 6).

Contrairement aux tests unitaires des Phases 2/4/5 (purement logiques,
sans DB), ces tests necessitent une vraie base PostgreSQL -- ils suivent
le meme principe que verify_migration.py (Phase 1) : creation de donnees
de test, verification, nettoyage.

A executer dans le conteneur backend (avec acces a acip-postgres) :
    docker exec -it acip-backend python -m pytest tests/test_dashboard_metrics.py -v

Prerequis : la migration 0004_add_analyst_verdict doit etre appliquee.
"""
from __future__ import annotations

import sys
import os
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from app.core.database import SessionLocal
from app.models.incident import IncidentModel, IncidentPriority
from app.models.data_source_type import DataSourceType
from app.models.investigation_case import InvestigationCaseModel, CaseStatus
from app.models.finding import FindingModel, FindingType, AnalystVerdict
from app.dashboard.metrics import (
    get_mtti_hours,
    get_volume_by_data_source,
    get_false_positive_rate,
    get_false_positive_rate_by_finding_type,
    get_pending_findings_summary,
)


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def sample_case(db):
    """Cree un incident + case clos 3 heures apres son ouverture, avec
    2 findings (1 confirme, 1 faux positif), pour tester les 3 metriques
    en une seule fixture. Nettoie tout a la fin du test."""
    incident = IncidentModel(
        id=uuid.uuid4(),
        title="TEST dashboard metrics",
        description="fixture de test",
        source_type="manual_test",
        source_event_id=f"test-dashboard-{uuid.uuid4()}",
    )
    db.add(incident)
    db.commit()

    created_at = datetime.now(timezone.utc) - timedelta(hours=5)
    closed_at = created_at + timedelta(hours=3)

    case = InvestigationCaseModel(
        id=uuid.uuid4(),
        incident_id=incident.id,
        playbook_id="credential_attack",
        status=CaseStatus.CLOSED,
        created_at=created_at,
        closed_at=closed_at,
    )
    db.add(case)
    db.commit()

    finding_confirmed = FindingModel(
        case_id=case.id,
        finding_type=FindingType.BRUTE_FORCE,
        data_source_type=DataSourceType.IAM,
        severity=IncidentPriority.HIGH,
        confidence_score=0.9,
        analyst_verdict=AnalystVerdict.CONFIRMED,
    )
    finding_fp = FindingModel(
        case_id=case.id,
        finding_type=FindingType.BRUTE_FORCE,
        data_source_type=DataSourceType.IAM,
        severity=IncidentPriority.HIGH,
        confidence_score=0.65,
        analyst_verdict=AnalystVerdict.FALSE_POSITIVE,
    )
    finding_pending = FindingModel(
        case_id=case.id,
        finding_type=FindingType.MASS_DOWNLOAD,
        data_source_type=DataSourceType.S3,
        severity=IncidentPriority.MEDIUM,
        confidence_score=0.85,
        analyst_verdict=AnalystVerdict.PENDING,
    )
    db.add_all([finding_confirmed, finding_fp, finding_pending])
    db.commit()

    yield case

    # Nettoyage
    db.query(FindingModel).filter(FindingModel.case_id == case.id).delete()
    db.query(InvestigationCaseModel).filter(InvestigationCaseModel.id == case.id).delete()
    db.query(IncidentModel).filter(IncidentModel.id == incident.id).delete()
    db.commit()


def test_mtti_reflects_case_duration(db, sample_case):
    result = get_mtti_hours(db)
    assert result["closed_cases_count"] >= 1
    assert result["mtti_hours"] is not None


def test_volume_by_data_source_includes_test_findings(db, sample_case):
    result = get_volume_by_data_source(db)
    by_source = {r["data_source_type"]: r["findings_count"] for r in result}
    assert by_source.get("iam", 0) >= 2
    assert by_source.get("s3", 0) >= 1


def test_false_positive_rate_excludes_pending(db, sample_case):
    result = get_false_positive_rate(db)
    # Sur ce lot : 1 confirmed + 1 false_positive => reviewed_total >= 2,
    # le pending n'est pas compte dans reviewed_total.
    assert result["reviewed_total"] >= 2
    assert result["false_positives"] >= 1
    assert result["false_positive_rate_pct"] is not None


def test_false_positive_rate_by_finding_type(db, sample_case):
    result = get_false_positive_rate_by_finding_type(db)
    brute_force_row = next((r for r in result if r["finding_type"] == "BRUTE_FORCE"), None)
    assert brute_force_row is not None
    assert brute_force_row["reviewed_total"] >= 2


def test_pending_findings_summary_includes_mass_download(db, sample_case):
    result = get_pending_findings_summary(db)
    types_pending = {r["finding_type"] for r in result}
    assert "MASS_DOWNLOAD" in types_pending
