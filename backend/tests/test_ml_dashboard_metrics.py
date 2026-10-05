"""
Test d'INTEGRATION pour les metriques ML du dashboard (necessite une vraie
base, meme principe que test_dashboard_metrics.py de la Phase 6).

Execution :
    docker exec -it acip-backend python -m pytest tests/test_ml_dashboard_metrics.py -v

Prerequis :
    - Migration 0005_add_ml_finding_type appliquee (ANOMALOUS_LOGIN existe)
    - finding.py contient bien ANOMALOUS_LOGIN dans FindingType
"""
from __future__ import annotations

import sys
import os
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from app.core.database import SessionLocal
from app.models.incident import IncidentModel, DataSourceType, IncidentPriority
from app.models.investigation_case import InvestigationCaseModel, CaseStatus
from app.models.finding import FindingModel, FindingType, AnalystVerdict
from app.dashboard.metrics import get_ml_anomaly_stats, get_ml_vs_rules_convergence


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def ml_and_rule_fixture(db):
    """Cree 2 cases :
    - case A : 1 finding ML (ANOMALOUS_LOGIN) + 1 finding regle (BRUTE_FORCE)
      -> doit compter comme 'convergence' (cases_flagged_by_both)
    - case B : 1 finding ML seul
      -> doit compter comme 'cases_flagged_by_ml_only'
    Nettoie tout a la fin.
    """
    created_incidents, created_cases, created_findings = [], [], []

    def _make_case(with_ml: bool, with_rule: bool, ml_confidence=0.82, ml_verdict=AnalystVerdict.PENDING):
        incident = IncidentModel(
            id=uuid.uuid4(), title="TEST ml dashboard metrics", description="fixture",
            source_type="manual_test", source_event_id=f"test-ml-dash-{uuid.uuid4()}",
        )
        db.add(incident)
        db.commit()
        created_incidents.append(incident)

        case = InvestigationCaseModel(
            id=uuid.uuid4(), incident_id=incident.id, playbook_id="credential_attack",
            status=CaseStatus.OPEN,
        )
        db.add(case)
        db.commit()
        created_cases.append(case)

        if with_ml:
            f = FindingModel(
                case_id=case.id, finding_type=FindingType.ANOMALOUS_LOGIN,
                data_source_type=DataSourceType.IAM, severity=IncidentPriority.HIGH,
                confidence_score=ml_confidence, analyst_verdict=ml_verdict,
            )
            db.add(f)
            created_findings.append(f)
        if with_rule:
            f = FindingModel(
                case_id=case.id, finding_type=FindingType.BRUTE_FORCE,
                data_source_type=DataSourceType.IAM, severity=IncidentPriority.HIGH,
                confidence_score=0.90, analyst_verdict=AnalystVerdict.PENDING,
            )
            db.add(f)
            created_findings.append(f)
        db.commit()
        return case

    case_both = _make_case(with_ml=True, with_rule=True, ml_confidence=0.90, ml_verdict=AnalystVerdict.CONFIRMED)
    case_ml_only = _make_case(with_ml=True, with_rule=False, ml_confidence=0.74)

    yield {"case_both": case_both, "case_ml_only": case_ml_only}

    for f in created_findings:
        db.query(FindingModel).filter(FindingModel.id == f.id).delete()
    for c in created_cases:
        db.query(InvestigationCaseModel).filter(InvestigationCaseModel.id == c.id).delete()
    for i in created_incidents:
        db.query(IncidentModel).filter(IncidentModel.id == i.id).delete()
    db.commit()


def test_ml_anomaly_stats_counts_findings(db, ml_and_rule_fixture):
    stats = get_ml_anomaly_stats(db)
    assert stats["total_anomalies_detected"] >= 2
    assert stats["model_status"] == "active"


def test_ml_anomaly_stats_average_confidence_is_computed(db, ml_and_rule_fixture):
    stats = get_ml_anomaly_stats(db)
    assert stats["average_confidence"] is not None
    assert 0.0 <= stats["average_confidence"] <= 1.0


def test_ml_precision_reflects_analyst_verdicts(db, ml_and_rule_fixture):
    stats = get_ml_anomaly_stats(db)
    # 1 finding ML confirme (case_both) sur nos donnees de test -> reviewed >= 1
    assert stats["reviewed_by_analyst"] >= 1
    assert stats["confirmed_by_analyst"] >= 1
    assert stats["precision_pct"] is not None


def test_convergence_detects_cases_flagged_by_both(db, ml_and_rule_fixture):
    convergence = get_ml_vs_rules_convergence(db)
    assert convergence["cases_flagged_by_both"] >= 1


def test_convergence_detects_ml_only_cases(db, ml_and_rule_fixture):
    convergence = get_ml_vs_rules_convergence(db)
    assert convergence["cases_flagged_by_ml_only"] >= 1
