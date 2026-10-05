

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, case
from sqlalchemy.orm import Session

from app.models.investigation_case import InvestigationCaseModel, CaseStatus
from app.models.finding import FindingModel, FindingType, AnalystVerdict


def get_mtti_hours(db: Session, since: datetime | None = None) -> dict[str, Any]:
    """Mean Time to Investigate, en heures, sur les cas clotures.
    Si `since` est fourni, ne considere que les cas ouverts apres cette date."""
    query = db.query(
        func.avg(
            func.extract("epoch", InvestigationCaseModel.closed_at - InvestigationCaseModel.created_at) / 3600.0
        ),
        func.count(InvestigationCaseModel.id),
    ).filter(InvestigationCaseModel.closed_at.isnot(None))

    if since is not None:
        query = query.filter(InvestigationCaseModel.created_at >= since)

    avg_hours, count = query.one()
    return {
        "mtti_hours": round(float(avg_hours), 2) if avg_hours is not None else None,
        "closed_cases_count": count,
    }


def get_mtti_by_playbook(db: Session) -> list[dict[str, Any]]:
    rows = (
        db.query(
            InvestigationCaseModel.playbook_id,
            func.avg(
                func.extract("epoch", InvestigationCaseModel.closed_at - InvestigationCaseModel.created_at) / 3600.0
            ),
            func.count(InvestigationCaseModel.id),
        )
        .filter(InvestigationCaseModel.closed_at.isnot(None))
        .group_by(InvestigationCaseModel.playbook_id)
        .order_by(func.avg(
            func.extract("epoch", InvestigationCaseModel.closed_at - InvestigationCaseModel.created_at)
        ).desc())
        .all()
    )
    return [
        {
            "playbook_id": playbook_id,
            "mtti_hours": round(float(avg_hours), 2) if avg_hours is not None else None,
            "closed_cases_count": count,
        }
        for playbook_id, avg_hours, count in rows
    ]


def get_volume_by_data_source(db: Session) -> list[dict[str, Any]]:
    rows = (
        db.query(FindingModel.data_source_type, func.count(FindingModel.id))
        .group_by(FindingModel.data_source_type)
        .order_by(func.count(FindingModel.id).desc())
        .all()
    )
    return [
        {"data_source_type": dst.value if dst else None, "findings_count": count}
        for dst, count in rows
    ]


def get_false_positive_rate(db: Session) -> dict[str, Any]:
    """Taux de faux positifs global, calcule uniquement sur les findings
    deja relus par un analyste (confirmed ou false_positive) -- les
    findings encore 'pending' ne biaisent pas le taux."""
    reviewed = case(
        (FindingModel.analyst_verdict.in_([AnalystVerdict.CONFIRMED, AnalystVerdict.FALSE_POSITIVE]), 1),
        else_=0,
    )
    is_fp = case((FindingModel.analyst_verdict == AnalystVerdict.FALSE_POSITIVE, 1), else_=0)

    false_positives, reviewed_total = db.query(func.sum(is_fp), func.sum(reviewed)).one()
    false_positives = false_positives or 0
    reviewed_total = reviewed_total or 0

    rate = round(100.0 * false_positives / reviewed_total, 2) if reviewed_total > 0 else None

    return {
        "false_positives": false_positives,
        "reviewed_total": reviewed_total,
        "false_positive_rate_pct": rate,
    }


def get_false_positive_rate_by_finding_type(db: Session) -> list[dict[str, Any]]:
    reviewed = case(
        (FindingModel.analyst_verdict.in_([AnalystVerdict.CONFIRMED, AnalystVerdict.FALSE_POSITIVE]), 1),
        else_=0,
    )
    is_fp = case((FindingModel.analyst_verdict == AnalystVerdict.FALSE_POSITIVE, 1), else_=0)

    rows = (
        db.query(
            FindingModel.finding_type,
            func.sum(is_fp),
            func.sum(reviewed),
        )
        .group_by(FindingModel.finding_type)
        .all()
    )

    results = []
    for finding_type, fp, reviewed_total in rows:
        fp = fp or 0
        reviewed_total = reviewed_total or 0
        rate = round(100.0 * fp / reviewed_total, 2) if reviewed_total > 0 else None
        results.append({
            "finding_type": finding_type.value if finding_type else None,
            "false_positives": fp,
            "reviewed_total": reviewed_total,
            "false_positive_rate_pct": rate,
        })
    return sorted(results, key=lambda r: (r["false_positive_rate_pct"] is None, -(r["false_positive_rate_pct"] or 0)))


def get_pending_findings_summary(db: Session) -> list[dict[str, Any]]:
    rows = (
        db.query(FindingModel.finding_type, FindingModel.severity, func.count(FindingModel.id))
        .filter(FindingModel.analyst_verdict == AnalystVerdict.PENDING)
        .group_by(FindingModel.finding_type, FindingModel.severity)
        .all()
    )
    return [
    {
        "finding_type": finding_type.value if finding_type else None,
        "severity": severity.value if severity else None,
        "pending_count": count,
    }
    for finding_type, severity, count in rows
]


def get_case_status_breakdown(db: Session) -> list[dict[str, Any]]:
    rows = (
        db.query(InvestigationCaseModel.status, func.count(InvestigationCaseModel.id))
        .group_by(InvestigationCaseModel.status)
        .all()
    )
    return [{"status": status.value if status else None, "case_count": count} for status, count in rows]


def get_dashboard_summary(db: Session) -> dict[str, Any]:
    """Point d'entree unique regroupant toutes les metriques -- pratique
    pour un seul appel API depuis le frontend React."""
    last_30_days = datetime.now(timezone.utc) - timedelta(days=30)
    return {
        "mtti": get_mtti_hours(db),
        "mtti_last_30_days": get_mtti_hours(db, since=last_30_days),
        "mtti_by_playbook": get_mtti_by_playbook(db),
        "volume_by_data_source": get_volume_by_data_source(db),
        "false_positive_rate": get_false_positive_rate(db),
        "false_positive_rate_by_type": get_false_positive_rate_by_finding_type(db),
        "pending_findings": get_pending_findings_summary(db),
        "case_status_breakdown": get_case_status_breakdown(db),
    }
