"""
Metriques specifiques au modele ML (Isolation Forest), a ajouter a
app/dashboard/metrics.py existant.

Ces fonctions manquaient : le dashboard affichait un bloc "ML Anomaly
Detection" purement descriptif (texte + tags de features), sans aucun
chiffre reel -- contrairement aux autres blocs (False Positive Rate,
MTTI...) qui interrogent la base.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.finding import FindingModel, FindingType, AnalystVerdict


def get_ml_anomaly_stats(db: Session, since_days: int = 7) -> dict[str, Any]:
    """Statistiques du modele Isolation Forest, sur la meme base que les
    autres cartes du dashboard (Phase 6)."""
    since = datetime.now(timezone.utc) - timedelta(days=since_days)

    base_query = db.query(FindingModel).filter(FindingModel.finding_type == FindingType.ANOMALOUS_LOGIN)

    total_count = base_query.count()
    recent_count = base_query.filter(FindingModel.created_at >= since).count()

    avg_confidence = (
        db.query(func.avg(FindingModel.confidence_score))
        .filter(FindingModel.finding_type == FindingType.ANOMALOUS_LOGIN)
        .scalar()
    )

    # Comparaison avec la verite terrain de l'analyste, comme pour le
    # taux de faux positifs classique (cf. get_false_positive_rate).
    reviewed = base_query.filter(
        FindingModel.analyst_verdict.in_([AnalystVerdict.CONFIRMED, AnalystVerdict.FALSE_POSITIVE])
    ).count()
    confirmed = base_query.filter(FindingModel.analyst_verdict == AnalystVerdict.CONFIRMED).count()

    precision_pct = round(100.0 * confirmed / reviewed, 1) if reviewed > 0 else None

    return {
        "total_anomalies_detected": total_count,
        "anomalies_last_7_days": recent_count,
        "average_confidence": round(float(avg_confidence), 3) if avg_confidence is not None else None,
        "reviewed_by_analyst": reviewed,
        "confirmed_by_analyst": confirmed,
        "precision_pct": precision_pct,  # None tant qu'aucun finding ML n'a ete relu
        "model_status": "active" if total_count > 0 else "no_detection_yet",
    }


def get_ml_vs_rules_convergence(db: Session) -> dict[str, Any]:
    """Compte les cas ou un meme acteur a ete signale A LA FOIS par une
    regle deterministe (BRUTE_FORCE, PRIVILEGE_ESCALATION) et par le
    modele ML (ANOMALOUS_LOGIN) -- signal de forte confiance a mettre en
    avant dans le dashboard (cf. run_iam_detection.py, meme logique)."""
    ml_findings = db.query(FindingModel).filter(FindingModel.finding_type == FindingType.ANOMALOUS_LOGIN).all()
    rule_findings = db.query(FindingModel).filter(
        FindingModel.finding_type.in_([FindingType.BRUTE_FORCE, FindingType.PRIVILEGE_ESCALATION])
    ).all()

    # Convergence approximee au niveau du CASE (meme dossier d'investigation),
    # a defaut de stocker l'acteur directement sur FindingModel.
    ml_cases = {f.case_id for f in ml_findings}
    rule_cases = {f.case_id for f in rule_findings}
    overlap = ml_cases & rule_cases

    return {
        "cases_flagged_by_ml_only": len(ml_cases - rule_cases),
        "cases_flagged_by_rules_only": len(rule_cases - ml_cases),
        "cases_flagged_by_both": len(overlap),
    }
