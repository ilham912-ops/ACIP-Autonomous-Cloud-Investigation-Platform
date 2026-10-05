"""
Relie le modele Isolation Forest a l'architecture ACIP existante :
transforme les connexions signalees comme anormales en FindingResult,
compatibles avec persistence.py (Phase 2) et le reste du pipeline.

Necessite l'extension du schema (finding_type ANOMALOUS_LOGIN), cf.
migrations/0005_add_ml_finding_type.py et PATCH_finding_py_ml.txt.
"""
from __future__ import annotations

from typing import Iterable

import pandas as pd

from app.detection.cloudtrail_event import CloudTrailEvent
from app.detection.finding_result import FindingResult, Severity

from app.ml.features import extract_login_features
from app.ml.iam_anomaly_model import TrainedIAMModel, score_events, DEFAULT_MODEL_PATH

# Seuil de confidence_score au-dela duquel une anomalie ML est remontee
# comme Finding. Contrairement aux regles deterministes, ce seuil ne
# porte pas sur une variable metier directe (nombre de tentatives...)
# mais sur le score calibre du modele -- a ajuster lors de l'evaluation
# (cf. Cahier des charges section 4).
ML_CONFIDENCE_THRESHOLD = 0.60


def detect_anomalous_logins(
    events: Iterable[CloudTrailEvent],
    model_path=DEFAULT_MODEL_PATH,
) -> list[FindingResult]:
    """Score les connexions IAM d'un lot d'evenements avec le modele
    Isolation Forest entraine, et retourne un Finding pour chaque
    connexion jugee suffisamment anormale."""
    trained = TrainedIAMModel.load(model_path)

    features_df = extract_login_features(events)
    if features_df.empty:
        return []

    scored = score_events(trained, features_df)
    anomalies = scored[scored["confidence_score"] >= ML_CONFIDENCE_THRESHOLD]

    findings: list[FindingResult] = []
    for _, row in anomalies.iterrows():
        severity = Severity.CRITICAL if row["confidence_score"] >= 0.85 else Severity.HIGH

        findings.append(FindingResult(
            finding_type="ANOMALOUS_LOGIN",
            data_source_type="iam",
            severity=severity,
            confidence_score=float(row["confidence_score"]),
            evidence_event_ids=[row["event_id"]],
            details={
                "actor": row["actor"],
                "source_ip": row["source_ip"],
                "hour_of_day": int(row["hour_of_day"]),
                "is_new_ip": bool(row["is_new_ip"]),
                "seconds_since_last_login": float(row["seconds_since_last_login"]),
                "raw_anomaly_score": round(float(row["anomaly_score"]), 4),
            },
            scoring_method="modele_ml:isolation_forest(min_max_calibre_sur_train)",
        ))

    return findings
