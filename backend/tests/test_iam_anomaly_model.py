"""
Tests du modele Isolation Forest IAM (features + comportement du modele).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detection.cloudtrail_event import CloudTrailEvent
from app.ml.features import extract_login_features, FEATURE_COLUMNS
from app.ml.iam_anomaly_model import train_iam_anomaly_model, score_events
from app.ml.synthetic_training_data import generate_normal_training_events, generate_anomalous_examples


def _events(raw):
    return [CloudTrailEvent.from_raw(r) for r in raw]


# ---------------------------------------------------------------------------
# extract_login_features
# ---------------------------------------------------------------------------

def test_features_has_expected_columns():
    raw = generate_normal_training_events(n_users=2, n_days=3)
    df = extract_login_features(_events(raw))
    for col in FEATURE_COLUMNS:
        assert col in df.columns


def test_first_login_has_zero_seconds_since_last():
    raw = generate_normal_training_events(n_users=1, n_days=1)
    df = extract_login_features(_events(raw))
    assert df.iloc[0]["seconds_since_last_login"] == 0.0


def test_first_ip_is_flagged_as_new():
    raw = generate_normal_training_events(n_users=1, n_days=1)
    df = extract_login_features(_events(raw))
    assert df.iloc[0]["is_new_ip"] == 1


def test_repeated_ip_is_not_new():
    raw = generate_normal_training_events(n_users=1, n_days=5)
    df = extract_login_features(_events(raw))
    # Au moins une connexion ulterieure doit reutiliser une IP deja vue
    assert (df["is_new_ip"] == 0).any()


def test_empty_events_returns_empty_dataframe():
    df = extract_login_features([])
    assert df.empty


# ---------------------------------------------------------------------------
# Modele entraine -- comportement de bout en bout
# ---------------------------------------------------------------------------

def test_model_flags_known_anomalies_after_training_on_normal_only():
    normal_raw = generate_normal_training_events(n_users=15, n_days=20)
    train_df = extract_login_features(_events(normal_raw))
    trained = train_iam_anomaly_model(train_df, contamination=0.05)

    anomalous_raw = generate_anomalous_examples()
    mixed_raw = normal_raw[-30:] + anomalous_raw
    mixed_df = extract_login_features(_events(mixed_raw))

    scored = score_events(trained, mixed_df)
    anomaly_rows = scored[scored["event_id"].isin({"anom-1", "anom-2"})]

    assert (anomaly_rows["is_anomaly"]).all()
    assert (anomaly_rows["confidence_score"] >= 0.5).all()


def test_confidence_score_is_bounded_between_0_and_1():
    normal_raw = generate_normal_training_events(n_users=10, n_days=15)
    train_df = extract_login_features(_events(normal_raw))
    trained = train_iam_anomaly_model(train_df)

    scored = score_events(trained, train_df)
    assert (scored["confidence_score"] >= 0.0).all()
    assert (scored["confidence_score"] <= 1.0).all()


def test_most_normal_events_are_not_flagged():
    """Sur le jeu d'entrainement lui-meme (donnees 'normales' par
    construction), la grande majorite ne doit pas etre signalee comme
    anomalie -- coherent avec contamination=0.05."""
    normal_raw = generate_normal_training_events(n_users=15, n_days=20)
    train_df = extract_login_features(_events(normal_raw))
    trained = train_iam_anomaly_model(train_df, contamination=0.05)

    scored = score_events(trained, train_df)
    anomaly_ratio = scored["is_anomaly"].mean()
    assert anomaly_ratio < 0.15  # tolerance autour du contamination cible
