"""
Script d'entrainement du modele Isolation Forest (demonstration).

Usage :
    python train_iam_anomaly_model.py

Genere un jeu d'entrainement synthetique "normal", entraine le modele,
verifie qualitativement qu'il detecte bien des exemples anormaux
construits a la main, puis sauvegarde le modele entraine sur disque.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.detection.cloudtrail_event import CloudTrailEvent
from app.ml.features import extract_login_features
from app.ml.iam_anomaly_model import train_iam_anomaly_model, score_events, DEFAULT_MODEL_PATH
from app.ml.synthetic_training_data import generate_normal_training_events, generate_anomalous_examples


def main() -> None:
    print("1. Generation du jeu d'entrainement synthetique (connexions normales)...")
    normal_raw = generate_normal_training_events(n_users=15, n_days=20)
    normal_events = [CloudTrailEvent.from_raw(r) for r in normal_raw]
    print(f"   {len(normal_events)} evenements de connexion generes.")

    print("\n2. Extraction des features...")
    features_df = extract_login_features(normal_events)
    print(f"   {len(features_df)} lignes de features extraites.")
    print(f"   Colonnes : {list(features_df.columns)}")

    print("\n3. Entrainement du modele Isolation Forest...")
    trained = train_iam_anomaly_model(features_df, contamination=0.05)
    print(f"   Modele entraine. Bornes de score (train) : "
          f"[{trained.train_score_min:.4f}, {trained.train_score_max:.4f}]")

    print("\n4. Sauvegarde du modele...")
    trained.save(DEFAULT_MODEL_PATH)
    print(f"   Modele sauvegarde dans {DEFAULT_MODEL_PATH}")

    print("\n5. Verification qualitative sur des exemples anormaux connus...")
    anomalous_raw = generate_anomalous_examples()
    # On melange avec quelques evenements normaux pour un test plus realiste
    # (le calcul de is_new_ip/seconds_since_last_login a besoin d'un minimum
    # d'historique par acteur pour etre pertinent).
    mixed_raw = normal_raw[-30:] + anomalous_raw
    mixed_events = [CloudTrailEvent.from_raw(r) for r in mixed_raw]
    mixed_features = extract_login_features(mixed_events)

    scored = score_events(trained, mixed_features)
    anomalous_ids = {"anom-1", "anom-2"}
    result_view = scored[scored["event_id"].isin(anomalous_ids)][
        ["event_id", "actor", "is_new_ip", "hour_of_day", "confidence_score", "is_anomaly"]
    ]
    print(result_view.to_string(index=False))

    detected = result_view[result_view["is_anomaly"]].shape[0]
    print(f"\n   {detected}/{len(anomalous_ids)} exemples anormaux connus detectes par le modele.")


if __name__ == "__main__":
    main()
