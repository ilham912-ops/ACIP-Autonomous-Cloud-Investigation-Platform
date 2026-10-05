"""
Modele Isolation Forest pour la detection d'anomalies de connexion IAM.

Isolation Forest (Liu, Ting, Zhou, 2008) est un modele NON SUPERVISE : il
n'a besoin d'aucune etiquette "attaque"/"normal" pour s'entrainer. Son
principe : les points anormaux sont plus faciles a "isoler" (moins
d'etapes de partitionnement aleatoire necessaires) que les points
normaux, qui sont noyes dans la masse des donnees similaires.

C'est le choix explicitement documente dans le Cahier des charges ML
(section 2.1) pour ce cas d'usage.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLUMNS

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "iam_isolation_forest.joblib"


@dataclass
class TrainedIAMModel:
    model: IsolationForest
    scaler: StandardScaler
    # Bornes observees sur le jeu d'entrainement, pour calibrer le score
    # de sortie en confidence_score [0, 1] de facon reproductible
    # (cf. Cahier des charges section 3.1 : "score normalise par
    # min-max scaling, calibre sur le jeu de donnees de reference").
    train_score_min: float
    train_score_max: float

    def save(self, path: Path = DEFAULT_MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: Path = DEFAULT_MODEL_PATH) -> "TrainedIAMModel":
        return joblib.load(path)


def train_iam_anomaly_model(
    features_df: pd.DataFrame,
    contamination: float = 0.05,
    random_state: int = 42,
) -> TrainedIAMModel:
    """Entraine un Isolation Forest sur des features de connexion IAM.

    contamination : proportion attendue d'anomalies dans le jeu
    d'entrainement (hyperparametre d'Isolation Forest). 0.05 = on suppose
    qu'au plus 5% des connexions d'entrainement sont anormales -- une
    hypothese raisonnable si le jeu d'entrainement est majoritairement du
    trafic legitime historique.
    """
    X = features_df[FEATURE_COLUMNS].to_numpy(dtype=float)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X_scaled)

    # decision_function : plus haut = plus normal, plus bas (souvent negatif) = plus anormal.
    train_scores = model.decision_function(X_scaled)

    return TrainedIAMModel(
        model=model,
        scaler=scaler,
        train_score_min=float(train_scores.min()),
        train_score_max=float(train_scores.max()),
    )


def score_events(trained: TrainedIAMModel, features_df: pd.DataFrame) -> pd.DataFrame:
    """Calcule un score d'anomalie et un confidence_score calibre [0,1]
    pour chaque ligne de features_df. confidence_score proche de 1 =
    forte confiance qu'il s'agit d'une anomalie."""
    if features_df.empty:
        return features_df.assign(anomaly_score=[], is_anomaly=[], confidence_score=[])

    X = features_df[FEATURE_COLUMNS].to_numpy(dtype=float)
    X_scaled = trained.scaler.transform(X)

    raw_scores = trained.model.decision_function(X_scaled)  # haut = normal, bas = anormal
    predictions = trained.model.predict(X_scaled)  # 1 = normal, -1 = anomalie

    # Calibration min-max en utilisant les bornes du jeu D'ENTRAINEMENT
    # (pas du jeu courant), pour rester reproductible d'un batch a l'autre
    # -- cf. methodologie section 3.1 du cahier des charges.
    span = trained.train_score_max - trained.train_score_min
    if span == 0:
        normalized_anomaly = np.zeros_like(raw_scores)
    else:
        # on inverse le signe : score eleve = anomalie => confidence elevee
        normalized_anomaly = (trained.train_score_max - raw_scores) / span
        normalized_anomaly = np.clip(normalized_anomaly, 0.0, 1.0)

    result = features_df.copy()
    result["anomaly_score"] = raw_scores
    result["is_anomaly"] = predictions == -1
    result["confidence_score"] = normalized_anomaly.round(3)
    return result
