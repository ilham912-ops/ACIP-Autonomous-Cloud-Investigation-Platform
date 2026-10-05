"""
Extraction de features comportementales a partir des evenements de
connexion IAM (CloudTrail ConsoleLogin), pour alimenter un modele
Isolation Forest (cf. Cahier des charges ML, section 2.1).

Contrairement aux regles deterministes de detect_brute_force() (seuils
fixes ecrits a la main), ces features sont concues pour etre apprises :
le modele decide lui-meme ce qui est "normal" a partir de la distribution
des donnees, sans seuil code en dur.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

import pandas as pd

from app.detection.cloudtrail_event import CloudTrailEvent


FEATURE_COLUMNS = [
    "hour_of_day",
    "day_of_week",
    "is_new_ip",
    "seconds_since_last_login",
    "is_failure",
]


@dataclass
class LoginFeatureRow:
    event_id: str
    actor: str
    timestamp: datetime
    source_ip: str
    hour_of_day: int
    day_of_week: int
    is_new_ip: int          # 1 si cette IP n'a jamais ete vue pour cet acteur avant cet evenement
    seconds_since_last_login: float  # temps ecoule depuis la derniere connexion du meme acteur (0 si premiere)
    is_failure: int


def extract_login_features(events: Iterable[CloudTrailEvent]) -> pd.DataFrame:
    """Construit un DataFrame de features, une ligne par evenement
    ConsoleLogin, ordonne chronologiquement par acteur.

    Le calcul de is_new_ip et seconds_since_last_login est SEQUENTIEL :
    chaque evenement est compare a l'historique des evenements
    CHRONOLOGIQUEMENT ANTERIEURS du meme acteur, jamais aux evenements
    futurs (pour eviter toute fuite d'information -- data leakage -- qui
    fausserait artificiellement la performance du modele).
    """
    login_events = [e for e in events if e.event_name == "ConsoleLogin"]
    login_events.sort(key=lambda e: e.event_time)

    rows: list[LoginFeatureRow] = []
    known_ips_by_actor: dict[str, set[str]] = {}
    last_login_time_by_actor: dict[str, datetime] = {}

    for e in login_events:
        actor = e.user_identity_arn or "unknown"
        known_ips = known_ips_by_actor.setdefault(actor, set())

        is_new_ip = 1 if e.source_ip not in known_ips else 0

        if actor in last_login_time_by_actor:
            seconds_since_last = (e.event_time - last_login_time_by_actor[actor]).total_seconds()
        else:
            seconds_since_last = 0.0  # premiere connexion observee pour cet acteur

        rows.append(LoginFeatureRow(
            event_id=e.event_id,
            actor=actor,
            timestamp=e.event_time,
            source_ip=e.source_ip,
            hour_of_day=e.event_time.hour,
            day_of_week=e.event_time.weekday(),
            is_new_ip=is_new_ip,
            seconds_since_last_login=seconds_since_last,
            is_failure=1 if e.response_success is False else 0,
        ))

        # Mise a jour de l'historique APRES avoir calcule les features de
        # l'evenement courant (important pour ne pas se comparer a soi-meme).
        known_ips.add(e.source_ip)
        last_login_time_by_actor[actor] = e.event_time

    if not rows:
        return pd.DataFrame(columns=["event_id", "actor", "timestamp", "source_ip"] + FEATURE_COLUMNS)

    return pd.DataFrame([vars(r) for r in rows])
