"""
Genere un jeu d'entrainement synthetique de connexions IAM "normales",
pour entrainer le modele Isolation Forest de maniere demonstrative.

IMPORTANT (a documenter dans le rapport, meme limite que les jeux
synthetiques precedents) : ceci simule un historique plausible mais reste
un jeu synthetique. Pour un vrai deploiement, ce modele DOIT etre
reentraine sur un historique reel de connexions de l'organisation cible
(Isolation Forest est non supervise mais reste sensible a la
representativite des donnees d'entrainement).
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

random.seed(7)

BASE_DAY = datetime(2026, 8, 24, 0, 0, 0, tzinfo=timezone.utc)  # un lundi


def _login_event(event_id: str, actor: str, ip: str, when: datetime, success: bool = True) -> dict:
    return {
        "eventID": event_id,
        "eventName": "ConsoleLogin",
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceIPAddress": ip,
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::123456789012:user/{actor}"},
        "responseElements": {"ConsoleLogin": "Success" if success else "Failure"},
    }


def generate_normal_training_events(n_users: int = 15, n_days: int = 20) -> list[dict]:
    """Simule n_users employes, chacun avec 1-2 IP habituelles et des
    connexions concentrees en heures de bureau (8h-19h, jours ouvres)."""
    events = []
    event_counter = 0

    for u in range(n_users):
        actor = f"employee{u}"
        # 1 a 2 IP habituelles par utilisateur (domicile + bureau, VPN...)
        habitual_ips = [f"198.51.100.{10 + u}"]
        if random.random() < 0.4:
            habitual_ips.append(f"203.0.113.{20 + u}")

        for day in range(n_days):
            current_day = BASE_DAY + timedelta(days=day)
            if current_day.weekday() >= 5:  # week-end : peu/pas de connexion
                if random.random() > 0.1:
                    continue

            # 1 a 3 connexions dans la journee, en heures de bureau
            for _ in range(random.randint(1, 3)):
                hour = random.randint(8, 18)
                minute = random.randint(0, 59)
                when = current_day.replace(hour=hour, minute=minute)
                ip = random.choice(habitual_ips)

                events.append(_login_event(f"train-{event_counter}", actor, ip, when, success=True))
                event_counter += 1

    return events


def generate_anomalous_examples() -> list[dict]:
    """Quelques connexions clairement anormales, POUR LA DEMONSTRATION
    uniquement (pas utilisees pour l'entrainement -- Isolation Forest est
    non supervise, ces exemples servent seulement a verifier que le
    modele les detecte bien apres entrainement)."""
    events = []

    # Connexion a 3h du matin, IP jamais vue, pour un utilisateur habitue
    # a se connecter en heures de bureau depuis une IP fixe.
    when = BASE_DAY + timedelta(days=25, hours=3, minutes=12)
    events.append(_login_event("anom-1", "employee0", "45.33.10.7", when, success=True))

    # Meme profil, IP totalement nouvelle et horaire inhabituel
    when2 = BASE_DAY + timedelta(days=26, hours=2, minutes=5)
    events.append(_login_event("anom-2", "employee3", "185.220.101.5", when2, success=True))

    return events
