"""
Generateur de donnees synthetiques IAM pour l'evaluation des regles de
detection (cf. Cahier des charges ML section 5.2 : objectif minimal de
200 exemples labellises par categorie d'attaque ciblee).

Chaque Scenario contient un lot d'evenements CloudTrail bruts et le
resultat attendu (label de verite terrain), pour permettre le calcul de
precision/recall dans evaluate_iam_rules.py.

IMPORTANT (limite connue) : ces scenarios sont generes selon la meme
logique que les regles de detection elles-memes. Ce jeu sert donc a
valider le bon fonctionnement du harnais de mesure et la non-regression
du code, PAS a mesurer une vraie capacite de generalisation. Une mesure
fiable de precision/recall necessite un jeu labellise a partir de vrais
logs (ou au moins construit independamment des regles), cf. section 5.2
du cahier des charges.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

random.seed(42)

BASE_TIME = datetime(2026, 8, 1, 8, 0, 0, tzinfo=timezone.utc)


def _console_login(event_id: str, ip: str, when: datetime, success: bool) -> dict:
    return {
        "eventID": event_id,
        "eventName": "ConsoleLogin",
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceIPAddress": ip,
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::123456789012:user/user-{ip[-3:]}"},
        "responseElements": {"ConsoleLogin": "Success" if success else "Failure"},
    }


def _iam_action(
    event_id: str, action: str, actor_type: str, actor_arn: str, when: datetime, policy_arn: str = ""
) -> dict:
    return {
        "eventID": event_id,
        "eventName": action,
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceIPAddress": "10.0.0.5",
        "userIdentity": {"type": actor_type, "arn": actor_arn},
        "requestParameters": {"policyArn": policy_arn} if policy_arn else {},
    }


@dataclass
class Scenario:
    scenario_id: str
    rule: str  # "brute_force" ou "privilege_escalation"
    expected_finding_type: Optional[str]  # None si aucun finding attendu (negatif)
    events: list = field(default_factory=list)


def _random_ip() -> str:
    return f"203.0.113.{random.randint(1, 250)}"


# ---------------------------------------------------------------------------
# Scenarios BRUTE_FORCE
# ---------------------------------------------------------------------------

def generate_brute_force_positive(n: int) -> list[Scenario]:
    scenarios = []
    for i in range(n):
        ip = _random_ip()
        start = BASE_TIME + timedelta(hours=i)
        n_attempts = random.randint(5, 9)
        events = [
            _console_login(f"bfp-{i}-{j}", ip, start + timedelta(seconds=j * random.randint(15, 55)), False)
            for j in range(n_attempts)
        ]
        scenarios.append(Scenario(f"bf_pos_{i}", "brute_force", "BRUTE_FORCE", events))
    return scenarios


def generate_brute_force_negative_spread(n: int) -> list[Scenario]:
    """Echecs reels mais espaces de plus de 5 minutes : ne doit pas declencher."""
    scenarios = []
    for i in range(n):
        ip = _random_ip()
        start = BASE_TIME + timedelta(hours=100 + i)
        events = [
            _console_login(f"bfn-spread-{i}-{j}", ip, start + timedelta(minutes=j * 12), False)
            for j in range(5)
        ]
        scenarios.append(Scenario(f"bf_neg_spread_{i}", "brute_force", None, events))
    return scenarios


def generate_brute_force_negative_few_attempts(n: int) -> list[Scenario]:
    """Moins que le seuil : ne doit pas declencher."""
    scenarios = []
    for i in range(n):
        ip = _random_ip()
        start = BASE_TIME + timedelta(hours=200 + i)
        events = [
            _console_login(f"bfn-few-{i}-{j}", ip, start + timedelta(seconds=j * 20), False)
            for j in range(random.randint(1, 4))
        ]
        scenarios.append(Scenario(f"bf_neg_few_{i}", "brute_force", None, events))
    return scenarios


def generate_brute_force_negative_successful(n: int) -> list[Scenario]:
    """Connexions normales reussies : ne doit pas declencher."""
    scenarios = []
    for i in range(n):
        ip = _random_ip()
        start = BASE_TIME + timedelta(hours=300 + i)
        events = [_console_login(f"bfn-ok-{i}", ip, start, True)]
        scenarios.append(Scenario(f"bf_neg_ok_{i}", "brute_force", None, events))
    return scenarios


# ---------------------------------------------------------------------------
# Scenarios PRIVILEGE_ESCALATION
# ---------------------------------------------------------------------------

def generate_privesc_positive_sensitive_policy(n: int) -> list[Scenario]:
    scenarios = []
    sensitive = ["AdministratorAccess", "IAMFullAccess", "PowerUserAccess"]
    for i in range(n):
        when = BASE_TIME + timedelta(hours=400 + i)
        policy = random.choice(sensitive)
        events = [_iam_action(
            f"pep-{i}", "AttachUserPolicy", "IAMUser",
            f"arn:aws:iam::123456789012:user/actor-{i}", when,
            policy_arn=f"arn:aws:iam::aws:policy/{policy}",
        )]
        scenarios.append(Scenario(f"pe_pos_sensitive_{i}", "privilege_escalation", "PRIVILEGE_ESCALATION", events))
    return scenarios


def generate_privesc_positive_access_key(n: int) -> list[Scenario]:
    scenarios = []
    for i in range(n):
        when = BASE_TIME + timedelta(hours=500 + i)
        events = [_iam_action(
            f"pek-{i}", "CreateAccessKey", "IAMUser",
            f"arn:aws:iam::123456789012:user/actor-key-{i}", when,
        )]
        scenarios.append(Scenario(f"pe_pos_key_{i}", "privilege_escalation", "PRIVILEGE_ESCALATION", events))
    return scenarios


def generate_privesc_negative_non_sensitive(n: int) -> list[Scenario]:
    scenarios = []
    benign = ["ReadOnlyAccess", "AmazonS3ReadOnlyAccess", "ViewOnlyAccess"]
    for i in range(n):
        when = BASE_TIME + timedelta(hours=600 + i)
        policy = random.choice(benign)
        events = [_iam_action(
            f"pen-{i}", "AttachUserPolicy", "IAMUser",
            f"arn:aws:iam::123456789012:user/actor-benign-{i}", when,
            policy_arn=f"arn:aws:iam::aws:policy/{policy}",
        )]
        scenarios.append(Scenario(f"pe_neg_benign_{i}", "privilege_escalation", None, events))
    return scenarios


def generate_privesc_negative_root(n: int) -> list[Scenario]:
    scenarios = []
    for i in range(n):
        when = BASE_TIME + timedelta(hours=700 + i)
        events = [_iam_action(
            f"per-{i}", "AttachUserPolicy", "Root",
            "arn:aws:iam::123456789012:root", when,
            policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
        )]
        scenarios.append(Scenario(f"pe_neg_root_{i}", "privilege_escalation", None, events))
    return scenarios


def build_dataset(per_category: int = 50) -> list[Scenario]:
    """Construit le jeu complet. Avec per_category=50 sur 4 sous-categories
    par regle, on atteint 200 exemples par regle (cible du cahier des
    charges section 5.2)."""
    dataset: list[Scenario] = []
    dataset += generate_brute_force_positive(per_category)
    dataset += generate_brute_force_negative_spread(per_category)
    dataset += generate_brute_force_negative_few_attempts(per_category)
    dataset += generate_brute_force_negative_successful(per_category)

    dataset += generate_privesc_positive_sensitive_policy(per_category)
    dataset += generate_privesc_positive_access_key(per_category)
    dataset += generate_privesc_negative_non_sensitive(per_category)
    dataset += generate_privesc_negative_root(per_category)

    return dataset


if __name__ == "__main__":
    ds = build_dataset(per_category=50)
    by_rule: dict[str, int] = {}
    for s in ds:
        by_rule[s.rule] = by_rule.get(s.rule, 0) + 1
    print(f"Dataset genere : {len(ds)} scenarios au total")
    for rule, count in by_rule.items():
        print(f"  - {rule}: {count} scenarios")
