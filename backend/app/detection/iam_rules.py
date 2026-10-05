"""
Regles de detection deterministes (baseline) sur les evenements IAM /
authentification (source AWS CloudTrail).

Conformement a la methodologie du Cahier des charges ML (section 7,
Etape 1 - "Regles deterministes (baseline)") : avant tout modele
statistique, on implemente des regles simples et explicables. Elles
couvrent deja une part significative des cas evidents et servent de
reference de comparaison pour les futurs modeles (Isolation Forest,
etc. - cf. section 2.1 du cahier des charges).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from .cloudtrail_event import CloudTrailEvent
from .finding_result import FindingResult, Severity

# ---------------------------------------------------------------------------
# Configuration des seuils.
# A ajuster lors de la phase d'evaluation (cf. Cahier des charges section 4 :
# precision >= 85%, rappel >= 80% pour le module IAM).
# ---------------------------------------------------------------------------
BRUTE_FORCE_MIN_ATTEMPTS = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)

SENSITIVE_POLICIES = {
    "AdministratorAccess",
    "IAMFullAccess",
    "PowerUserAccess",
}
RISKY_IAM_ACTIONS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "CreateAccessKey",
}


def _failed_console_logins_by_ip(
    events: Iterable[CloudTrailEvent],
) -> dict[str, list[CloudTrailEvent]]:
    grouped: dict[str, list[CloudTrailEvent]] = defaultdict(list)
    for e in events:
        if e.event_name == "ConsoleLogin" and e.response_success is False:
            grouped[e.source_ip].append(e)
    return grouped


def detect_brute_force(events: Iterable[CloudTrailEvent]) -> list[FindingResult]:
    """Detecte des pics d'echecs d'authentification par IP source.

    Regle : au moins BRUTE_FORCE_MIN_ATTEMPTS echecs de type ConsoleLogin
    depuis la meme IP en moins de BRUTE_FORCE_WINDOW.

    Type de donnee : IAM (CloudTrail ConsoleLogin failures).
    """
    findings: list[FindingResult] = []
    grouped = _failed_console_logins_by_ip(events)

    for ip, attempts in grouped.items():
        attempts_sorted = sorted(attempts, key=lambda e: e.event_time)

        if len(attempts_sorted) < BRUTE_FORCE_MIN_ATTEMPTS:
            continue

        # Fenetre glissante : on cherche BRUTE_FORCE_MIN_ATTEMPTS echecs
        # consecutifs contenus dans BRUTE_FORCE_WINDOW.
        for i in range(len(attempts_sorted) - BRUTE_FORCE_MIN_ATTEMPTS + 1):
            window = attempts_sorted[i:i + BRUTE_FORCE_MIN_ATTEMPTS]
            span = window[-1].event_time - window[0].event_time

            if span <= BRUTE_FORCE_WINDOW:
                # confidence_score : regle deterministe sans faux positif
                # connu -> score fixe eleve (cf. cahier des charges 3.1),
                # avec un leger bonus si le volume d'essais depasse le seuil.
                extra_attempts = len(attempts_sorted) - BRUTE_FORCE_MIN_ATTEMPTS
                confidence = min(0.90 + 0.01 * extra_attempts, 0.99)

                findings.append(FindingResult(
                    finding_type="BRUTE_FORCE",
                    data_source_type="iam",
                    severity=Severity.HIGH,
                    confidence_score=round(confidence, 2),
                    evidence_event_ids=[e.event_id for e in window],
                    details={
                        "source_ip": ip,
                        "attempts_in_window": len(window),
                        "total_attempts_observed": len(attempts_sorted),
                        "window_start": window[0].event_time.isoformat(),
                        "window_end": window[-1].event_time.isoformat(),
                    },
                    scoring_method="regle_deterministe:seuil_fixe(brute_force)",
                ))
                break  # une detection par IP suffit pour ce lot d'evenements

    return findings


def detect_privilege_escalation(events: Iterable[CloudTrailEvent]) -> list[FindingResult]:
    """Detecte l'attribution (ou l'auto-attribution) de politiques IAM
    sensibles, ou la creation de cles d'acces, sur un compte non-root.

    Type de donnee : IAM (CloudTrail evenements de gestion IAM).
    """
    findings: list[FindingResult] = []

    for e in events:
        if e.event_name not in RISKY_IAM_ACTIONS:
            continue
        if e.user_identity_type == "Root":
            # Le compte root possede deja tous les droits : ce n'est pas
            # une escalade de privileges.
            continue

        policy_arn = e.request_parameters.get("policyArn", "")
        is_sensitive_policy = any(p in policy_arn for p in SENSITIVE_POLICIES)

        if e.event_name in {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"}:
            if not is_sensitive_policy:
                # Attribution d'une politique non sensible : hors perimetre
                # de la Phase 2 (pourrait etre couvert par une regle moins
                # prioritaire plus tard).
                continue
            confidence = 0.85
            severity = Severity.CRITICAL
            scoring_note = "sensibilite_politique=elevee"
        else:
            # CreateAccessKey : toujours remonte, mais avec une confiance
            # plus faible (peut etre une action legitime d'un administrateur).
            confidence = 0.65
            severity = Severity.MEDIUM
            scoring_note = "creation_cle_acces=heuristique"

        findings.append(FindingResult(
            finding_type="PRIVILEGE_ESCALATION",
            data_source_type="iam",
            severity=severity,
            confidence_score=confidence,
            evidence_event_ids=[e.event_id],
            details={
                "actor_arn": e.user_identity_arn,
                "action": e.event_name,
                "target_policy": policy_arn or None,
                "source_ip": e.source_ip,
            },
            scoring_method=f"regle_deterministe:{scoring_note}(privilege_escalation)",
        ))

    return findings
