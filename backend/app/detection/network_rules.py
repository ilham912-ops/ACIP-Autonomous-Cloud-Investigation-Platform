"""
Regles de detection deterministes (baseline) sur les evenements reseau
(VPC Flow Logs) -- Cahier des charges ML section 2.2.

Conformement a la note de faisabilite de la feuille de route (section 7.1),
ce module (reseau) est le LIVRABLE FERME de la Phase 5. Le module runtime
(2.4, chaines de Markov sur syscalls) est traite separement comme objectif
conditionnel.

Approche deterministe simplifiee, avant les modeles statistiques prevus a
terme (DBSCAN pour le clustering IP/port, autocorrelation/FFT pour le
beaconing -- cf. cahier des charges section 2.2). Cette version baseline
permet deja de couvrir les cas evidents et sert de reference de comparaison
pour ces futurs modeles, conformement a la methodologie section 7 Etape 1.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from .network_event import VPCFlowLogEvent
from .finding_result import FindingResult, Severity

# ---------------------------------------------------------------------------
# Configuration des seuils (baseline fixe, a affiner avec un historique reel)
# ---------------------------------------------------------------------------
PORT_SCAN_MIN_DISTINCT_PORTS = 15
PORT_SCAN_WINDOW = timedelta(minutes=5)

BEACONING_MIN_CONNECTIONS = 6
# Coefficient de variation (ecart-type / moyenne) des intervalles entre
# connexions : plus il est bas, plus le rythme est regulier (caracteristique
# d'un beacon automatise plutot que d'un usage humain).
BEACONING_MAX_COEFFICIENT_OF_VARIATION = 0.15
BEACONING_MIN_INTERVAL_SECONDS = 5  # ignore les rafales quasi-instantanees (pas un beacon)


def _group_by_src_ip(events: Iterable[VPCFlowLogEvent]) -> dict[str, list[VPCFlowLogEvent]]:
    grouped: dict[str, list[VPCFlowLogEvent]] = defaultdict(list)
    for e in events:
        grouped[e.src_addr].append(e)
    return grouped


def _group_by_src_dst_pair(events: Iterable[VPCFlowLogEvent]) -> dict[tuple[str, str], list[VPCFlowLogEvent]]:
    grouped: dict[tuple[str, str], list[VPCFlowLogEvent]] = defaultdict(list)
    for e in events:
        grouped[(e.src_addr, e.dst_addr)].append(e)
    return grouped


def detect_port_scan(events: Iterable[VPCFlowLogEvent]) -> list[FindingResult]:
    """Detecte un scan de ports : une meme IP source contacte un grand
    nombre de ports distincts sur une courte fenetre de temps.

    Type de donnee : reseau (VPC Flow Logs).
    """
    findings: list[FindingResult] = []
    grouped = _group_by_src_ip(events)

    for src_ip, ip_events in grouped.items():
        events_sorted = sorted(ip_events, key=lambda e: e.start_time)
        distinct_ports = {e.dst_port for e in events_sorted}

        if len(distinct_ports) < PORT_SCAN_MIN_DISTINCT_PORTS:
            continue

        window_start = events_sorted[0].start_time
        window_end = events_sorted[-1].start_time
        if window_end - window_start > PORT_SCAN_WINDOW:
            continue  # ports distincts mais etales dans le temps -> pas un scan actif

        distinct_targets = {e.dst_addr for e in events_sorted}
        extra_ports = len(distinct_ports) - PORT_SCAN_MIN_DISTINCT_PORTS
        confidence = min(0.80 + 0.01 * extra_ports, 0.95)

        findings.append(FindingResult(
            finding_type="PORT_SCAN",
            data_source_type="network",
            severity=Severity.HIGH,
            confidence_score=round(confidence, 2),
            evidence_event_ids=[str(i) for i in range(len(events_sorted))],  # VPC Flow Logs n'ont pas d'event_id natif
            details={
                "source_ip": src_ip,
                "distinct_ports_contacted": len(distinct_ports),
                "distinct_targets_contacted": len(distinct_targets),
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
            },
            scoring_method="regle_deterministe:seuil_fixe(port_scan)",
        ))

    return findings


def detect_beaconing(events: Iterable[VPCFlowLogEvent]) -> list[FindingResult]:
    """Detecte un signal de beaconing C2 : des connexions regulierement
    espacees dans le temps vers une meme destination, caracteristique d'un
    processus automatise plutot que d'un usage humain.

    Approche : calcul du coefficient de variation des intervalles entre
    connexions successives vers la meme paire (source, destination). Un
    coefficient bas indique un rythme tres regulier.

    NOTE : ceci est une approximation deterministe simple de la detection
    par autocorrelation/FFT prevue a terme (cahier des charges section 2.2),
    suffisante pour capter un beacon a intervalle fixe, mais moins robuste
    qu'une analyse frequentielle face a un beacon a intervalle variable
    (jitter volontairement introduit par l'attaquant).
    """
    findings: list[FindingResult] = []
    grouped = _group_by_src_dst_pair(events)

    for (src_ip, dst_ip), pair_events in grouped.items():
        events_sorted = sorted(pair_events, key=lambda e: e.start_time)

        if len(events_sorted) < BEACONING_MIN_CONNECTIONS:
            continue

        intervals = [
            (events_sorted[i + 1].start_time - events_sorted[i].start_time).total_seconds()
            for i in range(len(events_sorted) - 1)
        ]

        if any(i < BEACONING_MIN_INTERVAL_SECONDS for i in intervals):
            continue  # rafale rapprochee, pas un rythme de beacon typique

        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            continue
        stdev_interval = statistics.pstdev(intervals)
        coefficient_of_variation = stdev_interval / mean_interval

        if coefficient_of_variation > BEACONING_MAX_COEFFICIENT_OF_VARIATION:
            continue  # rythme trop irregulier pour etre retenu comme beacon

        confidence = round(max(0.70, 0.95 - coefficient_of_variation), 2)

        findings.append(FindingResult(
            finding_type="C2_BEACONING",
            data_source_type="network",
            severity=Severity.CRITICAL,
            confidence_score=confidence,
            evidence_event_ids=[str(i) for i in range(len(events_sorted))],
            details={
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "connections_observed": len(events_sorted),
                "mean_interval_seconds": round(mean_interval, 1),
                "coefficient_of_variation": round(coefficient_of_variation, 3),
            },
            scoring_method="regle_deterministe:regularite_intervalle(c2_beaconing)",
        ))

    return findings
