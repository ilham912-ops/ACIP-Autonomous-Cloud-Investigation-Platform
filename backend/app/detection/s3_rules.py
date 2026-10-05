"""
Regles de detection deterministes (baseline) sur les evenements S3
(Cahier des charges ML, section 2.3 - donnees de stockage d'objets).

Feuille de route Phase 4 : detect_mass_download() est le livrable
principal de cette phase. Le seuillage utilise ici est fixe (deterministe),
conformement a la methodologie "regles avant modeles statistiques"
(section 7, Etape 1). Le seuillage ADAPTATIF base sur la distribution
historique des requetes (mentionne en section 2.3 du cahier des charges)
est laisse pour une iteration ulterieure, une fois un historique de
volumetrie reel disponible.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from .s3_event import S3Event
from .finding_result import FindingResult, Severity

# ---------------------------------------------------------------------------
# Configuration des seuils (baseline fixe -- a affiner en Phase 6 avec un
# historique reel, cf. cahier des charges section 4 : precision >= 85%,
# rappel >= 80% pour le module S3).
# ---------------------------------------------------------------------------
MASS_DOWNLOAD_MIN_OBJECTS = 20
MASS_DOWNLOAD_WINDOW = timedelta(minutes=10)


def _get_object_events_by_actor(events: Iterable[S3Event]) -> dict[str, list[S3Event]]:
    """Regroupe les evenements GetObject par acteur (arn), plutot que par
    IP seule : un meme utilisateur/role peut telecharger depuis plusieurs
    IP (ex: proxy, VPN), et regrouper par identite est plus robuste pour
    detecter une exfiltration menee par un compte compromis."""
    grouped: dict[str, list[S3Event]] = defaultdict(list)
    for e in events:
        if e.event_name == "GetObject":
            key = e.actor_arn or e.source_ip  # repli sur l'IP si l'ARN est absent
            grouped[key].append(e)
    return grouped


def detect_mass_download(events: Iterable[S3Event]) -> list[FindingResult]:
    """Detecte un telechargement massif d'objets S3 par un meme acteur en
    peu de temps -- signal caracteristique d'une exfiltration de donnees.

    Regle : au moins MASS_DOWNLOAD_MIN_OBJECTS operations GetObject par le
    meme acteur en moins de MASS_DOWNLOAD_WINDOW.

    Type de donnee : S3 (data events GetObject).
    """
    findings: list[FindingResult] = []
    grouped = _get_object_events_by_actor(events)

    for actor, actor_events in grouped.items():
        events_sorted = sorted(actor_events, key=lambda e: e.event_time)

        if len(events_sorted) < MASS_DOWNLOAD_MIN_OBJECTS:
            continue

        for i in range(len(events_sorted) - MASS_DOWNLOAD_MIN_OBJECTS + 1):
            window = events_sorted[i:i + MASS_DOWNLOAD_MIN_OBJECTS]
            span = window[-1].event_time - window[0].event_time

            if span <= MASS_DOWNLOAD_WINDOW:
                buckets_touched = sorted({e.bucket_name for e in window})
                total_bytes = sum(e.bytes_transferred or 0 for e in window)
                extra_objects = len(events_sorted) - MASS_DOWNLOAD_MIN_OBJECTS
                confidence = min(0.85 + 0.01 * extra_objects, 0.97)

                findings.append(FindingResult(
                    finding_type="MASS_DOWNLOAD",
                    data_source_type="s3",
                    severity=Severity.HIGH,
                    confidence_score=round(confidence, 2),
                    evidence_event_ids=[e.event_id for e in window],
                    details={
                        "actor": actor,
                        "objects_in_window": len(window),
                        "total_objects_observed": len(events_sorted),
                        "buckets_touched": buckets_touched,
                        "total_bytes_transferred": total_bytes or None,
                        "window_start": window[0].event_time.isoformat(),
                        "window_end": window[-1].event_time.isoformat(),
                    },
                    scoring_method="regle_deterministe:seuil_fixe(mass_download)",
                ))
                break  # une detection par acteur suffit pour ce lot

    return findings
