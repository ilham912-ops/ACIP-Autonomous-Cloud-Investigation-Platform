"""
Convention centralisee de nommage des chemins S3 pour ACIP.

Tous les workers (Ingestion Service, AWS Collector, Correlation Worker,
AI Analysis Worker) doivent utiliser ces fonctions plutot que de
construire des chemins S3 a la main -- ca garantit un format unique,
exploitable de facon previsible par le dashboard et les futurs exports.

Bucket cible (a adapter selon l'environnement) : acip-evidence
"""
from datetime import datetime, timezone
from uuid import UUID


def raw_event_path(source_type: str, incident_id: UUID, when: datetime | None = None) -> str:
    """Chemin d'un evenement brut, avant normalisation.

    Exemple: raw-events/cloudtrail/2026/08/13/3f225e24-6b86-4977-8d1c-00a241c24481.json
    """
    when = when or datetime.now(timezone.utc)
    return (
        f"raw-events/{source_type}/"
        f"{when:%Y}/{when:%m}/{when:%d}/"
        f"{incident_id}.json"
    )


def evidence_path(case_id: UUID, data_source_type: str, filename: str) -> str:
    """Chemin d'une preuve collectee et rattachee a un case.

    Exemple: evidence/c505eb03-.../cloudtrail/events.json
    data_source_type doit correspondre a l'enum DataSourceType
    (iam, network, s3, config, runtime, database).
    """
    return f"evidence/{case_id}/{data_source_type}/{filename}"


def report_path(case_id: UUID, report_type: str, ext: str = "pdf", when: datetime | None = None) -> str:
    """Chemin d'un rapport final genere pour un case.

    Exemple: reports/c505eb03-.../summary_20260813T142530Z.pdf
    report_type: 'summary', 'timeline', 'full'...
    """
    when = when or datetime.now(timezone.utc)
    timestamp = when.strftime("%Y%m%dT%H%M%SZ")
    return f"reports/{case_id}/{report_type}_{timestamp}.{ext}"


def export_path(case_id: UUID, ext: str = "csv", when: datetime | None = None) -> str:
    """Chemin d'un export ponctuel demande par un analyste.

    Exemple: exports/c505eb03-.../export_20260813T142530Z.csv
    """
    when = when or datetime.now(timezone.utc)
    timestamp = when.strftime("%Y%m%dT%H%M%SZ")
    return f"exports/{case_id}/export_{timestamp}.{ext}"


def full_s3_uri(bucket: str, key: str) -> str:
    """Construit l'URI S3 complete a partir du bucket et d'un chemin
    genere par une des fonctions ci-dessus.

    Exemple: full_s3_uri("acip-evidence", evidence_path(...))
            -> "s3://acip-evidence/evidence/.../cloudtrail/events.json"
    """
    return f"s3://{bucket}/{key}"


if __name__ == "__main__":
    # Petit auto-test manuel, aligne sur le resultat de test_phase1.py
    from uuid import uuid4

    case_id = uuid4()
    incident_id = uuid4()

    print(raw_event_path("cloudtrail", incident_id))
    print(evidence_path(case_id, "iam", "cloudtrail_events.json"))
    print(report_path(case_id, "summary"))
    print(export_path(case_id))
    print(full_s3_uri("acip-evidence", evidence_path(case_id, "iam", "events.json")))