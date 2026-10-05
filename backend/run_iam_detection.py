"""
Script d'integration Phase 2 : lit des evenements CloudTrail (JSON), execute
les regles de detection IAM, enregistre l'evidence associee (convention S3
Phase 1) et persiste les Findings en base (table findings).

Usage:
    python run_iam_detection.py --case-id <uuid-existant> --events-file cloudtrail_events.json

Le fichier events-file doit contenir une liste JSON d'evenements CloudTrail
au format brut (le meme format que celui utilise par AWS Collector lors de
la collecte reelle -- cf. Fetch CloudTrail Events dans l'architecture).

Ce script simule le comportement de l'AWS Collector + Correlation Worker
pour la partie IAM : dans le pipeline reel (SQS), il serait declenche par
une tache publiee par l'Investigation Orchestrator plutot que par une
ligne de commande.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.database import SessionLocal
from app.core.s3_paths import evidence_path, full_s3_uri
from app.models.evidence import EvidenceModel
from app.models.data_source_type import DataSourceType
from app.detection.cloudtrail_event import CloudTrailEvent
from app.detection.iam_rules import detect_brute_force, detect_privilege_escalation
from app.detection.persistence import persist_findings

S3_BUCKET = "acip-evidence"


def load_events(events_file: Path) -> list[dict]:
    with open(events_file, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, dict) and "Records" in raw:
        # Format export CloudTrail natif (S3 -> {"Records": [...]})
        return raw["Records"]
    return raw


def record_evidence(db, case_id: UUID, events_file: Path) -> EvidenceModel:
    """Enregistre le fichier source comme evidence, selon la convention
    S3 definie en Phase 1 (evidence/{case_id}/{data_source_type}/{filename})."""
    key = evidence_path(case_id, "iam", events_file.name)
    evidence = EvidenceModel(
        case_id=case_id,
        data_source_type=DataSourceType.IAM,
        raw_data_s3_path=full_s3_uri(S3_BUCKET, key),
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute les regles de detection IAM sur un lot d'evenements CloudTrail")
    parser.add_argument("--case-id", required=True, help="UUID d'un investigation_case existant")
    parser.add_argument("--events-file", required=True, help="Chemin vers un fichier JSON d'evenements CloudTrail")
    args = parser.parse_args()

    case_id = UUID(args.case_id)
    events_file = Path(args.events_file)

    if not events_file.exists():
        print(f"Fichier introuvable: {events_file}")
        sys.exit(1)

    raw_events = load_events(events_file)
    events = [CloudTrailEvent.from_raw(r) for r in raw_events]
    print(f"{len(events)} evenements charges depuis {events_file.name}")

    db = SessionLocal()
    try:
        evidence = record_evidence(db, case_id, events_file)
        print(f"Evidence enregistree : {evidence.id} -> {evidence.raw_data_s3_path}")

        results = detect_brute_force(events) + detect_privilege_escalation(events)

        if not results:
            print("Aucun finding detecte sur ce lot d'evenements.")
            return

        findings = persist_findings(db, case_id, results)

        print(f"\n{len(findings)} finding(s) enregistre(s) :")
        for f, r in zip(findings, results):
            print(
                f"  - [{f.severity.value.upper():8}] {f.finding_type.value:22} "
                f"confidence={f.confidence_score:.2f}  ({r.scoring_method})"
            )
            for k, v in r.details.items():
                print(f"        {k}: {v}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
