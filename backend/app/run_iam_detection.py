
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
        return raw["Records"]
    return raw


def record_evidence(db, case_id: UUID, events_file: Path) -> EvidenceModel:
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


def run_ml_detection(events: list) -> list:
    """Execute le modele Isolation Forest si disponible. Retourne une liste
    vide (avec avertissement) si le modele ou ses dependances manquent,
    plutot que de faire echouer tout le script pour une brique optionnelle."""
    try:
        from app.detection.anomaly_detection import detect_anomalous_logins
    except ImportError as e:
        print(f"[ML] Module ML indisponible ({e}) -- poursuite avec les regles deterministes seules.")
        return []

    try:
        return detect_anomalous_logins(events)
    except FileNotFoundError:
        print(
            "[ML] Aucun modele entraine trouve (app/ml/models/iam_isolation_forest.joblib). "
            "Executez train_iam_anomaly_model.py au prealable. Poursuite sans la partie ML."
        )
        return []
    except Exception as e:
        # Erreur inattendue (ex: enum ANOMALOUS_LOGIN absent, colonne manquante...)
        # -- on ne bloque pas les regles deterministes pour autant.
        print(f"[ML] Erreur lors de la detection ML ({e}) -- poursuite sans la partie ML.")
        return []


def print_findings_report(results, findings) -> None:
    deterministic = [r for r in results if r.scoring_method.startswith("regle_deterministe")]
    ml_based = [r for r in results if r.scoring_method.startswith("modele_ml")]

    print(f"\n{len(findings)} finding(s) enregistre(s) au total "
          f"({len(deterministic)} regle(s) deterministe(s), {len(ml_based)} modele ML) :\n")

    for f, r in zip(findings, results):
        origin = "REGLE" if r.scoring_method.startswith("regle_deterministe") else "ML   "
        print(
            f"  [{origin}] [{f.severity.value.upper():8}] {f.finding_type.value:22} "
            f"confidence={f.confidence_score:.2f}  ({r.scoring_method})"
        )
        for k, v in r.details.items():
            print(f"        {k}: {v}")

    if deterministic and ml_based:
        det_actors = {r.details.get("actor") or r.details.get("actor_arn") for r in deterministic}
        ml_actors = {r.details.get("actor") for r in ml_based}
        overlap = det_actors & ml_actors
        if overlap:
            print(f"\n  Note : {len(overlap)} acteur(s) signale(s) A LA FOIS par une regle "
                  f"deterministe et par le modele ML -> forte convergence de signal, "
                  f"a prioriser pour l'analyste : {overlap}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute les regles IAM (deterministes + ML) sur un lot d'evenements CloudTrail")
    parser.add_argument("--case-id", required=True, help="UUID d'un investigation_case existant")
    parser.add_argument("--events-file", required=True, help="Chemin vers un fichier JSON d'evenements CloudTrail")
    parser.add_argument("--skip-ml", action="store_true", help="Desactive volontairement la detection ML (regles deterministes uniquement)")
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

        print("\n[REGLES] Execution des regles deterministes (detect_brute_force, detect_privilege_escalation)...")
        results = detect_brute_force(events) + detect_privilege_escalation(events)
        print(f"[REGLES] {len(results)} finding(s) detecte(s).")

        if args.skip_ml:
            print("\n[ML] Detection ML desactivee (--skip-ml).")
        else:
            print("\n[ML] Execution du modele Isolation Forest...")
            ml_results = run_ml_detection(events)
            print(f"[ML] {len(ml_results)} finding(s) detecte(s).")
            results += ml_results

        if not results:
            print("\nAucun finding detecte sur ce lot d'evenements (regles et ML confondus).")
            return

        findings = persist_findings(db, case_id, results)
        print_findings_report(results, findings)

    finally:
        db.close()


if __name__ == "__main__":
    main()
