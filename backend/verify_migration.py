"""
Script de verification de la migration ACIP.

Ce script :
1. Se connecte a la base via la meme config que le backend (app.core.database)
2. Verifie que les 5 tables existent
3. Insere une chaine de test : incident -> investigation_case -> evidence
4. Verifie que la jointure fonctionne
5. Nettoie les donnees de test
6. Affiche un resultat clair : OK ou ERREUR a chaque etape

Usage (depuis le conteneur backend, dossier backend/) :
    python verify_migration.py
"""
import sys
import uuid
from sqlalchemy import text

from app.core.database import SessionLocal, engine


def check(label, condition):
    status = "OK " if condition else "ECHEC"
    print(f"[{status}] {label}")
    return condition


def main():
    all_ok = True
    db = SessionLocal()

    try:
        # ---- 1. Connexion ----
        try:
            db.execute(text("SELECT 1"))
            all_ok &= check("Connexion a la base", True)
        except Exception as e:
            check("Connexion a la base", False)
            print(f"    -> Erreur: {e}")
            print(f"    -> URL utilisee: {engine.url}")
            sys.exit(1)

        # ---- 2. Presence des tables ----
        expected_tables = ["incidents", "investigation_cases", "evidence", "findings", "tasks"]
        result = db.execute(text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
        ))
        existing = {row[0] for row in result}
        for t in expected_tables:
            all_ok &= check(f"Table '{t}' presente", t in existing)

        if not all(t in existing for t in ["incidents", "investigation_cases", "evidence"]):
            print("\nArret: tables essentielles manquantes, impossible de tester les insertions.")
            sys.exit(1)

        # ---- 3. Insertion d'un incident de test ----
        incident_id = uuid.uuid4()
        db.execute(text("""
            INSERT INTO incidents (id, title, description, source_type, source_event_id)
            VALUES (:id, 'TEST verify_migration', 'ligne de test', 'manual_test', :event_id)
        """), {"id": str(incident_id), "event_id": f"test-{incident_id}"})
        all_ok &= check("Insertion incident de test", True)

        # ---- 4. Insertion d'un investigation_case lie ----
        case_id = uuid.uuid4()
        db.execute(text("""
            INSERT INTO investigation_cases (id, incident_id, playbook_id, status)
            VALUES (:id, :incident_id, 'test_playbook', 'open')
        """), {"id": str(case_id), "incident_id": str(incident_id)})
        all_ok &= check("Insertion investigation_case lie a l'incident", True)

        # ---- 5. Insertion d'une evidence liee ----
        evidence_id = uuid.uuid4()
        db.execute(text("""
            INSERT INTO evidence (id, case_id, data_source_type, raw_data_s3_path)
            VALUES (:id, :case_id, 'iam', 's3://acip-evidence/test/verify_migration.json')
        """), {"id": str(evidence_id), "case_id": str(case_id)})
        all_ok &= check("Insertion evidence liee au case", True)

        # ---- 6. Verification de la jointure ----
        result = db.execute(text("""
            SELECT c.id, e.data_source_type
            FROM investigation_cases c
            JOIN evidence e ON e.case_id = c.id
            WHERE c.id = :case_id
        """), {"case_id": str(case_id)})
        row = result.fetchone()
        all_ok &= check("Jointure case <-> evidence fonctionnelle", row is not None)

        # ---- 7. Verification de la contrainte FK (doit echouer volontairement) ----
        fk_blocked = False
        try:
            db.execute(text("""
                INSERT INTO investigation_cases (id, incident_id, status)
                VALUES (:id, :fake_incident, 'open')
            """), {"id": str(uuid.uuid4()), "fake_incident": str(uuid.uuid4())})
            db.commit()
        except Exception:
            fk_blocked = True
            db.rollback()
        all_ok &= check("Contrainte FK active (insertion invalide bien bloquee)", fk_blocked)

        db.commit()

        # ---- 8. Nettoyage des donnees de test ----
        db.execute(text("DELETE FROM evidence WHERE id = :id"), {"id": str(evidence_id)})
        db.execute(text("DELETE FROM investigation_cases WHERE id = :id"), {"id": str(case_id)})
        db.execute(text("DELETE FROM incidents WHERE id = :id"), {"id": str(incident_id)})
        db.commit()
        all_ok &= check("Nettoyage des donnees de test", True)

    except Exception as e:
        db.rollback()
        print(f"\nERREUR INATTENDUE: {e}")
        all_ok = False
    finally:
        db.close()

    print("\n" + "=" * 50)
    if all_ok:
        print("RESULTAT GLOBAL: TOUT FONCTIONNE CORRECTEMENT")
    else:
        print("RESULTAT GLOBAL: DES PROBLEMES ONT ETE DETECTES (voir ECHEC ci-dessus)")
    print("=" * 50)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
