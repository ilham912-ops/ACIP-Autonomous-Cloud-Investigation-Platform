import uuid

from app.core.database import SessionLocal
from app.models.incident import IncidentModel, IncidentStatus, IncidentPriority
from app.models.investigation_case import InvestigationCaseModel, CaseStatus
from app.models.evidence import EvidenceModel
from app.models.finding import FindingModel, FindingType
from app.models.task import TaskModel, TaskStatus, WorkerName
from app.models.data_source_type import DataSourceType
from app.utils.s3_paths import evidence_path

db = SessionLocal()

try:
    incident = IncidentModel(
    title="Phase 1 Test Incident",
    description="Test complet du modèle de données ACIP",
    status=IncidentStatus.PENDING,
    priority=IncidentPriority.HIGH,
    source_type="cloudtrail",
    source_event_id=f"phase1-test-{uuid.uuid4()}",
    extra_data={"environment": "development"},
    assigned_to="phase1-test",
    assigned_team="SOC",
    )
    db.add(incident)
    db.flush()

    print("✅ Incident créé :", incident.id)

    # 2. INVESTIGATION CASE
    case = InvestigationCaseModel(
        incident_id=incident.id,
        playbook_id="PB-PHASE1",
        status=CaseStatus.OPEN,
    )

    db.add(case)
    db.flush()

    print("✅ Investigation Case créée :", case.id)

    # 3. EVIDENCE
    evidence = EvidenceModel(
        case_id=case.id,
        data_source_type=DataSourceType.CLOUDTRAIL,
        raw_data_s3_path = evidence_path(
    case.id,
    "cloudtrail",
    "events.json"
)
    )

    db.add(evidence)
    db.flush()

    print("✅ Evidence créée :", evidence.id)

    # 4. FINDING
    finding = FindingModel(
        case_id=case.id,
        finding_type=FindingType.BRUTE_FORCE,
        data_source_type=DataSourceType.CLOUDTRAIL,
        severity=IncidentPriority.HIGH,
        confidence_score=0.95,
    )

    db.add(finding)
    db.flush()

    print("✅ Finding créée :", finding.id)

    # 5. TASK
    task = TaskModel(
        case_id=case.id,
        worker_name=WorkerName.AWS_COLLECTOR,
        status=TaskStatus.PENDING,
    )

    db.add(task)
    db.flush()

    print("✅ Task créée :", task.id)

    # Validation
    db.commit()

    print("\n====================================")
    print("🎉 PHASE 1 TEST RÉUSSI")
    print("====================================")
    print("Incident          :", incident.id)
    print("InvestigationCase :", case.id)
    print("Evidence          :", evidence.id)
    print("Finding           :", finding.id)
    print("Task              :", task.id)
    print("S3 path           :", evidence.raw_data_s3_path)

except Exception as e:
    db.rollback()
    print("\n❌ ERREUR :", e)
    raise

finally:
    db.close()