"""
Investigation Orchestrator - selection et declenchement du playbook.

Relie les Findings d'un case (Phase 2) au playbook correspondant (Phase 3):
1. Lit les findings du case en base.
2. Determine le finding dominant (plus haute severite).
3. Resout le playbook_id via la table de mapping.
4. Met a jour investigation_cases.playbook_id.
5. Cree une ligne Task (status=pending) par tache definie dans le playbook.
6. Publie chaque tache sur la file d'attente (SQS ou local selon l'environnement).

Rappel de perimetre (Cahier des charges v1.1, section 1.3) : ce module ne
declenche AUCUNE action corrective automatique. Les recommended_actions du
playbook sont uniquement affichees a l'analyste dans le dashboard.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.models.finding import FindingModel
from app.models.investigation_case import InvestigationCaseModel
from app.models.task import TaskModel, TaskStatus, WorkerName

from .playbook_loader import Playbook, load_mapping, load_playbooks
from .playbook_selection import pick_dominant_finding_type, resolve_playbook_id
from .queue_adapter import QueueAdapter, get_queue_adapter


class NoPlaybookAvailableError(Exception):
    """Leve quand aucun playbook n'est mappe pour le(s) finding_type(s) du case."""


def select_and_trigger_playbook(
    db: Session,
    case_id: UUID,
    queue: QueueAdapter | None = None,
) -> tuple[InvestigationCaseModel, list[TaskModel]]:
    """Point d'entree principal, a appeler par l'Investigation Orchestrator
    une fois qu'un ou plusieurs Findings ont ete enregistres pour un case."""
    queue = queue or get_queue_adapter()

    case = db.query(InvestigationCaseModel).filter(InvestigationCaseModel.id == case_id).one()

    findings = db.query(FindingModel).filter(FindingModel.case_id == case_id).all()
    finding_pairs = [(f.finding_type.value, f.severity.value) for f in findings]

    dominant_type = pick_dominant_finding_type(finding_pairs)

    mapping = load_mapping()
    playbook_id = resolve_playbook_id(dominant_type, mapping)

    if playbook_id is None:
        raise NoPlaybookAvailableError(
            f"Aucun playbook mappe pour le finding_type dominant '{dominant_type}' "
            f"(case_id={case_id}). Ajoutez une entree dans config/playbook_mapping.json."
        )

    playbooks = load_playbooks()
    playbook = playbooks[playbook_id]

    case.playbook_id = playbook.playbook_id
    db.add(case)

    tasks: list[TaskModel] = []
    for playbook_task in playbook.tasks:
        task = TaskModel(
            case_id=case.id,
            worker_name=WorkerName(playbook_task.worker_name),
            status=TaskStatus.PENDING,
        )
        db.add(task)
        tasks.append(task)

    db.commit()
    for t in tasks:
        db.refresh(t)

    _publish_tasks(queue, case, playbook, tasks)

    return case, tasks


def _publish_tasks(
    queue: QueueAdapter,
    case: InvestigationCaseModel,
    playbook: Playbook,
    tasks: list[TaskModel],
) -> None:
    for task, playbook_task in zip(tasks, playbook.tasks):
        queue.publish({
            "task_id": str(task.id),
            "case_id": str(case.id),
            "playbook_id": playbook.playbook_id,
            "worker_name": playbook_task.worker_name,
            "action": playbook_task.action,
            "description": playbook_task.description,
        })
