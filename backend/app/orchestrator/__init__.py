from .playbook_loader import Playbook, PlaybookTask, load_playbooks, load_mapping
from .playbook_selection import pick_dominant_finding_type, resolve_playbook_id
from .queue_adapter import get_queue_adapter, LocalQueueAdapter, QueueAdapter

__all__ = [
    "Playbook",
    "PlaybookTask",
    "load_playbooks",
    "load_mapping",
    "pick_dominant_finding_type",
    "resolve_playbook_id",
    "select_and_trigger_playbook",
    "NoPlaybookAvailableError",
    "get_queue_adapter",
    "LocalQueueAdapter",
    "QueueAdapter",
]


def __getattr__(name):
    # Import paresseux : select_and_trigger_playbook/NoPlaybookAvailableError
    # dependent de SQLAlchemy et des modeles ORM du projet (app.models.*),
    # qui ne sont pas necessaires pour utiliser la logique de selection pure
    # ou les tests unitaires. On ne les importe qu'a l'usage.
    if name in ("select_and_trigger_playbook", "NoPlaybookAvailableError"):
        from .playbook_selector import select_and_trigger_playbook, NoPlaybookAvailableError
        return {"select_and_trigger_playbook": select_and_trigger_playbook,
                "NoPlaybookAvailableError": NoPlaybookAvailableError}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
