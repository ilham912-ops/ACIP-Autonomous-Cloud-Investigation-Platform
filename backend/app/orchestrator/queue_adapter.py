"""
Abstraction de publication des taches vers la file d'attente.

En production (architecture technique ACIP), les taches sont publiees vers
Amazon SQS pour etre consommees par les workers Docker. En developpement
local, sans acces AWS configure, LocalQueueAdapter journalise simplement
les messages -- ce qui permet de tester toute la chaine de selection de
playbook sans dependance externe.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Protocol

logger = logging.getLogger("acip.orchestrator.queue")


class QueueAdapter(Protocol):
    def publish(self, message: dict[str, Any]) -> None: ...


class LocalQueueAdapter:
    """Adaptateur de developpement : journalise les messages au lieu de les
    envoyer a une vraie file. Utile pour les tests et le mode local."""

    def __init__(self) -> None:
        self.published: list[dict[str, Any]] = []

    def publish(self, message: dict[str, Any]) -> None:
        self.published.append(message)
        logger.info("Tache publiee (mode local) : %s", json.dumps(message, default=str))


class SQSQueueAdapter:
    """Adaptateur de production : publie sur Amazon SQS via boto3.
    Necessite la variable d'environnement SQS_QUEUE_URL et des credentials
    AWS valides (IAM role EC2 ou variables d'environnement standard)."""

    def __init__(self, queue_url: str | None = None) -> None:
        import boto3  # import local: evite la dependance boto3 en mode dev

        self.queue_url = queue_url or os.environ["SQS_QUEUE_URL"]
        self._client = boto3.client("sqs")

    def publish(self, message: dict[str, Any]) -> None:
        self._client.send_message(
            QueueUrl=self.queue_url,
            MessageBody=json.dumps(message, default=str),
        )


def get_queue_adapter() -> QueueAdapter:
    """Choisit l'adaptateur selon la variable d'environnement USE_SQS
    (true -> SQS reel, absent/false -> adaptateur local)."""
    if os.environ.get("USE_SQS", "false").lower() == "true":
        return SQSQueueAdapter()
    return LocalQueueAdapter()
