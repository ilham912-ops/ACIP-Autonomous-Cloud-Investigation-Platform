"""
Charge les playbooks JSON depuis config/playbooks/ et la table de mapping
finding_type -> playbook_id depuis config/playbook_mapping.json.

Garder ces fichiers externes au code (plutot que codes en dur) permet de
modifier un playbook ou d'ajouter un mapping sans redeployer le module de
detection (exigence du Cahier des charges ML, section 3.2).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


@dataclass
class PlaybookTask:
    worker_name: str
    action: str
    description: str = ""


@dataclass
class Playbook:
    playbook_id: str
    name: str
    description: str
    applicable_finding_types: list[str]
    priority: str
    tasks: list[PlaybookTask] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Playbook":
        required = ["playbook_id", "name", "applicable_finding_types", "tasks"]
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"Playbook invalide, champs manquants: {missing}")

        tasks = [PlaybookTask(**t) for t in data["tasks"]]
        return cls(
            playbook_id=data["playbook_id"],
            name=data["name"],
            description=data.get("description", ""),
            applicable_finding_types=data["applicable_finding_types"],
            priority=data.get("priority", "MEDIUM"),
            tasks=tasks,
            recommended_actions=data.get("recommended_actions", []),
        )


def load_playbooks(config_dir: Path = DEFAULT_CONFIG_DIR) -> dict[str, Playbook]:
    """Charge tous les fichiers .json de config/playbooks/ dans un dict
    indexe par playbook_id."""
    playbooks_dir = config_dir / "playbooks"
    playbooks: dict[str, Playbook] = {}

    for json_file in sorted(playbooks_dir.glob("*.json")):
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        playbook = Playbook.from_dict(data)
        playbooks[playbook.playbook_id] = playbook

    return playbooks


def load_mapping(config_dir: Path = DEFAULT_CONFIG_DIR) -> dict[str, str]:
    """Charge la table finding_type -> playbook_id."""
    mapping_file = config_dir / "playbook_mapping.json"
    with open(mapping_file, "r", encoding="utf-8") as f:
        return json.load(f)
