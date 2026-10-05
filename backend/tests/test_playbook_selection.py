"""
Tests de la Phase 3 : logique de selection (pure, sans DB) et chargement
des fichiers playbooks/mapping.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.orchestrator.playbook_selection import pick_dominant_finding_type, resolve_playbook_id
from app.orchestrator.playbook_loader import load_playbooks, load_mapping, Playbook
from app.orchestrator.queue_adapter import LocalQueueAdapter

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


# ---------------------------------------------------------------------------
# pick_dominant_finding_type
# ---------------------------------------------------------------------------

def test_picks_highest_severity():
    findings = [("BRUTE_FORCE", "high"), ("PRIVILEGE_ESCALATION", "critical")]
    assert pick_dominant_finding_type(findings) == "PRIVILEGE_ESCALATION"


def test_keeps_first_on_severity_tie():
    findings = [("BRUTE_FORCE", "high"), ("SECURITY_GROUP_OPEN", "high")]
    assert pick_dominant_finding_type(findings) == "BRUTE_FORCE"


def test_empty_findings_returns_none():
    assert pick_dominant_finding_type([]) is None


def test_single_finding():
    assert pick_dominant_finding_type([("BRUTE_FORCE", "high")]) == "BRUTE_FORCE"


# ---------------------------------------------------------------------------
# resolve_playbook_id
# ---------------------------------------------------------------------------

def test_resolve_known_mapping():
    mapping = {"BRUTE_FORCE": "credential_attack"}
    assert resolve_playbook_id("BRUTE_FORCE", mapping) == "credential_attack"


def test_resolve_unknown_finding_type_returns_none():
    mapping = {"BRUTE_FORCE": "credential_attack"}
    assert resolve_playbook_id("CRYPTOMINING", mapping) is None


def test_resolve_none_finding_type_returns_none():
    mapping = {"BRUTE_FORCE": "credential_attack"}
    assert resolve_playbook_id(None, mapping) is None


# ---------------------------------------------------------------------------
# Chargement reel des fichiers config/
# ---------------------------------------------------------------------------

def test_load_mapping_contains_expected_entries():
    mapping = load_mapping(CONFIG_DIR)
    assert mapping["BRUTE_FORCE"] == "credential_attack"
    assert mapping["PRIVILEGE_ESCALATION"] == "privilege_abuse"


def test_load_playbooks_contains_both_playbooks():
    playbooks = load_playbooks(CONFIG_DIR)
    assert "credential_attack" in playbooks
    assert "privilege_abuse" in playbooks


def test_credential_attack_playbook_structure():
    playbooks = load_playbooks(CONFIG_DIR)
    pb = playbooks["credential_attack"]
    assert isinstance(pb, Playbook)
    assert pb.priority == "HIGH"
    assert len(pb.tasks) == 3
    assert all(t.worker_name for t in pb.tasks)
    assert len(pb.recommended_actions) >= 3


def test_privilege_abuse_playbook_structure():
    playbooks = load_playbooks(CONFIG_DIR)
    pb = playbooks["privilege_abuse"]
    assert pb.priority == "CRITICAL"
    assert len(pb.tasks) == 4


def test_all_mapped_playbooks_exist_on_disk():
    """Garde-fou : chaque playbook_id du mapping doit correspondre a un
    fichier JSON reellement present, pour eviter une erreur silencieuse
    en production."""
    mapping = load_mapping(CONFIG_DIR)
    playbooks = load_playbooks(CONFIG_DIR)
    for finding_type, playbook_id in mapping.items():
        assert playbook_id in playbooks, f"Playbook '{playbook_id}' (mappe pour {finding_type}) introuvable"


# ---------------------------------------------------------------------------
# LocalQueueAdapter
# ---------------------------------------------------------------------------

def test_local_queue_adapter_records_messages():
    queue = LocalQueueAdapter()
    queue.publish({"task_id": "abc", "action": "test"})
    assert len(queue.published) == 1
    assert queue.published[0]["action"] == "test"
