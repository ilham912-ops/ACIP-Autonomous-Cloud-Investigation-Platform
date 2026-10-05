"""
Logique pure de selection du playbook, independante de la base de donnees
et de SQLAlchemy -- pour rester facilement testable (cf. tests/test_playbook_selection.py).
"""
from __future__ import annotations

# Ordre de priorite des severites, du plus urgent au moins urgent.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def pick_dominant_finding_type(findings: list[tuple[str, str]]) -> str | None:
    """Choisit le finding_type qui doit determiner le playbook, parmi une
    liste de (finding_type, severity) associee a un case.

    Regle : on retient le finding de plus haute severite ; en cas d'egalite,
    le premier rencontre (ordre d'insertion / de detection) est conserve.
    """
    if not findings:
        return None

    best_type, best_severity = findings[0]
    best_rank = _SEVERITY_ORDER.get(best_severity.lower(), 99)

    for finding_type, severity in findings[1:]:
        rank = _SEVERITY_ORDER.get(severity.lower(), 99)
        if rank < best_rank:
            best_type, best_severity, best_rank = finding_type, severity, rank

    return best_type


def resolve_playbook_id(finding_type: str | None, mapping: dict[str, str]) -> str | None:
    """Retourne le playbook_id correspondant au finding_type dominant, ou
    None si aucun mapping n'existe (cas non couvert par la feuille de route
    actuelle, ex: MASS_DOWNLOAD avant la Phase 4)."""
    if finding_type is None:
        return None
    return mapping.get(finding_type)
