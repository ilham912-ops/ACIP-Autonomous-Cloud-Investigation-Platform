"""
Templates de prompts pour l'AI Analysis Worker (Cahier des charges ML,
cas d'usage 4 : generation de resume et de recommandations).

Chaque template est contextualise par data_source_type, conformement a
l'exigence du cahier des charges section 3.4. Le prompt est "groundé" :
il n'utilise QUE les donnees passees en contexte (finding + evidence),
et demande explicitement au modele de ne pas inventer d'elements absents
des preuves (mitigation du risque d'hallucination, cf. section 6).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_SYSTEM_INSTRUCTIONS = (
    "Tu es un assistant d'investigation de securite cloud. Tu recois les "
    "faits d'un incident (finding) et les preuves associees (evidence). "
    "Redige un resume factuel destine a un analyste SOC. REGLES STRICTES : "
    "1) N'utilise QUE les informations fournies ci-dessous, n'invente "
    "aucun detail absent des preuves. 2) Si une information manque, "
    "indique-le explicitement plutot que de la deduire. 3) Reste concis "
    "(4 a 6 phrases). 4) Termine par une liste de 2 a 4 recommandations, "
    "qui restent des SUGGESTIONS a valider par l'analyste -- ne formule "
    "jamais une recommandation comme une action deja en cours ou automatique."
)

_TEMPLATES: dict[str, str] = {
    "iam": (
        "Type d'incident : activite IAM suspecte.\n"
        "Analyse ce finding en expliquant le risque d'acces non autorise ou "
        "d'escalade de privileges qu'il represente. Precise l'acteur "
        "concerne, l'action effectuee, et pourquoi cette combinaison est "
        "consideree comme suspecte."
    ),
    "s3": (
        "Type d'incident : acces suspect au stockage S3.\n"
        "Analyse ce finding en expliquant le volume et la nature de "
        "l'activite observee. Si les buckets ou prefixes concernes "
        "suggerent un niveau de sensibilite particulier, mentionne-le "
        "prudemment (uniquement a partir des noms fournis, sans supposer "
        "le contenu exact des fichiers)."
    ),
    "network": (
        "Type d'incident : activite reseau suspecte.\n"
        "Analyse ce finding en expliquant le comportement reseau observe "
        "(ex: volumetrie, regularite, destination) et le risque associe."
    ),
}

_DEFAULT_TEMPLATE = (
    "Type d'incident : activite suspecte.\n"
    "Analyse ce finding a partir des informations fournies ci-dessous."
)


@dataclass
class FindingContext:
    """Contexte minimal necessaire pour construire un prompt -- construit a
    partir d'un FindingModel + des Evidence associees en base."""
    finding_type: str
    data_source_type: str
    severity: str
    confidence_score: float
    details: dict[str, Any]
    evidence_s3_paths: list[str]


def build_prompt(context: FindingContext) -> str:
    """Construit le prompt complet (system + contexte du finding) a envoyer
    a l'API Claude pour generer le resume de l'AI Analysis Worker."""
    template = _TEMPLATES.get(context.data_source_type, _DEFAULT_TEMPLATE)

    details_lines = "\n".join(f"  - {k}: {v}" for k, v in context.details.items())
    evidence_lines = "\n".join(f"  - {p}" for p in context.evidence_s3_paths) or "  (aucune reference d'evidence disponible)"

    return (
        f"{_SYSTEM_INSTRUCTIONS}\n\n"
        f"{template}\n\n"
        f"--- Finding ---\n"
        f"finding_type: {context.finding_type}\n"
        f"data_source_type: {context.data_source_type}\n"
        f"severity: {context.severity}\n"
        f"confidence_score: {context.confidence_score}\n"
        f"details:\n{details_lines}\n\n"
        f"--- References d'evidence (S3) ---\n"
        f"{evidence_lines}\n"
    )
