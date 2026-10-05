"""
Evalue detect_brute_force() et detect_privilege_escalation() sur le jeu de
donnees synthetique, et calcule precision / recall / taux de faux positifs
par regle -- a comparer aux cibles du Cahier des charges ML section 4 :

    Moteur IAM : precision >= 85%, recall >= 80%, faux positifs <= 15%

Usage:
    python evaluate_iam_rules.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.detection.cloudtrail_event import CloudTrailEvent
from app.detection.iam_rules import detect_brute_force, detect_privilege_escalation
from generate_synthetic_iam_data import build_dataset, Scenario

RULE_FUNCTIONS = {
    "brute_force": detect_brute_force,
    "privilege_escalation": detect_privilege_escalation,
}


def evaluate_scenario(scenario: Scenario) -> bool:
    """Retourne True si la regle a produit au moins un finding sur ce lot
    d'evenements (peu importe lequel, un seul type de finding est possible
    par regle dans ce module)."""
    events = [CloudTrailEvent.from_raw(r) for r in scenario.events]
    rule_fn = RULE_FUNCTIONS[scenario.rule]
    findings = rule_fn(events)
    return len(findings) > 0


def compute_metrics(dataset: list[Scenario]) -> dict[str, dict[str, float]]:
    counts: dict[str, dict[str, int]] = {
        rule: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rule in RULE_FUNCTIONS
    }

    for scenario in dataset:
        predicted_positive = evaluate_scenario(scenario)
        expected_positive = scenario.expected_finding_type is not None
        c = counts[scenario.rule]

        if predicted_positive and expected_positive:
            c["tp"] += 1
        elif predicted_positive and not expected_positive:
            c["fp"] += 1
        elif not predicted_positive and expected_positive:
            c["fn"] += 1
        else:
            c["tn"] += 1

    metrics: dict[str, dict[str, float]] = {}
    for rule, c in counts.items():
        tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
        recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else float("nan")
        metrics[rule] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "fp_rate": fp_rate,
        }
    return metrics


TARGETS = {
    "brute_force": {"precision": 0.85, "recall": 0.80, "fp_rate": 0.15},
    "privilege_escalation": {"precision": 0.85, "recall": 0.80, "fp_rate": 0.15},
}


def print_report(metrics: dict[str, dict[str, float]]) -> None:
    print("=" * 72)
    print("RAPPORT D'EVALUATION - Moteur IAM (Phase 2)")
    print("=" * 72)
    for rule, m in metrics.items():
        target = TARGETS[rule]
        print(f"\n--- {rule} ---")
        print(f"  TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  TN={m['tn']}")
        print(f"  Precision : {m['precision']:.2%}  (cible >= {target['precision']:.0%})"
              f"  {'OK' if m['precision'] >= target['precision'] else 'EN DESSOUS DE LA CIBLE'}")
        print(f"  Recall    : {m['recall']:.2%}  (cible >= {target['recall']:.0%})"
              f"  {'OK' if m['recall'] >= target['recall'] else 'EN DESSOUS DE LA CIBLE'}")
        print(f"  Taux FP   : {m['fp_rate']:.2%}  (cible <= {target['fp_rate']:.0%})"
              f"  {'OK' if m['fp_rate'] <= target['fp_rate'] else 'AU DESSUS DE LA CIBLE'}")
    print("\n" + "=" * 72)
    print("NOTE : jeu synthetique construit selon la meme logique que les regles.")
    print("Ce rapport valide le harnais de mesure, pas la generalisation reelle.")
    print("Cf. Cahier des charges ML section 5.2 pour la constitution d'un jeu")
    print("labellise a partir de donnees reelles/independantes.")
    print("=" * 72)


if __name__ == "__main__":
    dataset = build_dataset(per_category=50)
    metrics = compute_metrics(dataset)
    print_report(metrics)
