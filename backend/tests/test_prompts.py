"""
Tests du module de prompts pour l'AI Analysis Worker (Phase 4).
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.ai.prompts import build_prompt, FindingContext


def _sample_context(data_source_type: str) -> FindingContext:
    return FindingContext(
        finding_type="MASS_DOWNLOAD",
        data_source_type=data_source_type,
        severity="high",
        confidence_score=0.9,
        details={"actor": "arn:aws:iam::123456789012:user/test", "objects_in_window": 25},
        evidence_s3_paths=["s3://acip-evidence/evidence/case-1/s3/access_logs.json"],
    )


def test_prompt_contains_finding_details():
    prompt = build_prompt(_sample_context("s3"))
    assert "MASS_DOWNLOAD" in prompt
    assert "objects_in_window" in prompt
    assert "0.9" in prompt


def test_prompt_uses_s3_specific_template():
    prompt = build_prompt(_sample_context("s3"))
    assert "stockage S3" in prompt


def test_prompt_uses_iam_specific_template():
    prompt = build_prompt(_sample_context("iam"))
    assert "IAM" in prompt


def test_prompt_falls_back_to_default_for_unknown_source():
    prompt = build_prompt(_sample_context("runtime"))
    assert "activite suspecte" in prompt


def test_prompt_includes_anti_hallucination_instructions():
    prompt = build_prompt(_sample_context("s3"))
    assert "N'utilise QUE les informations fournies" in prompt


def test_prompt_includes_evidence_references():
    prompt = build_prompt(_sample_context("s3"))
    assert "s3://acip-evidence/evidence/case-1/s3/access_logs.json" in prompt


def test_prompt_handles_missing_evidence_gracefully():
    context = _sample_context("s3")
    context.evidence_s3_paths = []
    prompt = build_prompt(context)
    assert "aucune reference d'evidence disponible" in prompt
