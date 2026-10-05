"""
Tests des regles de detection IAM (Phase 2).

Chaque test simule un lot d'evenements CloudTrail au format brut (JSON-like
dict), les convertit via CloudTrailEvent.from_raw, puis verifie que la regle
declenche (ou ne declenche pas) le Finding attendu.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.detection.cloudtrail_event import CloudTrailEvent
from app.detection.iam_rules import detect_brute_force, detect_privilege_escalation


def _console_login_event(event_id: str, ip: str, when: datetime, success: bool) -> dict:
    return {
        "eventID": event_id,
        "eventName": "ConsoleLogin",
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceIPAddress": ip,
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/test"},
        "responseElements": {"ConsoleLogin": "Success" if success else "Failure"},
    }


def _iam_action_event(
    event_id: str,
    action: str,
    actor_type: str,
    actor_arn: str,
    when: datetime,
    policy_arn: str = "",
) -> dict:
    return {
        "eventID": event_id,
        "eventName": action,
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceIPAddress": "10.0.0.5",
        "userIdentity": {"type": actor_type, "arn": actor_arn},
        "requestParameters": {"policyArn": policy_arn} if policy_arn else {},
    }


# ---------------------------------------------------------------------------
# detect_brute_force
# ---------------------------------------------------------------------------

def test_brute_force_detected_when_5_failures_in_5_minutes():
    base = datetime(2026, 8, 13, 10, 0, 0, tzinfo=timezone.utc)
    raw_events = [
        _console_login_event(f"evt-{i}", "203.0.113.10", base + timedelta(seconds=i * 30), success=False)
        for i in range(5)
    ]
    events = [CloudTrailEvent.from_raw(r) for r in raw_events]

    findings = detect_brute_force(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "BRUTE_FORCE"
    assert finding.data_source_type == "iam"
    assert finding.details["source_ip"] == "203.0.113.10"
    assert finding.confidence_score >= 0.90
    assert len(finding.evidence_event_ids) == 5


def test_no_brute_force_when_attempts_spread_over_time():
    base = datetime(2026, 8, 13, 10, 0, 0, tzinfo=timezone.utc)
    # 5 echecs mais espaces de 10 minutes chacun -> hors fenetre de 5 minutes
    raw_events = [
        _console_login_event(f"evt-{i}", "203.0.113.10", base + timedelta(minutes=i * 10), success=False)
        for i in range(5)
    ]
    events = [CloudTrailEvent.from_raw(r) for r in raw_events]

    findings = detect_brute_force(events)

    assert findings == []


def test_no_brute_force_when_fewer_than_threshold():
    base = datetime(2026, 8, 13, 10, 0, 0, tzinfo=timezone.utc)
    raw_events = [
        _console_login_event(f"evt-{i}", "203.0.113.10", base + timedelta(seconds=i * 30), success=False)
        for i in range(3)  # < BRUTE_FORCE_MIN_ATTEMPTS (5)
    ]
    events = [CloudTrailEvent.from_raw(r) for r in raw_events]

    findings = detect_brute_force(events)

    assert findings == []


def test_successful_logins_are_ignored():
    base = datetime(2026, 8, 13, 10, 0, 0, tzinfo=timezone.utc)
    raw_events = [
        _console_login_event(f"evt-{i}", "203.0.113.10", base + timedelta(seconds=i * 30), success=True)
        for i in range(5)
    ]
    events = [CloudTrailEvent.from_raw(r) for r in raw_events]

    findings = detect_brute_force(events)

    assert findings == []


def test_brute_force_separates_different_ips():
    base = datetime(2026, 8, 13, 10, 0, 0, tzinfo=timezone.utc)
    raw_events = (
        [_console_login_event(f"evt-a{i}", "203.0.113.10", base + timedelta(seconds=i * 30), success=False) for i in range(5)]
        + [_console_login_event(f"evt-b{i}", "198.51.100.20", base + timedelta(seconds=i * 30), success=False) for i in range(2)]
    )
    events = [CloudTrailEvent.from_raw(r) for r in raw_events]

    findings = detect_brute_force(events)

    # Seule l'IP avec >= 5 echecs dans la fenetre doit remonter un finding
    assert len(findings) == 1
    assert findings[0].details["source_ip"] == "203.0.113.10"


# ---------------------------------------------------------------------------
# detect_privilege_escalation
# ---------------------------------------------------------------------------

def test_privilege_escalation_detected_for_sensitive_policy_attach():
    when = datetime(2026, 8, 13, 11, 0, 0, tzinfo=timezone.utc)
    raw = _iam_action_event(
        "evt-1", "AttachUserPolicy", "IAMUser",
        "arn:aws:iam::123456789012:user/suspicious",
        when,
        policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    events = [CloudTrailEvent.from_raw(raw)]

    findings = detect_privilege_escalation(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "PRIVILEGE_ESCALATION"
    assert finding.severity.value == "critical"
    assert finding.confidence_score == 0.85
    assert "AdministratorAccess" in finding.details["target_policy"]


def test_no_finding_for_non_sensitive_policy_attach():
    when = datetime(2026, 8, 13, 11, 0, 0, tzinfo=timezone.utc)
    raw = _iam_action_event(
        "evt-1", "AttachUserPolicy", "IAMUser",
        "arn:aws:iam::123456789012:user/normal",
        when,
        policy_arn="arn:aws:iam::aws:policy/ReadOnlyAccess",
    )
    events = [CloudTrailEvent.from_raw(raw)]

    findings = detect_privilege_escalation(events)

    assert findings == []


def test_create_access_key_flagged_with_lower_confidence():
    when = datetime(2026, 8, 13, 11, 0, 0, tzinfo=timezone.utc)
    raw = _iam_action_event(
        "evt-1", "CreateAccessKey", "IAMUser",
        "arn:aws:iam::123456789012:user/normal",
        when,
    )
    events = [CloudTrailEvent.from_raw(raw)]

    findings = detect_privilege_escalation(events)

    assert len(findings) == 1
    assert findings[0].confidence_score == 0.65
    assert findings[0].severity.value == "medium"


def test_root_account_actions_are_excluded():
    when = datetime(2026, 8, 13, 11, 0, 0, tzinfo=timezone.utc)
    raw = _iam_action_event(
        "evt-1", "AttachUserPolicy", "Root",
        "arn:aws:iam::123456789012:root",
        when,
        policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    events = [CloudTrailEvent.from_raw(raw)]

    findings = detect_privilege_escalation(events)

    assert findings == []
