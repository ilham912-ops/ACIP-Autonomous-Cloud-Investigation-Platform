"""
Tests de detect_mass_download() (Phase 4).
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.detection.s3_event import S3Event
from app.detection.s3_rules import detect_mass_download


def _get_object_event(event_id: str, actor: str, bucket: str, when: datetime, bytes_out: int = 1024) -> dict:
    return {
        "eventID": event_id,
        "eventName": "GetObject",
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceIPAddress": "10.0.0.9",
        "userIdentity": {"arn": actor},
        "requestParameters": {"bucketName": bucket, "key": f"file-{event_id}.dat"},
        "additionalEventData": {"bytesTransferredOut": bytes_out},
    }


def test_mass_download_detected_when_20_objects_in_10_minutes():
    base = datetime(2026, 8, 14, 10, 0, 0, tzinfo=timezone.utc)
    actor = "arn:aws:iam::123456789012:user/compromised"
    raw_events = [
        _get_object_event(f"evt-{i}", actor, "acip-sensitive-data", base + timedelta(seconds=i * 20))
        for i in range(20)
    ]
    events = [S3Event.from_raw(r) for r in raw_events]

    findings = detect_mass_download(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "MASS_DOWNLOAD"
    assert finding.data_source_type == "s3"
    assert finding.details["actor"] == actor
    assert finding.details["objects_in_window"] == 20
    assert finding.confidence_score >= 0.85


def test_no_finding_when_below_threshold():
    base = datetime(2026, 8, 14, 10, 0, 0, tzinfo=timezone.utc)
    actor = "arn:aws:iam::123456789012:user/normal"
    raw_events = [
        _get_object_event(f"evt-{i}", actor, "acip-reports", base + timedelta(seconds=i * 20))
        for i in range(10)  # < seuil de 20
    ]
    events = [S3Event.from_raw(r) for r in raw_events]

    findings = detect_mass_download(events)

    assert findings == []


def test_no_finding_when_spread_over_time():
    base = datetime(2026, 8, 14, 10, 0, 0, tzinfo=timezone.utc)
    actor = "arn:aws:iam::123456789012:user/scheduled_export"
    # 20 objets mais espaces de 2 minutes chacun -> hors fenetre de 10 minutes
    raw_events = [
        _get_object_event(f"evt-{i}", actor, "acip-reports", base + timedelta(minutes=i * 2))
        for i in range(20)
    ]
    events = [S3Event.from_raw(r) for r in raw_events]

    findings = detect_mass_download(events)

    assert findings == []


def test_different_actors_evaluated_separately():
    base = datetime(2026, 8, 14, 10, 0, 0, tzinfo=timezone.utc)
    actor_a = "arn:aws:iam::123456789012:user/suspect"
    actor_b = "arn:aws:iam::123456789012:user/normal"

    raw_events = (
        [_get_object_event(f"a-{i}", actor_a, "acip-data", base + timedelta(seconds=i * 15)) for i in range(20)]
        + [_get_object_event(f"b-{i}", actor_b, "acip-data", base + timedelta(seconds=i * 15)) for i in range(5)]
    )
    events = [S3Event.from_raw(r) for r in raw_events]

    findings = detect_mass_download(events)

    assert len(findings) == 1
    assert findings[0].details["actor"] == actor_a


def test_put_and_delete_events_are_ignored():
    """detect_mass_download ne doit reagir qu'aux GetObject, pas aux
    ecritures/suppressions (hors perimetre de cette regle)."""
    base = datetime(2026, 8, 14, 10, 0, 0, tzinfo=timezone.utc)
    actor = "arn:aws:iam::123456789012:user/writer"
    raw_events = [
        {
            "eventID": f"put-{i}",
            "eventName": "PutObject",
            "eventTime": (base + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sourceIPAddress": "10.0.0.9",
            "userIdentity": {"arn": actor},
            "requestParameters": {"bucketName": "acip-uploads", "key": f"upload-{i}.dat"},
        }
        for i in range(25)
    ]
    events = [S3Event.from_raw(r) for r in raw_events]

    findings = detect_mass_download(events)

    assert findings == []
