"""
Tests de detect_port_scan() et detect_beaconing() (Phase 5).
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.detection.network_event import VPCFlowLogEvent
from app.detection.network_rules import detect_port_scan, detect_beaconing


def _flow(src, dst, src_port, dst_port, start, duration_s=1, bytes_out=500, action="ACCEPT"):
    return {
        "srcaddr": src,
        "dstaddr": dst,
        "srcport": src_port,
        "dstport": dst_port,
        "protocol": 6,
        "bytes": bytes_out,
        "start": int(start.timestamp()),
        "end": int((start + timedelta(seconds=duration_s)).timestamp()),
        "action": action,
    }


# ---------------------------------------------------------------------------
# detect_port_scan
# ---------------------------------------------------------------------------

def test_port_scan_detected_when_15_distinct_ports_in_5_minutes():
    base = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    raw = [
        _flow("198.51.100.5", "10.0.1.20", 50000 + i, 1000 + i, base + timedelta(seconds=i * 10))
        for i in range(15)
    ]
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    findings = detect_port_scan(events)

    assert len(findings) == 1
    assert findings[0].finding_type == "PORT_SCAN"
    assert findings[0].data_source_type == "network"
    assert findings[0].details["distinct_ports_contacted"] == 15


def test_no_port_scan_when_below_threshold():
    base = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    raw = [
        _flow("198.51.100.5", "10.0.1.20", 50000 + i, 1000 + i, base + timedelta(seconds=i * 10))
        for i in range(5)
    ]
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    assert detect_port_scan(events) == []


def test_no_port_scan_when_spread_over_time():
    base = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    raw = [
        _flow("198.51.100.5", "10.0.1.20", 50000 + i, 1000 + i, base + timedelta(minutes=i * 20))
        for i in range(15)
    ]
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    assert detect_port_scan(events) == []


def test_repeated_same_port_is_not_a_scan():
    """Beaucoup de connexions mais vers UN SEUL port -> pas un scan."""
    base = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    raw = [
        _flow("198.51.100.5", "10.0.1.20", 50000 + i, 443, base + timedelta(seconds=i * 5))
        for i in range(20)
    ]
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    assert detect_port_scan(events) == []


# ---------------------------------------------------------------------------
# detect_beaconing
# ---------------------------------------------------------------------------

def test_beaconing_detected_for_regular_interval():
    base = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    # Connexion toutes les 60 secondes pile, 8 fois -> tres regulier
    raw = [
        _flow("10.0.2.15", "203.0.113.99", 44000, 443, base + timedelta(seconds=i * 60))
        for i in range(8)
    ]
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    findings = detect_beaconing(events)

    assert len(findings) == 1
    assert findings[0].finding_type == "C2_BEACONING"
    assert findings[0].details["destination_ip"] == "203.0.113.99"
    assert findings[0].confidence_score >= 0.70


def test_no_beaconing_for_irregular_interval():
    base = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    offsets = [0, 12, 45, 130, 133, 300, 301, 600]  # tres irregulier
    raw = [
        _flow("10.0.2.15", "203.0.113.99", 44000, 443, base + timedelta(seconds=o))
        for o in offsets
    ]
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    assert detect_beaconing(events) == []


def test_no_beaconing_when_below_min_connections():
    base = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    raw = [
        _flow("10.0.2.15", "203.0.113.99", 44000, 443, base + timedelta(seconds=i * 60))
        for i in range(3)  # < BEACONING_MIN_CONNECTIONS
    ]
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    assert detect_beaconing(events) == []


def test_no_beaconing_for_rapid_burst():
    """Rafale de connexions tres rapprochees (< seuil minimal) -> pas un beacon."""
    base = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    raw = [
        _flow("10.0.2.15", "203.0.113.99", 44000, 443, base + timedelta(seconds=i * 0.5))
        for i in range(8)
    ]
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    assert detect_beaconing(events) == []


def test_beaconing_separates_different_destination_pairs():
    base = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    raw = (
        [_flow("10.0.2.15", "203.0.113.99", 44000, 443, base + timedelta(seconds=i * 60)) for i in range(8)]
        + [_flow("10.0.2.15", "203.0.113.50", 44000, 443, base + timedelta(seconds=i * 7)) for i in range(3)]
    )
    events = [VPCFlowLogEvent.from_raw(r) for r in raw]

    findings = detect_beaconing(events)

    assert len(findings) == 1
    assert findings[0].details["destination_ip"] == "203.0.113.99"
