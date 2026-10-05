"""
Wrapper normalise autour d'une entree VPC Flow Log brute.

Format VPC Flow Logs (version par defaut AWS) :
version account-id interface-id srcaddr dstaddr srcport dstport protocol
packets bytes start end action log-status
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class VPCFlowLogEvent:
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    protocol: int
    bytes_transferred: int
    start_time: datetime
    end_time: datetime
    action: str  # ACCEPT ou REJECT
    raw: dict[str, Any]

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "VPCFlowLogEvent":
        return cls(
            src_addr=raw["srcaddr"],
            dst_addr=raw["dstaddr"],
            src_port=int(raw["srcport"]),
            dst_port=int(raw["dstport"]),
            protocol=int(raw["protocol"]),
            bytes_transferred=int(raw.get("bytes", 0)),
            start_time=datetime.fromtimestamp(int(raw["start"]), tz=timezone.utc),
            end_time=datetime.fromtimestamp(int(raw["end"]), tz=timezone.utc),
            action=raw.get("action", "ACCEPT"),
            raw=raw,
        )
