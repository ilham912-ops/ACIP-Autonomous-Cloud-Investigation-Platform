"""
Wrapper normalise autour d'un evenement CloudTrail brut.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class CloudTrailEvent:
    event_id: str
    event_name: str
    event_time: datetime
    source_ip: str
    user_identity_type: str
    user_identity_arn: str
    response_success: Optional[bool]
    request_parameters: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "CloudTrailEvent":
        user_identity = raw.get("userIdentity", {}) or {}
        response_elements = raw.get("responseElements") or {}

        response_success: Optional[bool] = None
        if raw.get("eventName") == "ConsoleLogin":
            response_success = response_elements.get("ConsoleLogin") == "Success"

        event_time_raw = raw.get("eventTime", "")
        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))

        return cls(
            event_id=raw.get("eventID", ""),
            event_name=raw.get("eventName", ""),
            event_time=event_time,
            source_ip=raw.get("sourceIPAddress", "unknown"),
            user_identity_type=user_identity.get("type", "Unknown"),
            user_identity_arn=user_identity.get("arn", ""),
            response_success=response_success,
            request_parameters=raw.get("requestParameters") or {},
            raw=raw,
        )
