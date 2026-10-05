"""
Wrapper normalise autour d'un evenement S3 Data Event / Access Log brut
(format CloudTrail Data Events pour S3 : GetObject, PutObject, DeleteObject).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class S3Event:
    event_id: str
    event_name: str  # GetObject, PutObject, DeleteObject, PutBucketAcl...
    event_time: datetime
    bucket_name: str
    object_key: str
    source_ip: str
    actor_arn: str
    bytes_transferred: Optional[int] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "S3Event":
        user_identity = raw.get("userIdentity", {}) or {}
        request_parameters = raw.get("requestParameters", {}) or {}
        additional_data = raw.get("additionalEventData", {}) or {}

        event_time_raw = raw.get("eventTime", "")
        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))

        return cls(
            event_id=raw.get("eventID", ""),
            event_name=raw.get("eventName", ""),
            event_time=event_time,
            bucket_name=request_parameters.get("bucketName", "unknown"),
            object_key=request_parameters.get("key", ""),
            source_ip=raw.get("sourceIPAddress", "unknown"),
            actor_arn=user_identity.get("arn", ""),
            bytes_transferred=additional_data.get("bytesTransferredOut"),
            raw=raw,
        )
