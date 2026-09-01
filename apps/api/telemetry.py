"""Canonical telemetry contracts for FlowCrypid's future multi-source data plane."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field


class TelemetryBase(BaseModel):
    event_id: str = Field(min_length=8, max_length=128)
    observed_at: datetime
    source_ip: str | None = None
    asset_id: str | None = None
    user_id: str | None = None
    tenant_id: str = "default"


class NetworkFlowEvent(TelemetryBase):
    event_type: Literal["network_flow"] = "network_flow"
    destination_ip: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: int | None = Field(default=None, ge=0, le=255)
    bytes_out: int = Field(default=0, ge=0)
    bytes_in: int = Field(default=0, ge=0)
    packets_out: int = Field(default=0, ge=0)
    packets_in: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0, ge=0)
    destination_domain: str | None = None


class DNSEvent(TelemetryBase):
    event_type: Literal["dns"] = "dns"
    query: str
    query_type: str = "A"
    response_code: str | None = None
    answer_count: int = Field(default=0, ge=0)
    query_length: int = Field(default=0, ge=0)
    entropy: float | None = Field(default=None, ge=0)
    resolver_ip: str | None = None


class EndpointEvent(TelemetryBase):
    event_type: Literal["endpoint"] = "endpoint"
    action: str
    path: str | None = None
    process_name: str | None = None
    parent_process: str | None = None
    sensitivity: Literal["unknown", "low", "medium", "high", "critical"] = "unknown"


class AuthenticationEvent(TelemetryBase):
    event_type: Literal["authentication"] = "authentication"
    action: Literal["login", "logout", "failure", "mfa_challenge", "mfa_success"]
    success: bool
    authentication_method: str | None = None
    source_country: str | None = None


class FileAccessEvent(TelemetryBase):
    event_type: Literal["file_access"] = "file_access"
    action: Literal["read", "write", "archive", "compress", "encrypt", "delete"]
    path: str | None = None
    bytes_accessed: int = Field(default=0, ge=0)
    sensitivity: Literal["unknown", "low", "medium", "high", "critical"] = "unknown"


TelemetryEvent = Annotated[
    NetworkFlowEvent | DNSEvent | EndpointEvent | AuthenticationEvent | FileAccessEvent,
    Field(discriminator="event_type"),
]


def normalize_event(event: TelemetryEvent) -> dict[str, object]:
    """Return a stable, JSON-compatible event shape for correlation and storage."""
    payload = event.model_dump(mode="json")
    payload["observed_at"] = event.observed_at.isoformat()
    return payload
