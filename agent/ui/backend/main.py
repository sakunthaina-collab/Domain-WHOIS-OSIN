"""Trustworthy Agent defensive-only backend prototype.

Developer: NAKARIN SAKULTHAI
License: MIT License

This service intentionally keeps containment actions in demo mode. It never
contacts a target, performs exploitation, scans, brute-forces, or attacks back.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator


app = FastAPI(
    title="Trustworthy Agent Defensive API",
    version="0.2.0",
    description="Telemetry, explainable risk scoring, evidence integrity, and human-approved demo containment.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Actor"],
)

MAX_TEXT = 500
ALLOWED_EVENT_TYPES = {
    "login_anomaly",
    "remote_command",
    "credential_access_attempt",
    "telemetry_deviation",
    "api_chain",
    "threat_intel_match",
}
OFFENSIVE_ACTIONS = {"exploit", "attack_back", "brute_force", "credential_dump", "port_scan"}
CONTAINMENT_ACTIONS = {"revoke_token", "quarantine_case", "freeze_transaction", "manual_control"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def clean_text(value: str, field_name: str) -> str:
    value = value.strip()
    if not value or len(value) > MAX_TEXT:
        raise ValueError(f"{field_name} must be 1-{MAX_TEXT} characters")
    if "\x00" in value:
        raise ValueError(f"{field_name} contains an invalid character")
    return value


class EventType(str, Enum):
    login_anomaly = "login_anomaly"
    remote_command = "remote_command"
    credential_access_attempt = "credential_access_attempt"
    telemetry_deviation = "telemetry_deviation"
    api_chain = "api_chain"
    threat_intel_match = "threat_intel_match"


class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: EventType
    source: str = Field(min_length=1, max_length=MAX_TEXT)
    asset_id: str = Field(min_length=1, max_length=MAX_TEXT)
    occurred_at: datetime | None = None
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=30)

    @field_validator("source", "asset_id")
    @classmethod
    def validate_text(cls, value: str, info: Any) -> str:
        return clean_text(value, info.field_name)

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, value: dict[str, str | int | float | bool]) -> dict[str, str | int | float | bool]:
        for key, item in value.items():
            clean_text(key, "attribute key")
            if isinstance(item, str):
                clean_text(item, f"attribute {key}")
        return value


class Signal(BaseModel):
    factor: str
    category: Literal["fact", "signal", "inference"]
    weight: int = Field(ge=0, le=100)
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)


class AuditEntry(BaseModel):
    sequence: int
    ts: str
    action: str
    actor: str
    metadata: dict[str, str] = Field(default_factory=dict)
    previous_hash: str
    entry_hash: str


class EvidenceRecord(BaseModel):
    evidence_id: str
    claim: str
    source: str
    retrieved_at: str
    raw_response_sha256: str


class Incident(BaseModel):
    incident_id: str
    status: Literal["open", "pending_approval", "contained", "closed"]
    severity: Literal["low", "medium", "high", "critical"]
    risk_score: int = Field(ge=0, le=100)
    confidence: Literal["low", "medium", "high"]
    attribution: Literal["unknown", "unconfirmed"] = "unknown"
    signals: list[Signal]
    evidence: list[EvidenceRecord]
    audit_trail: list[AuditEntry]
    pending_approval_id: str | None = None
    requested_action: str | None = None
    created_at: str
    updated_at: str


class ContainmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    reason: str = Field(min_length=10, max_length=MAX_TEXT)
    requested_by: str = Field(min_length=1, max_length=MAX_TEXT)

    @field_validator("action", "reason", "requested_by")
    @classmethod
    def validate_request_text(cls, value: str, info: Any) -> str:
        return clean_text(value, info.field_name)


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool
    approver: str = Field(min_length=1, max_length=MAX_TEXT)
    note: str = Field(min_length=5, max_length=MAX_TEXT)

    @field_validator("approver", "note")
    @classmethod
    def validate_decision_text(cls, value: str, info: Any) -> str:
        return clean_text(value, info.field_name)


class MemoryStore:
    def __init__(self) -> None:
        self.lock = Lock()
        self.incidents: dict[str, Incident] = {}

    def add_audit(self, incident: Incident, action: str, actor: str, metadata: dict[str, str] | None = None) -> None:
        previous_hash = incident.audit_trail[-1].entry_hash if incident.audit_trail else "GENESIS"
        sequence = len(incident.audit_trail) + 1
        payload = {
            "sequence": sequence,
            "ts": iso_now(),
            "action": action,
            "actor": actor,
            "metadata": metadata or {},
            "previous_hash": previous_hash,
        }
        entry_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        incident.audit_trail.append(AuditEntry(**payload, entry_hash=entry_hash))
        incident.updated_at = payload["ts"]

    def verify_chain(self, incident: Incident) -> bool:
        previous_hash = "GENESIS"
        for entry in incident.audit_trail:
            payload = {
                "sequence": entry.sequence,
                "ts": entry.ts,
                "action": entry.action,
                "actor": entry.actor,
                "metadata": entry.metadata,
                "previous_hash": previous_hash,
            }
            expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if entry.previous_hash != previous_hash or entry.entry_hash != expected:
                return False
            previous_hash = entry.entry_hash
        return True


store = MemoryStore()


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def derive_signal(event: TelemetryEvent) -> Signal:
    rules: dict[EventType, tuple[str, str, int, str]] = {
        EventType.login_anomaly: ("login_anomaly", "fact", 15, "Login occurred outside the observed baseline"),
        EventType.remote_command: ("remote_command_outside_window", "signal", 25, "Remote command requires maintenance-window evidence"),
        EventType.credential_access_attempt: ("credential_access_attempt", "signal", 25, "Credential access pattern detected; no credential was accessed by this service"),
        EventType.telemetry_deviation: ("telemetry_deviation", "fact", 15, "Telemetry moved outside the configured safety baseline"),
        EventType.api_chain: ("multi_service_sequence", "signal", 15, "Multiple services were called in a short sequence"),
        EventType.threat_intel_match: ("threat_intel_match", "inference", 10, "Passive intelligence matched a known risk pattern; attribution remains unknown"),
    }
    factor, category, weight, detail = rules[event.event_type]
    return Signal(factor=factor, category=category, weight=weight, detail=detail)


def risk_confidence(signals: list[Signal], event: TelemetryEvent) -> str:
    if event.attributes.get("authoritative_source") is True and len(signals) >= 2:
        return "high"
    if event.severity in {"high", "critical"} or len(signals) >= 2:
        return "medium"
    return "low"


def create_incident(event: TelemetryEvent, actor: str) -> Incident:
    signal = derive_signal(event)
    evidence_id = f"ev_{secrets.token_hex(6)}"
    evidence_payload = {
        "event_type": event.event_type.value,
        "source": event.source,
        "asset_id": event.asset_id,
        "occurred_at": (event.occurred_at or utc_now()).isoformat(),
        "attributes": event.attributes,
    }
    evidence = EvidenceRecord(
        evidence_id=evidence_id,
        claim=signal.detail,
        source=event.source,
        retrieved_at=iso_now(),
        raw_response_sha256=sha256_payload(evidence_payload),
    )
    signal.evidence_ids.append(evidence_id)
    score = min(100, signal.weight + (15 if event.severity == "high" else 25 if event.severity == "critical" else 0))
    severity = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    now = iso_now()
    incident = Incident(
        incident_id=f"INC-{utc_now().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}",
        status="open",
        severity=severity,
        risk_score=score,
        confidence=risk_confidence([signal], event),
        signals=[signal],
        evidence=[evidence],
        audit_trail=[],
        created_at=now,
        updated_at=now,
    )
    store.add_audit(incident, "incident_created", actor, {"event_type": event.event_type.value})
    return incident


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "defensive-only", "version": app.version}


@app.post("/api/v1/telemetry/events", response_model=Incident, status_code=status.HTTP_201_CREATED)
def ingest_event(event: TelemetryEvent, request: Request) -> Incident:
    actor = request.headers.get("X-Actor", "telemetry-ingest")
    incident = create_incident(event, actor)
    with store.lock:
        store.incidents[incident.incident_id] = incident
    return incident


@app.get("/api/v1/incidents", response_model=list[Incident])
def list_incidents() -> list[Incident]:
    with store.lock:
        return list(store.incidents.values())


@app.get("/api/v1/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> Incident:
    incident = store.incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@app.get("/api/v1/incidents/{incident_id}/integrity")
def integrity(incident_id: str) -> dict[str, Any]:
    incident = get_incident(incident_id)
    return {
        "incident_id": incident_id,
        "audit_entries": len(incident.audit_trail),
        "hash_chain": "verified" if store.verify_chain(incident) else "tampered",
        "evidence_records": len(incident.evidence),
        "evidence_hashes_present": all(len(item.raw_response_sha256) == 64 for item in incident.evidence),
    }


@app.post("/api/v1/incidents/{incident_id}/containment/request")
def request_containment(incident_id: str, request_body: ContainmentRequest) -> dict[str, Any]:
    incident = get_incident(incident_id)
    action = request_body.action.lower().strip()
    if action in OFFENSIVE_ACTIONS or action not in CONTAINMENT_ACTIONS:
        raise HTTPException(status_code=400, detail="action is not allowed by defensive-only policy")
    if incident.pending_approval_id:
        raise HTTPException(status_code=409, detail="an approval is already pending")
    approval_id = f"APR-{secrets.token_hex(5).upper()}"
    incident.pending_approval_id = approval_id
    incident.requested_action = action
    incident.status = "pending_approval"
    store.add_audit(incident, "containment_requested", request_body.requested_by, {"action": action, "approval_id": approval_id})
    return {"approval_id": approval_id, "incident_id": incident_id, "status": "pending_approval", "action": action, "human_approval_required": True}


@app.post("/api/v1/incidents/{incident_id}/containment/approve")
def approve_containment(incident_id: str, decision: ApprovalDecision) -> dict[str, Any]:
    incident = get_incident(incident_id)
    if not incident.pending_approval_id or not incident.requested_action:
        raise HTTPException(status_code=409, detail="no pending containment approval")
    approval_id = incident.pending_approval_id
    if decision.approved:
        incident.status = "contained"
        store.add_audit(incident, "containment_approved_demo", decision.approver, {"action": incident.requested_action, "approval_id": approval_id})
        result = "demo_containment_recorded"
    else:
        incident.status = "open"
        store.add_audit(incident, "containment_denied", decision.approver, {"approval_id": approval_id})
        result = "containment_denied"
    action = incident.requested_action
    incident.pending_approval_id = None
    incident.requested_action = None
    return {"incident_id": incident_id, "approval_id": approval_id, "result": result, "action": action, "external_action_executed": False}


@app.get("/api/v1/policy")
def policy() -> dict[str, Any]:
    return {
        "mode": "defensive-only",
        "human_approval_required_for": sorted(CONTAINMENT_ACTIONS),
        "prohibited_actions": sorted(OFFENSIVE_ACTIONS),
        "passive_osint": True,
        "external_actions_enabled": False,
    }


# NAKARIN SAKULTHAI · MIT License
