from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
import hmac
import ipaddress
import json
import math
import logging
import os
import re
import secrets
import sqlite3
import tempfile
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from scapy.all import DNSQR, IP, IPv6, TCP, UDP, PcapReader  # type: ignore

from .calibration import calibrated_probability, load_calibration
from .telemetry import TelemetryEvent, normalize_event
from .correlation import correlate_events
from .feature_extraction import FeatureExtractor, FlowFeatureVector
from .flow_engine import FlowRecord
from .ml_anomaly import MLAnomalyDetector, ML_DETECTOR, load_startup_detector

MAX_UPLOAD_BYTES = int(os.getenv("FLOWCRYPID_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
MAX_PACKETS = int(os.getenv("FLOWCRYPID_MAX_PACKETS", "500000"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("FLOWCRYPID_MAX_LOGIN_ATTEMPTS", "10"))
MAX_UPLOAD_ATTEMPTS = int(os.getenv("FLOWCRYPID_MAX_UPLOAD_ATTEMPTS", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("FLOWCRYPID_RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_CLIENTS = int(os.getenv("FLOWCRYPID_RATE_LIMIT_MAX_CLIENTS", "10000"))
RATE_LIMIT_BACKEND = os.getenv("FLOWCRYPID_RATE_LIMIT_BACKEND", "sqlite").lower()
PCAP_MAGIC_BYTES = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
APP_VERSION = os.getenv("FLOWCRYPID_VERSION", "1.2.0")
CALIBRATION_PATH = os.getenv("FLOWCRYPID_CALIBRATION_PATH", "models/calibration.json")
CALIBRATION = load_calibration(CALIBRATION_PATH)
ML_MODEL = ML_DETECTOR
DB_PATH = Path(os.getenv("FLOWCRYPID_DB_PATH", "storage/flowcrypid.db"))
SESSION_TTL_SECONDS = int(os.getenv("FLOWCRYPID_SESSION_TTL_SECONDS", str(8 * 60 * 60)))
RETENTION_DAYS = int(os.getenv("FLOWCRYPID_RETENTION_DAYS", "30"))
WORKER_COUNT = int(os.getenv("FLOWCRYPID_WORKER_COUNT", "2"))
WORKER_MODE = os.getenv("FLOWCRYPID_WORKER_MODE", "local").lower()
ENVIRONMENT = os.getenv("FLOWCRYPID_ENVIRONMENT", "development").lower()
PRIVACY_MODE = os.getenv("FLOWCRYPID_PRIVACY_MODE", "off").lower()
APPROVED_DESTINATIONS = {value.strip() for value in os.getenv("FLOWCRYPID_APPROVED_DESTINATIONS", "").split(",") if value.strip()}
COMMON_DESTINATION_PORTS = {22, 25, 53, 80, 110, 123, 143, 443, 587, 993, 995}
SUSPICIOUS_DESTINATIONS = {value.strip() for value in os.getenv("FLOWCRYPID_SUSPICIOUS_DESTINATIONS", "").split(",") if value.strip()}
try:
    SOURCE_BASELINES = {str(key): float(value) for key, value in json.loads(os.getenv("FLOWCRYPID_SOURCE_BASELINES", "{}" )).items()}
except (TypeError, ValueError, json.JSONDecodeError):
    SOURCE_BASELINES = {}
CRITICAL_SOURCES = {value.strip() for value in os.getenv("FLOWCRYPID_CRITICAL_SOURCES", "").split(",") if value.strip()}
REQUEST_COUNTS: dict[str, int] = defaultdict(int)
REQUEST_LATENCIES_MS: list[float] = []
JOB_COUNTS: dict[str, int] = defaultdict(int)
RATE_LIMIT_EVENTS: dict[tuple[str, str], deque[float]] = defaultdict(deque)
logger = logging.getLogger("flowcrypid.api")
logging.basicConfig(level=os.getenv("FLOWCRYPID_LOG_LEVEL", "INFO"), format="%(message)s")


class HealthComponents(BaseModel):
    pcap_parser: str = "ready"
    rule_engine: str = "ready"
    ml_anomaly_model: str = "demo"
    baseline_store: str = "sqlite"
    detector_validation: str = "unvalidated"
    worker_execution: str = "local-single-node"


class HealthResponse(BaseModel):
    status: str
    components: HealthComponents
    version: str


class User(BaseModel):
    id: int
    email: str
    role: str


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: User


class Incident(BaseModel):
    id: str
    source_ip: str
    title: str
    severity: str
    risk_score: int
    first_seen: float | None = None
    last_seen: float | None = None
    status: str = "new"
    assignee: str | None = None
    notes: str = ""


class IncidentUpdate(BaseModel):
    status: str | None = Field(default=None, pattern="^(new|acknowledged|investigating|resolved|false_positive)$")
    assignee: str | None = Field(default=None, max_length=254)
    notes: str | None = Field(default=None, max_length=5000)


class FlowFinding(BaseModel):
    id: str
    title: str
    tier: str
    detector_id: str = "FLOW-ENSEMBLE"
    detector_version: str = "heuristic-v2"
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    source_ip: str
    dest_ip: str
    dest_port: int | None = None
    protocol: int | None = None
    first_seen: float | None = None
    last_seen: float | None = None
    evidence: list[str]
    contributing_signals: list[str]
    explanation: list[str] = []
    calibrated_probability: float = Field(ge=0, le=1)
    calibration_method: str = "raw-score-fallback"


class UploadResponse(BaseModel):
    capture_id: str | None = None
    parsed_flows: int
    total_packets: int
    unsupported_packets: int
    findings: list[FlowFinding]
    incidents: list[Incident]
    capture_started_at: float | None = None
    capture_ended_at: float | None = None
    error: str | None = None


class JobResponse(BaseModel):
    id: str
    status: str
    filename: str
    size_bytes: int
    progress: int = Field(ge=0, le=100)
    error: str | None = None
    result: UploadResponse | None = None
    created_at: float
    updated_at: float
    started_at: float | None = None
    completed_at: float | None = None


@dataclass
class Flow:
    source_ip: str
    dest_ip: str
    source_port: int | None
    dest_port: int | None
    protocol: int
    packets: int = 0
    bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    dns_query: str = ""
    dns_entropy: float = 0.0


def database() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)).hex()
        return hmac.compare_digest(candidate, digest_hex)
    except (TypeError, ValueError):
        return False


def redact_ip(value: str) -> str:
    if PRIVACY_MODE != "redact":
        return value
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            octets = value.split(".")
            return ".".join(octets[:2] + ["x", "x"])
        return value.split(":")[0] + ":…"
    except ValueError:
        return "redacted"


def log_event(event: str, **fields: Any) -> None:
    safe_fields = {key: value for key, value in fields.items() if key not in {"password", "token", "authorization", "payload"}}
    logger.info(json.dumps({"event": event, "timestamp": time.time(), **safe_fields}, default=str))


def safe_error(exc: Exception) -> str:
    """Return a user-safe failure string without exposing local paths or parser internals."""
    detail = str(exc).replace("\\n", " ").strip()
    if not detail:
        return "Capture analysis failed"
    return detail[:500]


def detector_status() -> dict[str, Any]:
    calibration_loaded = bool(CALIBRATION)
    return {
        "detector_id": "FLOW-ENSEMBLE",
        "detector_version": "heuristic-v2",
        "ml_model": "isolation-forest",
        "ml_model_status": ML_MODEL.status,
        "ml_model_path": os.getenv("FLOWCRYPID_MODEL_PATH", "models/isolation_forest.joblib"),
        "ml_scaler_path": os.getenv("FLOWCRYPID_SCALER_PATH", "models/scaler.joblib"),
        "validation_status": "validated-calibration" if calibration_loaded else "unvalidated",
        "calibration_method": CALIBRATION.get("method") if calibration_loaded else "raw-score-fallback",
        "benchmark_present": Path("evaluation/results").exists() and any(Path("evaluation/results").glob("*.json")),
        "warning": None if calibration_loaded else "Risk scores are heuristic prioritization signals; no calibrated probability or benchmark claim is active.",
    }


def record_audit_event(event: str, actor_user_id: int | None = None, request: Request | None = None, **metadata: Any) -> None:
    safe_metadata = {key: value for key, value in metadata.items() if key not in {"password", "token", "authorization", "payload"}}
    created_at = time.time()
    client = client_address(request) if request else None
    metadata_json = json.dumps(safe_metadata, sort_keys=True, default=str)
    with database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        previous = connection.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = previous["event_hash"] if previous and "event_hash" in previous.keys() else None
        canonical = json.dumps({"event": event, "actor_user_id": actor_user_id, "client": client, "metadata": metadata_json, "created_at": created_at, "previous_hash": previous_hash}, sort_keys=True)
        event_hash = hashlib.sha256(canonical.encode()).hexdigest()
        connection.execute("INSERT INTO audit_events(event, actor_user_id, client, metadata, created_at, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?)", (event, actor_user_id, client, metadata_json, created_at, previous_hash, event_hash))


def client_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def check_rate_limit(request: Request, bucket: str, limit: int) -> None:
    now = time.time()
    client = client_address(request)
    if RATE_LIMIT_BACKEND == "sqlite":
        retry_after = None
        with database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM rate_limit_events WHERE created_at < ?", (now - RATE_LIMIT_WINDOW_SECONDS,))
            recent = connection.execute("SELECT created_at FROM rate_limit_events WHERE bucket = ? AND client = ? ORDER BY created_at", (bucket, client)).fetchall()
            if len(recent) >= limit:
                retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - recent[0]["created_at"])))
            else:
                connection.execute("INSERT INTO rate_limit_events(bucket, client, created_at) VALUES (?, ?, ?)", (bucket, client, now))
        if retry_after is not None:
            log_event("rate_limit_blocked", bucket=bucket, client=client)
            record_audit_event("rate_limit_blocked", request=request, bucket=bucket)
            raise HTTPException(status_code=429, detail="Too many requests; retry later", headers={"Retry-After": str(retry_after)})
        return
    key = (bucket, client)
    if len(RATE_LIMIT_EVENTS) > RATE_LIMIT_MAX_CLIENTS:
        stale_keys = [event_key for event_key, events in RATE_LIMIT_EVENTS.items() if not events or now - events[-1] > RATE_LIMIT_WINDOW_SECONDS]
        for stale_key in stale_keys:
            RATE_LIMIT_EVENTS.pop(stale_key, None)
    events = RATE_LIMIT_EVENTS[key]
    while events and now - events[0] >= RATE_LIMIT_WINDOW_SECONDS:
        events.popleft()
    if len(events) >= limit:
        retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - events[0])))
        log_event("rate_limit_blocked", bucket=bucket, client=client_address(request))
        record_audit_event("rate_limit_blocked", request=request, bucket=bucket)
        raise HTTPException(status_code=429, detail="Too many requests; retry later", headers={"Retry-After": str(retry_after)})
    events.append(now)


def valid_capture_magic(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] in PCAP_MAGIC_BYTES


def cleanup_retention() -> None:
    cutoff = time.time() - RETENTION_DAYS * 86400
    with database() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
        connection.execute("DELETE FROM captures WHERE created_at < ?", (cutoff,))
        connection.execute("DELETE FROM analysis_jobs WHERE created_at < ?", (cutoff,))
        connection.execute("DELETE FROM audit_events WHERE created_at < ?", (cutoff,))


def seed_database() -> None:
    with database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS captures (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                filename TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                parsed_flows INTEGER NOT NULL,
                total_packets INTEGER NOT NULL,
                unsupported_packets INTEGER NOT NULL,
                started_at REAL,
                ended_at REAL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT NOT NULL,
                capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
                payload TEXT NOT NULL,
                PRIMARY KEY (capture_id, id)
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                source_ip TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                first_seen REAL,
                last_seen REAL,
                status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'investigating', 'resolved', 'false_positive')),
                assignee TEXT,
                notes TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_user_status ON incidents(user_id, status, updated_at);
            CREATE TABLE IF NOT EXISTS rate_limit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket TEXT NOT NULL,
                client TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rate_limit_events_key ON rate_limit_events(bucket, client, created_at);
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                client TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL,
                previous_hash TEXT,
                event_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                stored_path TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('queued', 'processing', 'completed', 'failed')),
                progress INTEGER NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
                error TEXT,
                result TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                started_at REAL,
                completed_at REAL
            );
            """
        )
        for migration in ("ALTER TABLE audit_events ADD COLUMN previous_hash TEXT", "ALTER TABLE audit_events ADD COLUMN event_hash TEXT"):
            try:
                connection.execute(migration)
            except sqlite3.OperationalError:
                pass
        admin_email_raw = os.getenv("FLOWCRYPID_ADMIN_EMAIL")
        admin_password = os.getenv("FLOWCRYPID_ADMIN_PASSWORD")
        user_count = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if not admin_email_raw and not admin_password:
            if user_count == 0:
                logger.warning("No administrator configured; set FLOWCRYPID_ADMIN_EMAIL and FLOWCRYPID_ADMIN_PASSWORD before enabling authenticated workflows")
            return
        if not admin_email_raw or not admin_password:
            raise RuntimeError("FLOWCRYPID_ADMIN_EMAIL and FLOWCRYPID_ADMIN_PASSWORD must be provided together")
        admin_email = admin_email_raw.strip().lower()
        if len(admin_password) < 12:
            raise RuntimeError("FLOWCRYPID_ADMIN_PASSWORD must be at least 12 characters")
        exists = connection.execute("SELECT 1 FROM users WHERE email = ?", (admin_email,)).fetchone()
        if not exists:
            connection.execute("INSERT INTO users(email, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)", (admin_email, hash_password(admin_password), time.time()))


def safe_timestamp(packet: Any) -> float:
    try:
        value = float(packet.time)
        return value if value >= 0 else 0.0
    except (AttributeError, TypeError, ValueError):
        return 0.0


def packet_network_data(packet: Any) -> tuple[str, str, int] | None:
    if IP in packet:
        layer = packet[IP]
        return str(layer.src), str(layer.dst), int(layer.proto)
    if IPv6 in packet:
        layer = packet[IPv6]
        return str(layer.src), str(layer.dst), int(layer.nh)
    return None


def flow_key(packet: Any, src: str, dst: str, proto: int) -> tuple[str, str, int, int | None, int | None]:
    source_port: int | None = None
    dest_port: int | None = None
    if TCP in packet:
        source_port, dest_port = int(packet[TCP].sport), int(packet[TCP].dport)
    elif UDP in packet:
        source_port, dest_port = int(packet[UDP].sport), int(packet[UDP].dport)
    return src, dst, proto, source_port, dest_port


def private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def classify_flow(flow: Flow, index: int, download_bytes: int = 0) -> FlowFinding | None:
    duration = max(0.0, (flow.last_seen or 0.0) - (flow.first_seen or 0.0))
    signals: list[str] = []
    evidence: list[str] = []
    explanation: list[str] = []
    confidences: list[float] = []
    component_scores: list[int] = []
    title = "Unusual network flow"

    def add_signal(signal: str, confidence: float, component_score: int, evidence_items: list[str], explanation_items: list[str]) -> None:
        signals.append(signal)
        confidences.append(confidence)
        component_scores.append(component_score)
        evidence.extend(evidence_items)
        explanation.extend(explanation_items)

    if flow.bytes >= 100_000 and private_ip(flow.source_ip) and not private_ip(flow.dest_ip) and flow.first_seen is not None:
        observed = time.gmtime(flow.first_seen)
        if observed.tm_hour < 8 or observed.tm_hour >= 18 or observed.tm_wday >= 5:
            add_signal("P0_AFTER_HOURS_TRANSFER", 0.82, 84, [f"{flow.bytes / 1_000_000:.2f} MB outbound during off-hours"], [f"The transfer began at UTC hour {observed.tm_hour:02d}, outside the configured 08:00–18:00 weekday baseline."])
    if flow.bytes >= 1_000_000 and duration <= 900 and private_ip(flow.source_ip) and not private_ip(flow.dest_ip):
        add_signal("P0_LOW_AND_SLOW_EXFIL", 0.90, 90, [f"{flow.bytes / 1_000_000:.1f} MB outbound across {flow.packets} packets", f"Observed over {max(1, int(duration))} seconds"], [f"Outbound bytes exceeded 1 MB within a 15-minute window ({flow.bytes:,} bytes, {duration:.0f} seconds).", "The source address is private and the destination address is external."])
    if private_ip(flow.source_ip) and not private_ip(flow.dest_ip) and flow.bytes >= 500_000 and flow.bytes / max(1, download_bytes) >= 10:
        add_signal("P1_UPLOAD_DOWNLOAD_IMBALANCE", 0.76, 74, [f"Outbound/inbound byte ratio is {flow.bytes / max(1, download_bytes):.1f}:1"], [f"Outbound traffic exceeded inbound traffic by at least 10:1 for this host-direction pair ({flow.bytes:,} outbound vs {download_bytes:,} inbound bytes)."])
    if flow.dest_ip in SUSPICIOUS_DESTINATIONS:
        add_signal("P0_REPUTATION_MATCH", 0.88, 86, [f"Destination matched configured intelligence: {flow.dest_ip}"], ["The destination is present in the configured suspicious-destination set; validate feed provenance before response."])
    if flow.source_ip in CRITICAL_SOURCES and flow.bytes >= 100_000:
        add_signal("P1_CRITICAL_ASSET_ACTIVITY", 0.72, 76, [f"Critical source transferred {flow.bytes:,} bytes"], ["The source is marked critical by asset context, so otherwise ordinary traffic receives higher investigation priority."])
    baseline_bytes = SOURCE_BASELINES.get(flow.source_ip)
    if baseline_bytes and flow.bytes >= baseline_bytes * 3:
        add_signal("P1_BEHAVIORAL_DEVIATION", 0.70, 70, [f"Observed {flow.bytes:,} bytes versus {baseline_bytes:,.0f}-byte source baseline"], ["The flow is at least three times the configured source baseline; this is a prioritization signal, not a probability."])
    if not private_ip(flow.dest_ip) and flow.packets <= 3 and flow.dest_ip not in APPROVED_DESTINATIONS:
        add_signal("P1_RARE_EXTERNAL_DESTINATION", 0.72, 72, ["External destination observed in a low-volume flow"], [f"The external flow contained {flow.packets} packet(s), below the low-volume threshold of 3."])
    if flow.dest_port in {53, 5353} and flow.bytes >= 20_000:
        add_signal("P2_ABNORMAL_DNS_VOLUME", 0.78, 62, ["DNS traffic exceeds the lightweight anomaly threshold"], [f"DNS traffic exceeded the 20 KB threshold ({flow.bytes:,} bytes)."])
    if flow.dest_port in {53, 5353} and flow.packets >= 10 and flow.bytes / max(1, flow.packets) >= 80:
        add_signal("P2_DNS_TUNNELING_LIKE", 0.68, 66, [f"DNS average payload proxy is {flow.bytes / max(1, flow.packets):.0f} bytes per packet"], ["High-volume DNS traffic with large average packets is tunneling-like and requires payload-level DNS decoding for confirmation."])
    if flow.dest_port in {53, 5353} and flow.dns_query and len(flow.dns_query) >= 20 and flow.dns_entropy >= 3.5:
        add_signal("P2_HIGH_ENTROPY_DNS", 0.74, 70, [f"DNS label entropy is {flow.dns_entropy:.2f} bits/character", f"Observed query length is {len(flow.dns_query)} characters"], ["The queried label has high Shannon entropy and is long enough to be consistent with encoded or generated DNS content.", "This is a triage signal only; payload decoding and domain reputation are required for confirmation."])
    if not private_ip(flow.dest_ip) and flow.dest_port not in COMMON_DESTINATION_PORTS and flow.bytes >= 10_000:
        add_signal("P2_UNUSUAL_DESTINATION_PORT", 0.62, 56, [f"External traffic uses destination port {flow.dest_port}"], [f"The destination port {flow.dest_port} is outside the configured common-port set."])
    if flow.protocol not in {1, 6, 17} and flow.bytes >= 10_000:
        add_signal("P2_UNUSUAL_PROTOCOL", 0.58, 52, [f"Observed IP protocol {flow.protocol}"], [f"The flow uses IP protocol {flow.protocol}, outside the common TCP/UDP/ICMP set."])
    if flow.packets >= 6 and duration >= 180 and duration / max(1, flow.packets - 1) >= 20:
        add_signal("P3_BEACONING", 0.70, 48, [f"Repeated connections across {flow.packets} packets"], [f"The flow contained {flow.packets} packets over {duration:.0f} seconds with a repeated cadence."])
    if private_ip(flow.source_ip) and private_ip(flow.dest_ip) and flow.bytes >= 5_000_000:
        add_signal("P4_STAGING", 0.65, 32, ["Large internal-to-internal transfer detected"], [f"An internal-to-internal transfer exceeded the 5 MB staging threshold ({flow.bytes:,} bytes)."])
    if not signals:
        return None

    score = min(100, max(component_scores) + min(20, (len(component_scores) - 1) * 5))
    tier = "P0" if score >= 85 else "P1" if score >= 70 else "P2" if score >= 55 else "P3" if score >= 40 else "P4" if score >= 25 else "P5"
    title = {"P0": "After-hours data transfer", "P1": "Rare external destination", "P2": "Unusual DNS activity", "P3": "Periodic beaconing", "P4": "Internal staging volume", "P5": "Unusual network flow"}[tier]
    confidence = round(1.0 - math.prod(1.0 - value for value in confidences), 2)
    explanation.insert(0, f"Ensemble decision combined {len(signals)} independent signal(s): {', '.join(signals)}.")
    explanation.append(f"Risk score is {score}/100; confidence is {confidence:.0%}. Confidence is evidence strength, not a calibrated probability.")
    probability = calibrated_probability(score, CALIBRATION)
    return FlowFinding(id=f"F-{index:04d}", title=title, tier=tier, detector_id="FLOW-ENSEMBLE", detector_version="heuristic-v2", confidence=confidence, risk_score=score, source_ip=flow.source_ip, dest_ip=flow.dest_ip, dest_port=flow.dest_port, protocol=flow.protocol, first_seen=flow.first_seen, last_seen=flow.last_seen, evidence=evidence, contributing_signals=signals, explanation=explanation, calibrated_probability=probability, calibration_method=str(CALIBRATION.get("method")) if CALIBRATION else "raw-score-fallback")


def _flow_features(flow: Flow, index: int) -> FlowFeatureVector:
    """Adapt the PCAP parser's directional flow into the canonical feature schema."""
    start = float(flow.first_seen or 0.0)
    end = float(flow.last_seen or start)
    duration = max(0.0, end - start)
    record = FlowRecord(
        flow_id=f"pcap-{index:06d}",
        src_ip=flow.source_ip,
        dst_ip=flow.dest_ip,
        src_port=int(flow.source_port or 0),
        dst_port=int(flow.dest_port or 0),
        protocol={6: "TCP", 17: "UDP", 1: "ICMP"}.get(flow.protocol, "OTHER"),
        start_time=start,
        end_time=end,
        duration=duration,
        total_packets=flow.packets,
        forward_packets=flow.packets,
        total_bytes=flow.bytes,
        forward_bytes=flow.bytes,
    ).finalize()
    features = FeatureExtractor().extract(record)
    features.dns_query_count = 1 if flow.dns_query else 0
    features.dns_response_count = 0
    features.dns_domain_entropy = flow.dns_entropy
    return features


def analyze_capture(path: Path) -> UploadResponse:
    flows: dict[tuple[str, str, int, int | None, int | None], Flow] = {}
    unsupported = 0
    total_packets = 0
    capture_started: float | None = None
    capture_ended: float | None = None
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                total_packets += 1
                if total_packets > MAX_PACKETS:
                    raise ValueError(f"capture exceeds the {MAX_PACKETS:,}-packet processing limit")
                timestamp = safe_timestamp(packet)
                capture_started = timestamp if capture_started is None else min(capture_started, timestamp)
                capture_ended = timestamp if capture_ended is None else max(capture_ended, timestamp)
                network = packet_network_data(packet)
                if network is None:
                    unsupported += 1
                    continue
                src, dst, proto = network
                key = flow_key(packet, src, dst, proto)
                current = flows.get(key)
                if current is None:
                    current = Flow(src, dst, protocol=proto, source_port=key[3], dest_port=key[4], first_seen=timestamp, last_seen=timestamp)
                    flows[key] = current
                current.packets += 1
                current.bytes += len(packet)
                if DNSQR in packet:
                    try:
                        query = bytes(packet[DNSQR].qname).decode("ascii", errors="ignore").rstrip(".")
                        label = query.split(".", 1)[0]
                        if len(query) > len(current.dns_query):
                            current.dns_query = query
                            if label:
                                counts = defaultdict(int)
                                for character in label.lower():
                                    counts[character] += 1
                                current.dns_entropy = round(-sum((count / len(label)) * math.log2(count / len(label)) for count in counts.values()), 3)
                    except (AttributeError, TypeError, UnicodeError, ValueError):
                        pass
                current.first_seen = timestamp if current.first_seen is None else min(current.first_seen, timestamp)
                current.last_seen = timestamp if current.last_seen is None else max(current.last_seen, timestamp)
    except Exception as exc:
        raise ValueError(f"unable to parse capture: {exc}") from exc
    flow_values = list(flows.values())
    findings = []
    for index, flow in enumerate(flow_values, 1):
        # Live ML path: PCAP -> Flow -> canonical Features -> persisted Scaler -> Isolation Forest -> score.
        ml_finding = ML_MODEL.analyze(_flow_features(flow, index))
        if ml_finding.is_anomalous:
            ml_score = ml_finding.normalized_score
            ml_tier = "P1" if ml_score >= 0.80 else "P3"
            findings.append(FlowFinding(
                id=f"F-{len(findings) + 1:04d}",
                title="Isolation Forest flow anomaly",
                tier=ml_tier,
                detector_id="ML-ISOLATION-FOREST",
                detector_version=ml_finding.model_id,
                confidence=round(min(0.99, 0.50 + ml_score / 2), 4),
                risk_score=int(round(ml_score * 100)),
                source_ip=flow.source_ip,
                dest_ip=flow.dest_ip,
                dest_port=flow.dest_port,
                protocol=flow.protocol,
                first_seen=flow.first_seen,
                last_seen=flow.last_seen,
                evidence=[f"normalized anomaly score: {ml_score:.4f}", f"raw Isolation Forest decision function: {ml_finding.anomaly_score:.4f}"],
                contributing_signals=["ML_ISOLATION_FOREST_ANOMALY"],
                explanation=[ml_finding.explanation],
                calibrated_probability=calibrated_probability(int(round(ml_score * 100)), CALIBRATION),
                calibration_method=str(CALIBRATION.get("method")) if CALIBRATION else "raw-score-fallback",
            ))
        reverse_key = (flow.dest_ip, flow.source_ip, flow.protocol, flow.dest_port, flow.source_port)
        download_bytes = flows.get(reverse_key).bytes if flows.get(reverse_key) else 0
        if finding := classify_flow(flow, index, download_bytes):
            findings.append(finding)

    by_source: dict[str, list[Flow]] = defaultdict(list)
    for flow in flow_values:
        by_source[flow.source_ip].append(flow)
    for source_ip, source_flows in by_source.items():
        external = [flow for flow in source_flows if private_ip(flow.source_ip) and not private_ip(flow.dest_ip)]
        destinations = {flow.dest_ip for flow in external}
        outbound_bytes = sum(flow.bytes for flow in external)
        staged_bytes = sum(flow.bytes for flow in source_flows if private_ip(flow.dest_ip))
        if len(destinations) >= 3 and outbound_bytes >= 1_000_000:
            findings.append(FlowFinding(id=f"F-{len(findings) + 1:04d}", title="Rotating external destinations", tier="P1", detector_id="FLOW-CORRELATION", detector_version="correlation-v1", confidence=0.78, risk_score=78, source_ip=source_ip, dest_ip="multiple", evidence=[f"{len(destinations)} external destinations", f"{outbound_bytes:,} outbound bytes"], contributing_signals=["P1_DESTINATION_ROTATION"], explanation=[f"The source contacted {len(destinations)} distinct external destinations with at least 1 MB total outbound traffic.", "This is a correlation signal, not proof of malicious activity."], calibrated_probability=calibrated_probability(78, CALIBRATION), calibration_method=str(CALIBRATION.get("method")) if CALIBRATION else "raw-score-fallback"))
        if staged_bytes >= 5_000_000 and outbound_bytes >= 500_000:
            findings.append(FlowFinding(id=f"F-{len(findings) + 1:04d}", title="Staging followed by external transfer", tier="P0", detector_id="FLOW-CORRELATION", detector_version="correlation-v1", confidence=0.74, risk_score=88, source_ip=source_ip, dest_ip="multiple", evidence=[f"{staged_bytes:,} internal staging bytes", f"{outbound_bytes:,} external outbound bytes"], contributing_signals=["P5_STAGING_TO_EXFILTRATION"], explanation=["The same source shows substantial internal staging and subsequent external transfer in the capture window.", "This composite signal requires endpoint/file-access context for confirmation."], calibrated_probability=calibrated_probability(88, CALIBRATION), calibration_method=str(CALIBRATION.get("method")) if CALIBRATION else "raw-score-fallback"))
    findings.sort(key=lambda finding: finding.risk_score, reverse=True)
    incidents = [Incident(id=f"INC-{finding.id[2:]}", source_ip=finding.source_ip, title=finding.title, severity=finding.tier, risk_score=finding.risk_score, first_seen=finding.first_seen, last_seen=finding.last_seen) for finding in findings if finding.tier in {"P0", "P1"}]
    return UploadResponse(parsed_flows=len(flows), total_packets=total_packets, unsupported_packets=unsupported, findings=findings, incidents=incidents, capture_started_at=capture_started, capture_ended_at=capture_ended)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))) -> User:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required")
    with database() as connection:
        row = connection.execute("SELECT u.id, u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?", (token_hash(credentials.credentials), time.time())).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return User(id=row["id"], email=row["email"], role=row["role"])


def require_role(*roles: str) -> Callable[[User], User]:
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dependency


seed_database()
cleanup_retention()

@asynccontextmanager
async def lifespan(_: FastAPI):
    global ML_MODEL
    ML_MODEL = load_startup_detector()
    if ML_MODEL.status != "ready":
        logger.error("Persisted Isolation Forest artifacts are unavailable; ML scores will be disabled")
    else:
        logger.info("Loaded persisted Isolation Forest and RobustScaler artifacts")
    yield
    JOB_EXECUTOR.shutdown(wait=True, cancel_futures=False)


app = FastAPI(title="FlowCrypid API", version=APP_VERSION, lifespan=lifespan)
JOB_EXECUTOR = ThreadPoolExecutor(max_workers=WORKER_COUNT, thread_name_prefix="flowcrypid-worker")

@app.middleware("http")
async def request_observability(request: Request, call_next: Callable[..., Any]):
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000
    route = request.url.path
    REQUEST_COUNTS[f"{request.method} {route} {response.status_code}"] += 1
    REQUEST_LATENCIES_MS.append(elapsed_ms)
    if len(REQUEST_LATENCIES_MS) > 1000:
        del REQUEST_LATENCIES_MS[:-1000]
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    response.headers["Content-Security-Policy-Report-Only"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
    if ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    log_event("http_request", method=request.method, path=route, status_code=response.status_code, duration_ms=round(elapsed_ms, 2))
    return response
allowed_origins = [origin.strip() for origin in os.getenv("FLOWCRYPID_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=False, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type", "Accept"])


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="healthy", components=HealthComponents(ml_anomaly_model="ready" if ML_MODEL.status == "ready" else "missing", detector_validation=detector_status()["validation_status"], worker_execution="local-single-node" if WORKER_MODE == "local" else "unsupported-mode"), version=APP_VERSION)

@app.get("/api/health/live")
def live_health() -> dict[str, str]:
    return {"status": "alive", "version": APP_VERSION}

@app.get("/api/detector/status")
def detector_health() -> dict[str, Any]:
    return detector_status()


@app.get("/api/health/ready")
def ready_health() -> dict[str, Any]:
    with database() as connection:
        connection.execute("SELECT 1").fetchone()
    return {"status": "ready", "database": "sqlite", "privacy_mode": PRIVACY_MODE, "retention_days": RETENTION_DAYS, "worker_count": WORKER_COUNT, "worker_mode": WORKER_MODE, "rate_limit_backend": RATE_LIMIT_BACKEND, "detector_version": "heuristic-v2", "detector": detector_status(), "context": {"approved_destinations": len(APPROVED_DESTINATIONS), "suspicious_destinations": len(SUSPICIOUS_DESTINATIONS), "source_baselines": len(SOURCE_BASELINES), "critical_sources": len(CRITICAL_SOURCES)}}

@app.get("/api/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    lines = ["# HELP flowcrypid_http_requests_total Total HTTP requests by method, path, and status.", "# TYPE flowcrypid_http_requests_total counter"]
    for key, count in sorted(REQUEST_COUNTS.items()):
        method, path, status = key.split(" ", 2)
        labels = f'method="{method}",path="{path}",status="{status}"'
        lines.append(f"flowcrypid_http_requests_total{{{labels}}} {count}")
    average = sum(REQUEST_LATENCIES_MS) / len(REQUEST_LATENCIES_MS) if REQUEST_LATENCIES_MS else 0
    lines.extend(["# HELP flowcrypid_http_latency_ms_avg Average recent HTTP latency in milliseconds.", "# TYPE flowcrypid_http_latency_ms_avg gauge", f"flowcrypid_http_latency_ms_avg {average:.2f}"])
    lines.extend(["# HELP flowcrypid_analysis_jobs_total Analysis jobs by lifecycle state.", "# TYPE flowcrypid_analysis_jobs_total counter"])
    for status, count in sorted(JOB_COUNTS.items()):
        lines.append(f'flowcrypid_analysis_jobs_total{{status="{status}"}} {count}')
    lines.extend(["# HELP flowcrypid_analysis_workers Configured in-process analysis workers.", "# TYPE flowcrypid_analysis_workers gauge", f"flowcrypid_analysis_workers {WORKER_COUNT}"])
    return "\n".join(lines) + "\n"


@app.post("/api/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request) -> LoginResponse:
    check_rate_limit(request, "login", MAX_LOGIN_ATTEMPTS)
    with database() as connection:
        row = connection.execute("SELECT id, email, password_hash, role FROM users WHERE lower(email) = lower(?)", (payload.email.strip(),)).fetchone()
        if not row or not verify_password(payload.password, row["password_hash"]):
            log_event("login_failed", client=client_address(request), email=payload.email.strip().lower())
            record_audit_event("login_failed", request=request, email=payload.email.strip().lower())
            raise HTTPException(status_code=401, detail="Invalid email or password")
        raw_token = secrets.token_urlsafe(32)
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
        connection.execute("INSERT INTO sessions(token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)", (token_hash(raw_token), row["id"], time.time() + SESSION_TTL_SECONDS, time.time()))
    record_audit_event("login_succeeded", actor_user_id=row["id"], request=request, role=row["role"])
    return LoginResponse(access_token=raw_token, expires_in=SESSION_TTL_SECONDS, user=User(id=row["id"], email=row["email"], role=row["role"]))


@app.post("/api/auth/password")
def change_password(payload: PasswordChangeRequest, request: Request, user: User = Depends(current_user)) -> dict[str, str]:
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current password")
    with database() as connection:
        row = connection.execute("SELECT password_hash FROM users WHERE id = ?", (user.id,)).fetchone()
    if not row or not verify_password(payload.current_password, row["password_hash"]):
        record_audit_event("password_change_failed", actor_user_id=user.id, request=request, reason="invalid_current_password")
        raise HTTPException(status_code=401, detail="Current password is invalid")
    with database() as connection:
        connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(payload.new_password), user.id))
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user.id,))
    record_audit_event("password_changed", actor_user_id=user.id, request=request)
    return {"status": "password_changed", "detail": "All sessions were revoked; sign in again with the new password"}


@app.get("/api/auth/me", response_model=User)
def me(user: User = Depends(current_user)) -> User:
    return user


@app.post("/api/auth/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))) -> dict[str, str]:
    if credentials:
        with database() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(credentials.credentials),))
    return {"status": "signed_out"}


def job_from_row(row: sqlite3.Row) -> JobResponse:
    result = UploadResponse.model_validate_json(row["result"]) if row["result"] else None
    return JobResponse(id=row["id"], status=row["status"], filename=row["filename"], size_bytes=row["size_bytes"], progress=row["progress"], error=row["error"], result=result, created_at=row["created_at"], updated_at=row["updated_at"], started_at=row["started_at"], completed_at=row["completed_at"])


def recover_pending_jobs() -> None:
    if WORKER_MODE != "local":
        return
    with database() as connection:
        rows = connection.execute("SELECT id, user_id, stored_path, filename, size_bytes FROM analysis_jobs WHERE status IN ('queued', 'processing') ORDER BY created_at").fetchall()
        for row in rows:
            stored_path = Path(row["stored_path"])
            if stored_path.exists():
                now = time.time()
                connection.execute("UPDATE analysis_jobs SET status = 'queued', progress = 0, error = NULL, updated_at = ?, started_at = NULL, completed_at = NULL WHERE id = ?", (now, row["id"]))
                JOB_COUNTS["recovered"] += 1
                JOB_EXECUTOR.submit(process_analysis_job, row["id"], row["user_id"], stored_path, row["filename"], row["size_bytes"])
            else:
                connection.execute("UPDATE analysis_jobs SET status = 'failed', progress = 100, error = 'Stored capture was unavailable during worker recovery', updated_at = ?, completed_at = ? WHERE id = ?", (time.time(), time.time(), row["id"]))
                JOB_COUNTS["failed"] += 1
                log_event("capture_recovery_failed", job_id=row["id"], user_id=row["user_id"], reason="stored capture missing")


def claim_next_job() -> tuple[str, int, Path, str, int] | None:
    with database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT id, user_id, stored_path, filename, size_bytes FROM analysis_jobs WHERE status = 'queued' ORDER BY created_at LIMIT 1").fetchone()
        if not row:
            connection.commit()
            return None
        now = time.time()
        connection.execute("UPDATE analysis_jobs SET status = 'processing', progress = 5, started_at = ?, updated_at = ? WHERE id = ? AND status = 'queued'", (now, now, row["id"]))
        connection.commit()
    JOB_COUNTS["claimed"] += 1
    return row["id"], row["user_id"], Path(row["stored_path"]), row["filename"], row["size_bytes"]


def process_analysis_job(job_id: str, user_id: int, stored_path: Path, filename: str, size_bytes: int) -> None:
    started_at = time.time()
    JOB_COUNTS["processing"] += 1
    with database() as connection:
        connection.execute("UPDATE analysis_jobs SET status = 'processing', progress = 10, started_at = ?, updated_at = ? WHERE id = ?", (started_at, started_at, job_id))
    try:
        result = analyze_capture(stored_path)
        if PRIVACY_MODE == "redact":
            for finding in result.findings:
                finding.source_ip = redact_ip(finding.source_ip)
                finding.dest_ip = redact_ip(finding.dest_ip)
        capture_id = f"CAP-{secrets.token_hex(6).upper()}"
        with database() as connection:
            connection.execute("INSERT INTO captures(id, user_id, filename, size_bytes, parsed_flows, total_packets, unsupported_packets, started_at, ended_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (capture_id, user_id, filename, size_bytes, result.parsed_flows, result.total_packets, result.unsupported_packets, result.capture_started_at, result.capture_ended_at, time.time()))
            connection.executemany("INSERT INTO findings(id, capture_id, payload) VALUES (?, ?, ?)", [(finding.id, capture_id, finding.model_dump_json()) for finding in result.findings])
            connection.executemany("INSERT INTO incidents(id, capture_id, user_id, source_ip, title, severity, risk_score, first_seen, last_seen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [(incident.id, capture_id, user_id, incident.source_ip, incident.title, incident.severity, incident.risk_score, incident.first_seen, incident.last_seen, time.time(), time.time()) for incident in result.incidents])
            result.capture_id = capture_id
            completed_at = time.time()
            connection.execute("UPDATE analysis_jobs SET status = 'completed', progress = 100, result = ?, updated_at = ?, completed_at = ? WHERE id = ?", (result.model_dump_json(), completed_at, completed_at, job_id))
        JOB_COUNTS["completed"] += 1
        log_event("capture_analyzed", job_id=job_id, capture_id=capture_id, user_id=user_id, parsed_flows=result.parsed_flows, findings=len(result.findings), privacy_mode=PRIVACY_MODE)
        record_audit_event("capture_analyzed", actor_user_id=user_id, job_id=job_id, capture_id=capture_id, findings=len(result.findings))
    except Exception as exc:
        failed_at = time.time()
        with database() as connection:
            connection.execute("UPDATE analysis_jobs SET status = 'failed', progress = 100, error = ?, updated_at = ?, completed_at = ? WHERE id = ?", (safe_error(exc), failed_at, failed_at, job_id))
        JOB_COUNTS["failed"] += 1
        log_event("capture_analysis_failed", job_id=job_id, user_id=user_id, error_type=type(exc).__name__)
        record_audit_event("capture_analysis_failed", actor_user_id=user_id, job_id=job_id, error_type=type(exc).__name__)
    finally:
        stored_path.unlink(missing_ok=True)


@app.post("/api/upload", response_model=JobResponse, status_code=202)
async def upload(request: Request, file: UploadFile = File(...), user: User = Depends(require_role("admin", "analyst"))) -> JobResponse:
    check_rate_limit(request, "upload", MAX_UPLOAD_ATTEMPTS)
    if WORKER_MODE != "local":
        raise HTTPException(status_code=503, detail="The configured worker mode is unavailable in this release; use FLOWCRYPID_WORKER_MODE=local or deploy a compatible external worker.")
    filename = (file.filename or "").lower()
    if not filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=415, detail="Only .pcap and .pcapng files are accepted")
    temporary_path: Path | None = None
    queued = False
    total_bytes = 0
    try:
        upload_dir = DB_PATH.parent / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        job_id = f"JOB-{secrets.token_hex(8).upper()}"
        temporary_path = upload_dir / f"{job_id}{Path(filename).suffix}"
        with temporary_path.open("wb+") as handle:
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail=f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit")
                handle.write(chunk)
            handle.flush()
            if total_bytes == 0:
                raise HTTPException(status_code=400, detail="Uploaded capture is empty")
            handle.seek(0)
            magic = handle.read(4)
            if not valid_capture_magic(magic):
                raise HTTPException(status_code=400, detail="Capture content does not match a supported PCAP or PCAPNG format")
            temporary_path = Path(handle.name)
        now = time.time()
        with database() as connection:
            connection.execute("INSERT INTO analysis_jobs(id, user_id, filename, size_bytes, stored_path, status, progress, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'queued', 0, ?, ?)", (job_id, user.id, Path(filename).name, total_bytes, str(temporary_path), now, now))
        JOB_COUNTS["queued"] += 1
        if WORKER_MODE == "local":
            JOB_EXECUTOR.submit(process_analysis_job, job_id, user.id, temporary_path, Path(filename).name, total_bytes)
        queued = True
        log_event("capture_queued", job_id=job_id, user_id=user.id, filename=Path(filename).name, size_bytes=total_bytes)
        record_audit_event("capture_queued", actor_user_id=user.id, request=request, job_id=job_id, filename=Path(filename).name, size_bytes=total_bytes)
        with database() as connection:
            row = connection.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()
        return job_from_row(row)
    finally:
        await file.close()
        if temporary_path and not queued:
            temporary_path.unlink(missing_ok=True)


@app.get("/api/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: str, user: User = Depends(require_role("admin", "analyst"))) -> JobResponse:
    with database() as connection:
        row = connection.execute("SELECT * FROM analysis_jobs WHERE id = ? AND (user_id = ? OR ? = 'admin')", (job_id, user.id, user.role)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return job_from_row(row)


def verify_audit_chain() -> dict[str, Any]:
    with database() as connection:
        rows = connection.execute("SELECT id, event, actor_user_id, client, metadata, created_at, previous_hash, event_hash FROM audit_events ORDER BY id").fetchall()
    previous_hash = None
    for row in rows:
        canonical = json.dumps({"event": row["event"], "actor_user_id": row["actor_user_id"], "client": row["client"], "metadata": row["metadata"], "created_at": row["created_at"], "previous_hash": row["previous_hash"]}, sort_keys=True)
        expected_hash = hashlib.sha256(canonical.encode()).hexdigest()
        if row["previous_hash"] != previous_hash or (row["event_hash"] and row["event_hash"] != expected_hash):
            return {"valid": False, "checked": row["id"], "error": "audit chain integrity failure"}
        previous_hash = row["event_hash"]
    return {"valid": True, "checked": len(rows), "error": None}


@app.get("/api/audit/verify")
def audit_verify(user: User = Depends(require_role("admin"))) -> dict[str, Any]:
    return verify_audit_chain()


@app.get("/api/audit")
def audit_events(user: User = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    with database() as connection:
        rows = connection.execute("SELECT id, event, actor_user_id, client, metadata, created_at, previous_hash, event_hash FROM audit_events ORDER BY created_at DESC LIMIT 500").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/telemetry/validate")
def validate_telemetry(events: list[TelemetryEvent], request: Request, user: User = Depends(current_user)) -> dict[str, Any]:
    if len(events) > 10_000:
        raise HTTPException(status_code=413, detail="Telemetry batch exceeds the 10,000-event limit")
    normalized = [normalize_event(event) for event in events]
    record_audit_event("telemetry_validated", actor_user_id=user.id, request=request, event_count=len(normalized))
    return {"valid": True, "event_count": len(normalized), "event_types": sorted({str(event["event_type"]) for event in normalized}), "events": normalized}


@app.post("/api/correlation/preview")
def correlation_preview(events: list[TelemetryEvent], request: Request, user: User = Depends(current_user)) -> dict[str, Any]:
    if len(events) > 10_000:
        raise HTTPException(status_code=413, detail="Telemetry batch exceeds the 10,000-event limit")
    normalized = [normalize_event(event) for event in events]
    chains = correlate_events(normalized)
    record_audit_event("correlation_previewed", actor_user_id=user.id, request=request, event_count=len(normalized), chain_count=len(chains))
    return {"event_count": len(normalized), "chains": chains}


@app.get("/api/incidents", response_model=list[Incident])
def list_incidents(status: str | None = None, user: User = Depends(current_user)) -> list[Incident]:
    query = "SELECT id, source_ip, title, severity, risk_score, first_seen, last_seen, status, assignee, notes FROM incidents WHERE (user_id = ? OR ? = 'admin')"
    params: list[Any] = [user.id, user.role]
    if status:
        if status not in {"new", "acknowledged", "investigating", "resolved", "false_positive"}:
            raise HTTPException(status_code=400, detail="Unsupported incident status")
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY risk_score DESC, updated_at DESC LIMIT 500"
    with database() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [Incident(**dict(row)) for row in rows]


@app.patch("/api/incidents/{incident_id}", response_model=Incident)
def update_incident(incident_id: str, payload: IncidentUpdate, request: Request, user: User = Depends(current_user)) -> Incident:
    with database() as connection:
        row = connection.execute("SELECT id, source_ip, title, severity, risk_score, first_seen, last_seen, status, assignee, notes, user_id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row or (row["user_id"] != user.id and user.role != "admin"):
            raise HTTPException(status_code=404, detail="Incident not found")
        status = payload.status if payload.status is not None else row["status"]
        assignee = payload.assignee if payload.assignee is not None else row["assignee"]
        notes = payload.notes if payload.notes is not None else row["notes"]
        connection.execute("UPDATE incidents SET status = ?, assignee = ?, notes = ?, updated_at = ? WHERE id = ?", (status, assignee, notes, time.time(), incident_id))
        updated = connection.execute("SELECT id, source_ip, title, severity, risk_score, first_seen, last_seen, status, assignee, notes FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    record_audit_event("incident_updated", actor_user_id=user.id, request=request, incident_id=incident_id, status=status)
    return Incident(**dict(updated))


@app.get("/api/captures")
def captures(user: User = Depends(require_role("admin", "analyst"))) -> list[dict[str, Any]]:
    with database() as connection:
        rows = connection.execute("SELECT id, filename, size_bytes, parsed_flows, total_packets, unsupported_packets, started_at, ended_at, created_at FROM captures WHERE user_id = ? OR ? = 'admin' ORDER BY created_at DESC", (user.id, user.role)).fetchall()
    return [dict(row) for row in rows]


if WORKER_MODE == "local":
    recover_pending_jobs()
