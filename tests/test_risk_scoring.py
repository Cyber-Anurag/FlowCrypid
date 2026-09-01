# tests/test_risk_scoring.py
import pytest
from dataclasses import dataclass
from apps.api.risk_scoring import RiskScoringEngine


@dataclass
class DummyFinding:
    detector_id: str
    severity: str
    confidence: float
    evidence: dict


def test_high_risk_composite_scoring():
    engine = RiskScoringEngine()
    findings = [
        DummyFinding("DET-VOL-001", "high", 0.9, {"transfer_bytes": 60000000}),
        DummyFinding("DET-BEH-001", "high", 0.8, {"cv": 0.1})
    ]
    
    assessment = engine.calculate_risk(
        findings=findings,
        ml_anomaly_score=0.85,
        threat_intel_reputation="malicious",
        repeated_observations=3
    )

    assert assessment.risk_score > 75.0
    assert assessment.severity in ("high", "critical")
    assert len(assessment.signals) == 4
    assert any(s["detector"] == "THREAT-INTELLIGENCE-FEED" for s in assessment.signals)
    assert "operational prioritization" in assessment.explanation


def test_boundary_condition_zero_signals():
    engine = RiskScoringEngine()
    assessment = engine.calculate_risk(findings=[], ml_anomaly_score=0.0, threat_intel_reputation=None)

    assert assessment.risk_score == 0.0
    assert assessment.severity == "low"
    assert len(assessment.signals) == 0


def test_benign_traffic_low_score():
    engine = RiskScoringEngine()
    findings = [
        DummyFinding("DET-NET-001", "low", 0.6, {"rate": 10})
    ]
    assessment = engine.calculate_risk(findings=findings, ml_anomaly_score=0.1, threat_intel_reputation="benign")

    assert assessment.risk_score < 30.0
    assert assessment.severity == "low"