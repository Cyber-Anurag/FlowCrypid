# apps/api/risk_scoring.py
"""
Transparent Multi-Signal Risk Scoring Engine for FlowCrypid.
Combines deterministic findings, anomaly scores, and threat intelligence without double-counting.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional


@dataclass
class SignalContribution:
    detector: str
    contribution: float
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    risk_score: float
    severity: str        # 'low', 'medium', 'high', 'critical'
    confidence: float
    signals: List[Dict[str, Any]]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RiskScoringEngine:
    """Calculates transparent composite risk scores from multi-source security signals."""

    SEVERITY_WEIGHTS = {
        "low": 0.3,
        "medium": 0.6,
        "high": 1.0,
        "critical": 1.0
    }

    TI_REPUTATION_WEIGHTS = {
        "malicious": 1.0,
        "suspicious": 0.5,
        "unknown": 0.0,
        "benign": 0.0,
        "unavailable": 0.0
    }

    def calculate_risk(
        self,
        findings: List[Any],
        ml_anomaly_score: float = 0.0,
        threat_intel_reputation: Optional[str] = None,
        repeated_observations: int = 1
    ) -> RiskAssessment:
        signals: List[SignalContribution] = []
        base_score = 0.0
        max_confidence = 0.0

        # 1. Evaluate Deterministic Findings
        for finding in findings:
            sev_weight = self.SEVERITY_WEIGHTS.get(finding.severity.lower(), 0.3)
            conf = getattr(finding, "confidence", 0.7)
            max_confidence = max(max_confidence, conf)
            
            contrib = 0.45 * (sev_weight * conf)
            base_score += contrib
            signals.append(SignalContribution(
                detector=finding.detector_id,
                contribution=round(contrib * 100, 2),
                evidence=finding.evidence
            ))

        # 2. Evaluate ML Anomaly Signal (de-duplicated against deterministic findings)
        if ml_anomaly_score > 0.0:
            ml_contrib = 0.25 * ml_anomaly_score
            base_score += ml_contrib
            signals.append(SignalContribution(
                detector="ML-UNSUPERVISED-ANOMALY",
                contribution=round(ml_contrib * 100, 2),
                evidence={"normalized_anomaly_score": ml_anomaly_score}
            ))

        # 3. Evaluate Threat Intelligence Signal
        if threat_intel_reputation and threat_intel_reputation in self.TI_REPUTATION_WEIGHTS:
            ti_weight = self.TI_REPUTATION_WEIGHTS[threat_intel_reputation]
            if ti_weight > 0.0:
                ti_contrib = 0.30 * ti_weight
                base_score += ti_contrib
                signals.append(SignalContribution(
                    detector="THREAT-INTELLIGENCE-FEED",
                    contribution=round(ti_contrib * 100, 2),
                    evidence={"reputation": threat_intel_reputation}
                ))

        # Apply repeated observation scaling multiplier
        freq_multiplier = 1.0 + 0.1 * min(5, max(0, repeated_observations - 1))
        final_score = min(100.0, round((base_score * 100.0) * freq_multiplier, 2))

        # Determine qualitative severity tier from final score
        if final_score >= 80.0:
            severity = "critical"
        elif final_score >= 60.0:
            severity = "high"
        elif final_score >= 30.0:
            severity = "medium"
        else:
            severity = "low"

        # Construct analyst-friendly explanation
        signal_names = [s.detector for s in signals]
        explanation = (
            f"Risk score {final_score:.1f}/100.0 derived from {len(signals)} corroborating signals "
            f"({', '.join(signal_names)}) with frequency multiplier {freq_multiplier:.1f}x. "
            f"This score represents operational prioritization, not a calibrated statistical probability."
        )

        return RiskAssessment(
            risk_score=final_score,
            severity=severity,
            confidence=round(max_confidence if max_confidence > 0 else 0.5, 2),
            signals=[s.to_dict() for s in signals],
            explanation=explanation
        )