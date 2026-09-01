"""Persisted Isolation Forest anomaly detection for FlowCrypid."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from apps.api.feature_extraction import FlowFeatureVector


FEATURE_KEYS = [
    "total_bytes", "total_packets", "bytes_per_packet", "fwd_rev_byte_ratio",
    "duration", "packets_per_sec", "bytes_per_sec", "iat_mean", "iat_std",
    "packet_size_mean", "packet_size_std", "size_bin_small_ratio",
    "destination_port", "dns_query_count", "dns_domain_entropy", "periodicity_cv",
]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "isolation_forest.joblib"
DEFAULT_SCALER_PATH = PROJECT_ROOT / "models" / "scaler.joblib"


@dataclass
class MLAnomalyFinding:
    model_id: str
    anomaly_score: float
    normalized_score: float
    is_anomalous: bool
    top_contributing_features: List[Dict[str, Any]]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MLAnomalyDetector:
    """Isolation Forest inference backed by separately serialized model artifacts."""

    def __init__(self, contamination: float = 0.05, model_version: str = "iforest-v1.0"):
        self.model_version = model_version
        self.contamination = contamination
        self.scaler: RobustScaler | None = None
        self.model: IsolationForest | None = None
        self.feature_keys = FEATURE_KEYS.copy()
        self.is_fitted = False
        self._feature_medians: Dict[str, float] = {}

    def _vector_to_array(self, vector: FlowFeatureVector) -> np.ndarray:
        values = vector.to_dict()
        return np.asarray([float(values.get(key, 0.0) or 0.0) for key in self.feature_keys], dtype=float)

    def fit(self, vectors: List[FlowFeatureVector]) -> None:
        if len(vectors) < 2:
            raise ValueError("at least two training flow feature vectors are required")
        data = np.asarray([self._vector_to_array(vector) for vector in vectors], dtype=float)
        self.scaler = RobustScaler().fit(data)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        ).fit(self.scaler.transform(data))
        self._feature_medians = {key: float(np.median(data[:, i])) for i, key in enumerate(self.feature_keys)}
        self.is_fitted = True

    def save(self, model_path: str | Path = DEFAULT_MODEL_PATH, scaler_path: str | Path = DEFAULT_SCALER_PATH) -> None:
        if not self.is_fitted or self.model is None or self.scaler is None:
            raise RuntimeError("cannot serialize an unfitted detector")
        model_path, scaler_path = Path(model_path), Path(scaler_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        scaler_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)

    @classmethod
    def load(cls, model_path: str | Path = DEFAULT_MODEL_PATH, scaler_path: str | Path = DEFAULT_SCALER_PATH) -> "MLAnomalyDetector":
        model_path, scaler_path = Path(model_path), Path(scaler_path)
        detector = cls()
        detector.model = joblib.load(model_path)
        detector.scaler = joblib.load(scaler_path)
        if not isinstance(detector.model, IsolationForest) or not isinstance(detector.scaler, RobustScaler):
            raise TypeError("invalid Isolation Forest or RobustScaler artifact")
        detector.contamination = float(getattr(detector.model, "contamination", detector.contamination))
        detector._feature_medians = {
            key: float(value) for key, value in zip(detector.feature_keys, getattr(detector.scaler, "center_", np.zeros(len(detector.feature_keys))))
        }
        detector.is_fitted = True
        return detector

    @classmethod
    def from_artifacts(cls, model_path: str | Path = DEFAULT_MODEL_PATH, scaler_path: str | Path = DEFAULT_SCALER_PATH) -> "MLAnomalyDetector":
        try:
            return cls.load(model_path, scaler_path)
        except (FileNotFoundError, OSError, TypeError, ValueError, AttributeError) as exc:
            detector = cls()
            detector.load_error = str(exc)
            return detector

    @property
    def status(self) -> str:
        return "ready" if self.is_fitted else "missing"

    def analyze(self, vector: FlowFeatureVector) -> MLAnomalyFinding:
        if not self.is_fitted or self.model is None or self.scaler is None:
            return MLAnomalyFinding(self.model_version, 0.0, 0.0, False, [], "Persisted Isolation Forest artifacts are unavailable.")
        scaled = self.scaler.transform(self._vector_to_array(vector).reshape(1, -1))
        raw_score = float(self.model.decision_function(scaled)[0])
        is_anomalous = int(self.model.predict(scaled)[0]) == -1
        normalized_score = float(np.clip(0.5 - raw_score / 2.0, 0.0, 1.0))
        values = vector.to_dict()
        deviations = []
        for key in self.feature_keys:
            value = float(values.get(key, 0.0) or 0.0)
            median = self._feature_medians.get(key, 0.0)
            deviations.append((key, value, abs(value - median) / (abs(median) + 1e-6)))
        deviations.sort(key=lambda item: item[2], reverse=True)
        top = [{"feature": key, "value": value, "deviation_score": round(deviation, 4)} for key, value, deviation in deviations[:3]]
        explanation = f"Persisted Isolation Forest ({self.model_version}) produced anomaly score {normalized_score:.2f}; highest deviations: {', '.join(item['feature'] for item in top)}."
        return MLAnomalyFinding(self.model_version, round(raw_score, 4), round(normalized_score, 4), is_anomalous, top, explanation)


def load_startup_detector() -> MLAnomalyDetector:
    return MLAnomalyDetector.from_artifacts(
        os.getenv("FLOWCRYPID_MODEL_PATH", str(DEFAULT_MODEL_PATH)),
        os.getenv("FLOWCRYPID_SCALER_PATH", str(DEFAULT_SCALER_PATH)),
    )


ML_DETECTOR = load_startup_detector()

__all__ = ["FEATURE_KEYS", "MLAnomalyDetector", "MLAnomalyFinding", "ML_DETECTOR", "load_startup_detector"]


if __name__ == "__main__":
    raise SystemExit("Use scripts/train_isolation_forest.py to train artifacts.")

