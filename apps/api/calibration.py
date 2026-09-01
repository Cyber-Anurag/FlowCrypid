from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Iterable


def sigmoid(value: float) -> float:
    value = max(-60.0, min(60.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def fit_platt(scores: Iterable[float], labels: Iterable[int], iterations: int = 500, learning_rate: float = 0.01) -> dict[str, float | str]:
    values = [float(score) / 100.0 for score in scores]
    targets = [1.0 if int(label) else 0.0 for label in labels]
    if len(values) != len(targets) or len(values) < 4 or len(set(targets)) < 2:
        raise ValueError("calibration requires at least four examples containing both classes")
    slope, intercept = 1.0, -5.0
    for _ in range(iterations):
        probabilities = [sigmoid(slope * score + intercept) for score in values]
        gradient_slope = sum((probability - target) * score for probability, target, score in zip(probabilities, targets, values)) / len(values)
        gradient_intercept = sum(probability - target for probability, target in zip(probabilities, targets)) / len(values)
        slope -= learning_rate * gradient_slope
        intercept -= learning_rate * gradient_intercept
    return {"method": "platt", "slope": slope, "intercept": intercept, "training_examples": len(values)}


def calibrated_probability(raw_score: float, parameters: dict[str, float | str] | None) -> float:
    if not parameters or parameters.get("method") != "platt":
        return max(0.0, min(1.0, float(raw_score) / 100.0))
    return sigmoid(float(parameters.get("slope", 1.0)) * float(raw_score) / 100.0 + float(parameters.get("intercept", -5.0)))


def load_calibration(path: str | None) -> dict[str, float | str] | None:
    if not path:
        return None
    calibration_path = Path(path)
    if not calibration_path.exists():
        return None
    return json.loads(calibration_path.read_text(encoding="utf-8"))
