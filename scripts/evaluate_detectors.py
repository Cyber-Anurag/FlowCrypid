from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apps.api.calibration import fit_platt  # noqa: E402
from apps.api.main import Flow, classify_flow  # noqa: E402

SIGNALS = ["P0_LOW_AND_SLOW_EXFIL", "P1_RARE_EXTERNAL_DESTINATION", "P2_DNS_ANOMALY", "P3_BEACONING", "P4_STAGING"]
REQUIRED_COLUMNS = {"source_ip", "dest_ip", "dest_port", "protocol", "packets", "bytes", "first_seen", "last_seen", "label", "scenario", "split"}
DETECTOR_VERSION = "heuristic-v2"


def timestamp(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def metric_counts(labels: list[int], predictions: list[int]) -> dict[str, float | int]:
    tp = sum(label == 1 and prediction == 1 for label, prediction in zip(labels, predictions))
    tn = sum(label == 0 and prediction == 0 for label, prediction in zip(labels, predictions))
    fp = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions))
    fn = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"examples": len(labels), "tp": tp, "tn": tn, "fp": fp, "fn": fn, "accuracy": (tp + tn) / len(labels) if labels else 0.0, "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0, "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0}


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate FlowCrypid detectors on canonical labeled flows")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--split", default=None, choices=["train", "validation", "test"])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--dataset-source", default="unspecified", help="Canonical URL or provenance identifier for the input dataset")
    parser.add_argument("--dataset-version", default="unspecified")
    parser.add_argument("--fit-calibration", action="store_true")
    parser.add_argument("--calibration-output", type=Path)
    args = parser.parse_args()

    if not args.input.exists():
        raise SystemExit(f"input dataset not found: {args.input}")
    rows = []
    with args.input.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise SystemExit(f"dataset missing required columns: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, 2):
            try:
                label = int(row["label"])
                if label not in (0, 1):
                    raise ValueError("label must be 0 or 1")
                int(row["packets"])
                int(row["bytes"])
                timestamp(row["first_seen"])
                timestamp(row["last_seen"])
            except (KeyError, TypeError, ValueError) as error:
                raise SystemExit(f"invalid row {row_number}: {error}") from error
            if args.split and row.get("split") != args.split:
                continue
            rows.append(row)
    if not rows:
        raise SystemExit("no rows matched the requested split")

    labels: list[int] = []
    predictions: list[int] = []
    scores: list[float] = []
    detector_labels: dict[str, list[int]] = defaultdict(list)
    detector_predictions: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows, 1):
        flow = Flow(source_ip=row["source_ip"], dest_ip=row["dest_ip"], source_port=None, dest_port=int(row["dest_port"]) if row.get("dest_port") else None, protocol=int(row.get("protocol") or 0), packets=int(row["packets"]), bytes=int(row["bytes"]), first_seen=timestamp(row["first_seen"]), last_seen=timestamp(row["last_seen"]))
        finding = classify_flow(flow, index)
        label = int(row["label"])
        labels.append(label)
        predictions.append(1 if finding else 0)
        score = float(finding.risk_score if finding else 0)
        scores.append(score)
        active_signals = set(finding.contributing_signals if finding else [])
        for signal in SIGNALS:
            detector_labels[signal].append(label)
            detector_predictions[signal].append(1 if signal in active_signals else 0)

    digest = hashlib.sha256(args.input.read_bytes()).hexdigest()
    report = {
        "dataset": str(args.input),
        "dataset_source": args.dataset_source,
        "dataset_version": args.dataset_version,
        "dataset_sha256": digest,
        "split": args.split or "all",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "runtime": {"python": platform.python_version(), "detector_version": DETECTOR_VERSION},
        "class_distribution": dict(Counter(labels)),
        "scenarios": dict(Counter(row["scenario"] for row in rows)),
        "overall": metric_counts(labels, predictions),
        "detectors": {signal: metric_counts(detector_labels[signal], detector_predictions[signal]) for signal in SIGNALS},
        "score_distribution": dict(Counter(int(score) for score in scores)),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.fit_calibration:
        if not args.calibration_output:
            raise SystemExit("--calibration-output is required with --fit-calibration")
        calibration = fit_platt(scores, labels)
        args.calibration_output.parent.mkdir(parents=True, exist_ok=True)
        args.calibration_output.write_text(json.dumps(calibration, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["overall"], indent=2))


if __name__ == "__main__":
    main()
