#!/usr/bin/env python3
"""Train FlowCrypid's unsupervised Isolation Forest from authorized flow features.

The training CSV must contain FEATURE_KEYS plus optional label/split columns. Only
benign rows (label=0) from split=train are used because Isolation Forest learns
normal traffic rather than a malicious class boundary.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

from apps.api.feature_extraction import FlowFeatureVector
from apps.api.ml_anomaly import DEFAULT_MODEL_PATH, DEFAULT_SCALER_PATH, FEATURE_KEYS, MLAnomalyDetector


def load_vectors(path: Path) -> list[FlowFeatureVector]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    missing = [key for key in FEATURE_KEYS if key not in (rows[0] if rows else {})]
    if missing:
        raise ValueError(f"training CSV is missing feature columns: {', '.join(missing)}")
    vectors = []
    for row in rows:
        if row.get("split", "train") != "train" or row.get("label", "0") not in {"0", "benign", "normal"}:
            continue
        values = {key: float(row[key]) for key in FEATURE_KEYS}
        values.update({
            "fwd_rev_packet_ratio": float(row.get("fwd_rev_packet_ratio", values["fwd_rev_byte_ratio"])),
            "iat_min": float(row.get("iat_min", values["iat_mean"])),
            "iat_max": float(row.get("iat_max", values["iat_mean"])),
            "packet_size_min": int(float(row.get("packet_size_min", values["packet_size_mean"]))),
            "packet_size_max": int(float(row.get("packet_size_max", values["packet_size_mean"]))),
            "size_bin_medium_ratio": float(row.get("size_bin_medium_ratio", 1.0 - values["size_bin_small_ratio"])),
            "size_bin_large_ratio": float(row.get("size_bin_large_ratio", 0.0)),
            "is_privileged_port": int(float(row.get("is_privileged_port", values["destination_port"] < 1024))),
            "protocol_code": int(float(row.get("protocol_code", 6 if values["destination_port"] in {22, 80, 443, 8443} else 17))),
            "dns_response_count": int(float(row.get("dns_response_count", values["dns_query_count"] // 2))),
            "dns_nxdomain_count": int(float(row.get("dns_nxdomain_count", 0))),
            "burstiness_index": float(row.get("burstiness_index", values["packets_per_sec"])),
        })
        values["flow_id"] = row.get("flow_id", f"train-{len(vectors):05d}")
        values["total_bytes"] = int(values["total_bytes"])
        values["total_packets"] = int(values["total_packets"])
        values["destination_port"] = int(values["destination_port"])
        vectors.append(FlowFeatureVector(**values))
    return vectors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("evaluation/data/iforest_training.csv"))
    parser.add_argument("--model-output", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--scaler-output", type=Path, default=DEFAULT_SCALER_PATH)
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()
    vectors = load_vectors(args.input)
    if len(vectors) < 10:
        raise ValueError(f"need at least 10 benign training flows; found {len(vectors)}")
    detector = MLAnomalyDetector(contamination=args.contamination)
    detector.fit(vectors)
    detector.save(args.model_output, args.scaler_output)
    print(f"trained {len(vectors)} benign flows")
    print(f"model: {args.model_output}")
    print(f"scaler: {args.scaler_output}")


if __name__ == "__main__":
    main()
