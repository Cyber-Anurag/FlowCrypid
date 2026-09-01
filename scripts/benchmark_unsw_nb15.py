#!/usr/bin/env python3
"""Measured UNSW-NB15 benchmark for the FlowCrypid Isolation Forest.

No synthetic rows are created. The benchmark uses benign rows from the published
training split for fitting and the first N benign plus first N malicious rows from
the published testing split for one deterministic, balanced evaluation subset.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import RobustScaler

from apps.api.ml_anomaly import FEATURE_KEYS

SERVICE_PORTS = {"http": 80, "https": 443, "dns": 53, "ftp": 21, "ssh": 22, "smtp": 25, "pop3": 110, "imap4": 143}


def numeric(frame: pd.DataFrame, column: str) -> pd.Series:
    return pd.to_numeric(frame[column], errors="coerce").fillna(0.0)


def to_features(frame: pd.DataFrame) -> pd.DataFrame:
    spkts, dpkts = numeric(frame, "spkts"), numeric(frame, "dpkts")
    sbytes, dbytes = numeric(frame, "sbytes"), numeric(frame, "dbytes")
    dur = numeric(frame, "dur")
    total_packets = spkts + dpkts
    total_bytes = sbytes + dbytes
    bytes_per_packet = total_bytes / total_packets.clip(lower=1)
    packet_mean = (numeric(frame, "smean") * spkts + numeric(frame, "dmean") * dpkts) / total_packets.clip(lower=1)
    size_std = (numeric(frame, "smean") - numeric(frame, "dmean")).abs() / 2
    iat_mean = (numeric(frame, "sinpkt") + numeric(frame, "dinpkt")) / 2
    output = pd.DataFrame({
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "bytes_per_packet": bytes_per_packet,
        "fwd_rev_byte_ratio": sbytes / dbytes.clip(lower=1),
        "duration": dur,
        "packets_per_sec": total_packets / dur.clip(lower=1e-6),
        "bytes_per_sec": total_bytes / dur.clip(lower=1e-6),
        "iat_mean": iat_mean,
        "iat_std": numeric(frame, "sjit") + numeric(frame, "djit"),
        "packet_size_mean": packet_mean,
        "packet_size_std": size_std,
        "size_bin_small_ratio": (packet_mean < 128).astype(float),
        "destination_port": frame["service"].astype(str).str.lower().map(SERVICE_PORTS).fillna(0),
        "dns_query_count": (frame["service"].astype(str).str.lower() == "dns").astype(float),
        "dns_domain_entropy": 0.0,
        "periodicity_cv": (numeric(frame, "sjit") + numeric(frame, "djit")) / iat_mean.clip(lower=1e-6),
    })
    return output[FEATURE_KEYS].replace([np.inf, -np.inf], 0).fillna(0)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=Path, default=Path("evaluation/raw/UNSW_NB15_training-set.csv"))
    parser.add_argument("--test", type=Path, default=Path("evaluation/raw/UNSW_NB15_testing-set.csv"))
    parser.add_argument("--per-class", type=int, default=3500)
    parser.add_argument("--output", type=Path, default=Path("evaluation/results/unsw_nb15_benchmark.json"))
    args = parser.parse_args()

    train = pd.read_csv(args.train)
    test = pd.read_csv(args.test)
    if sha256(args.train) == sha256(args.test):
        # The accessible copies are byte-identical; never claim this is an official
        # train/test evaluation. Create a disjoint, deterministic holdout instead.
        ids = pd.to_numeric(train["id"], errors="coerce").fillna(-1).astype(int)
        test = train[ids.mod(10) == 0].copy()
        train = train[ids.mod(10) != 0].copy()
        split_mode = "single published split; disjoint deterministic id-mod-10 holdout"
    else:
        split_mode = "published training split and published testing split"
    train_benign = train[train["label"].astype(int) == 0]
    test_benign = test[test["label"].astype(int) == 0].head(args.per_class)
    test_malicious = test[test["label"].astype(int) == 1].head(args.per_class)
    test_eval = pd.concat([test_benign, test_malicious], ignore_index=True)
    if len(train_benign) < 100 or len(test_benign) < args.per_class or len(test_malicious) < args.per_class:
        raise ValueError("dataset does not contain enough labeled records for requested benchmark")

    scaler = RobustScaler().fit(to_features(train_benign))
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1).fit(scaler.transform(to_features(train_benign)))
    X_test = scaler.transform(to_features(test_eval))
    predicted = (model.predict(X_test) == -1).astype(int)
    actual = test_eval["label"].astype(int).to_numpy()
    tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[0, 1]).ravel()
    result = {
        "dataset": "UNSW-NB15",
        "dataset_source": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "published_training_records": int(len(train)),
        "published_testing_records": int(len(test)),
        "split_mode": split_mode,
        "training_benign_records_used": int(len(train_benign)),
        "evaluation_benign_records": int(len(test_benign)),
        "evaluation_malicious_records": int(len(test_malicious)),
        "selection": "first N records per class from the disjoint evaluation partition; deterministic, balanced subset",
        "feature_mapping": "UNSW-NB15 flow fields mapped to FlowCrypid FEATURE_KEYS; DNS entropy unavailable in UNSW CSV and set to 0 for this benchmark",
        "model": {"type": "IsolationForest", "n_estimators": 200, "contamination": 0.05, "random_state": 42, "scaler": "RobustScaler"},
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "metrics": {
            "accuracy": float(accuracy_score(actual, predicted)),
            "precision": float(precision_score(actual, predicted, zero_division=0)),
            "recall": float(recall_score(actual, predicted, zero_division=0)),
            "f1": float(f1_score(actual, predicted, zero_division=0)),
            "fpr": float(fp / (fp + tn)),
            "fnr": float(fn / (fn + tp)),
        },
        "sha256": {"train": sha256(args.train), "test": sha256(args.test)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
