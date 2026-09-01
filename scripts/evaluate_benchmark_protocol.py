#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import RobustScaler
from apps.api.main import Flow, classify_flow
from scripts.benchmark_unsw_nb15 import to_features, sha256

SIGNALS = ['P0_LOW_AND_SLOW_EXFIL', 'P1_RARE_EXTERNAL_DESTINATION', 'P2_DNS_ANOMALY', 'P3_BEACONING', 'P4_STAGING']

def metrics(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp), 'accuracy': float(accuracy_score(y, pred)), 'precision': float(precision_score(y, pred, zero_division=0)), 'recall': float(recall_score(y, pred, zero_division=0)), 'f1': float(f1_score(y, pred, zero_division=0)), 'fpr': float(fp/(fp+tn)), 'fnr': float(fn/(fn+tp))}

def main():
    root = Path(__file__).resolve().parents[1]
    data = root / 'evaluation/splits/unsw_nb15'
    train, val, test = [pd.read_csv(data / f'{name}.csv') for name in ('train','validation','test')]
    train_benign = train[train.label == 0]
    scaler = RobustScaler().fit(to_features(train_benign))
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1).fit(scaler.transform(to_features(train_benign)))
    val_y = val.label.astype(int).to_numpy(); test_y = test.label.astype(int).to_numpy()
    val_scores = -model.decision_function(scaler.transform(to_features(val)))
    test_scores = -model.decision_function(scaler.transform(to_features(test)))
    thresholds = np.unique(np.quantile(val_scores, np.linspace(0.01, 0.99, 199)))
    chosen = max(thresholds, key=lambda t: f1_score(val_y, (val_scores >= t).astype(int), zero_division=0))
    test_pred = (test_scores >= chosen).astype(int)
    ablations = {}
    for signal in SIGNALS:
        labels, preds = [], []
        for idx, row in test.iterrows():
            flow = Flow(source_ip=str(row.get('srcip', row.get('source_ip', '0.0.0.0'))), dest_ip=str(row.get('dstip', row.get('dest_ip', '0.0.0.0'))), source_port=None, dest_port=None, protocol=0, packets=int(row.spkts + row.dpkts), bytes=int(row.sbytes + row.dbytes), first_seen=0.0, last_seen=float(row.dur))
            finding = classify_flow(flow, int(idx)+1)
            labels.append(int(row.label)); preds.append(int(bool(finding and signal in finding.contributing_signals)))
        ablations[signal] = metrics(labels, preds)
    report = {'dataset':'UNSW-NB15', 'source':'https://research.unsw.edu.au/projects/unsw-nb15-dataset', 'split_manifest': str(data/'manifest.json'), 'train_records':len(train), 'validation_records':len(val), 'test_records':len(test), 'fit_benign_records':len(train_benign), 'feature_mapping':'UNSW-NB15 flow fields mapped to FlowCrypid canonical features; DNS entropy=0 because the CSV has no DNS query names', 'model':{'type':'IsolationForest','n_estimators':200,'contamination':0.05,'random_state':42,'scaler':'RobustScaler'}, 'threshold_selection':{'method':'validation F1 maximization over 199 score quantiles','threshold':float(chosen),'validation_metrics':metrics(val_y,(val_scores>=chosen).astype(int))}, 'test_metrics':metrics(test_y,test_pred), 'per_detector_ablations':ablations, 'input_sha256':sha256(root/'evaluation/raw/UNSW_NB15_training-set.csv')}
    out = root/'evaluation/results/benchmark_protocol.json'; out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(report, indent=2)+'\n'); print(json.dumps(report, indent=2))
if __name__=='__main__': main()
