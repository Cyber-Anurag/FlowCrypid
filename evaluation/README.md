# FlowCrypid evaluation

This directory defines the evaluation contract for FlowCrypid. It intentionally does not bundle a synthetic benchmark or claim results that have not been measured.

## Recommended dataset

The primary evaluation source is the official **CIC-IDS2017** dataset from the Canadian Institute for Cybersecurity. It provides labeled network flows and corresponding PCAP material. Review the dataset license and terms before redistribution or commercial use:

- Dataset page: https://www.unb.ca/cic/datasets/ids-2017.html

Use a time-aware split. Keep captures from the same day, host, or scenario together so records from one event do not leak across training and test sets.

| Split | Recommended use |
|---|---|
| Train | Fit optional score calibration parameters only. Do not tune final thresholds on this split repeatedly. |
| Validation | Choose thresholds and compare rule/model combinations. |
| Test | Report final metrics exactly once after the detector configuration is frozen. |

## Canonical input format

Convert the source dataset into a CSV with the following columns:

```text
source_ip,dest_ip,dest_port,protocol,packets,bytes,first_seen,last_seen,label,scenario,split
```

`label` must be `0` for benign and `1` for malicious or suspicious traffic. `first_seen` and `last_seen` must be ISO-8601 timestamps or Unix seconds. `scenario` should identify the source capture or attack family. `split` must be one of `train`, `validation`, or `test`.

The repository does not include CIC-IDS2017 records because the dataset is large and its redistribution terms must be respected. Place an authorized, locally prepared file at `evaluation/data/cicids2017_canonical.csv`.

## Run evaluation

```bash
python3 scripts/evaluate_detectors.py \
  --input evaluation/data/cicids2017_canonical.csv \
  --split test \
  --dataset-source https://www.unb.ca/cic/datasets/ids-2017.html \
  --dataset-version CIC-IDS2017 \
  --output evaluation/results/test_metrics.json
```

To fit a Platt calibration file from the training split:

```bash
python3 scripts/evaluate_detectors.py \
  --input evaluation/data/cicids2017_canonical.csv \
  --split train \
  --dataset-source https://www.unb.ca/cic/datasets/ids-2017.html \
  --dataset-version CIC-IDS2017 \
  --fit-calibration \
  --calibration-output models/calibration.json \
  --output evaluation/results/train_metrics.json
```

The runner reports binary accuracy, precision, recall, F1, false-positive rate, false-negative rate, confusion-matrix counts, score distribution, detector-level counts, class distribution, scenario distribution, input SHA-256, dataset provenance, and the active detector version (`heuristic-v2`). Metrics are only meaningful when labels, splits, and dataset provenance are documented. The current repository does not include an authorized dataset extract; see `evaluation/results/phase5-status.md` for the required handoff.
