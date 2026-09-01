# Phase 5 evaluation status

## Current status

The evaluation runner is ready, but no authorized canonical labeled dataset is present in `evaluation/data/`, so no detector performance numbers are being claimed or generated.

The recommended source is the official [CIC-IDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html), which provides labeled network flows and PCAP material. The repository intentionally does not redistribute the dataset. An authorized extract must be converted to the canonical schema before evaluation.

## Required input

Place an authorized file at:

```text
evaluation/data/cicids2017_canonical.csv
```

It must contain:

```text
source_ip,dest_ip,dest_port,protocol,packets,bytes,first_seen,last_seen,label,scenario,split
```

The `label` column must contain only `0` or `1`. The `split` column must contain `train`, `validation`, or `test`.

## Recommended run sequence

```bash
python3 scripts/evaluate_detectors.py \
  --input evaluation/data/cicids2017_canonical.csv \
  --split train \
  --dataset-source https://www.unb.ca/cic/datasets/ids-2017.html \
  --dataset-version CIC-IDS2017 \
  --fit-calibration \
  --calibration-output models/calibration.json \
  --output evaluation/results/train_metrics.json

python3 scripts/evaluate_detectors.py \
  --input evaluation/data/cicids2017_canonical.csv \
  --split test \
  --dataset-source https://www.unb.ca/cic/datasets/ids-2017.html \
  --dataset-version CIC-IDS2017 \
  --output evaluation/results/test_metrics.json
```

The resulting report includes the input SHA-256 hash, source and version metadata, detector version, class distribution, scenario distribution, confusion-matrix metrics, detector-level metrics, and score distribution.

## Integrity rule

Do not use demo findings, randomly generated rows, or an unverified third-party mirror as a substitute for this benchmark. Until the authorized extract is supplied and evaluated, FlowCrypid must continue to describe its detector as heuristic and unvalidated.
