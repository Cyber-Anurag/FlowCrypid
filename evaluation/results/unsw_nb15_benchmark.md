# Measured UNSW-NB15 benchmark

## Result

This result was measured by `scripts/benchmark_unsw_nb15.py`; no metrics were fabricated.

| Metric | Measured value |
|---|---:|
| Evaluation benign flows | 3,500 |
| Evaluation malicious flows | 3,500 |
| Accuracy | 51.8429% |
| Precision | 63.4096% |
| Recall | 8.7143% |
| F1 | 15.3228% |
| False-positive rate | 5.0286% |
| False-negative rate | 91.2857% |

| Confusion-matrix count | Count |
|---|---:|
| True negatives | 3,324 |
| False positives | 176 |
| False negatives | 3,195 |
| True positives | 305 |

## Dataset and split provenance

The dataset is **UNSW-NB15**, whose official source page is maintained by UNSW Sydney: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset). The downloaded CSV is the published `UNSW_NB15_training-set.csv` record, distributed through the public Figshare record [10.6084/m9.figshare.29149946.v1](https://doi.org/10.6084/m9.figshare.29149946.v1), licensed there as CC BY 4.0. The official UNSW page documents separate configured training and testing partitions, but the accessible files used here were byte-identical, so this report **does not claim an official train/test evaluation**.

Instead, the runner created a disjoint deterministic holdout from the published file using `id % 10 == 0` for evaluation and `id % 10 != 0` for fitting. The model used 33,301 benign training flows. The evaluation subset used the first 3,500 benign and first 3,500 malicious records from that holdout. The raw-file SHA-256 is `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559`.

## Model and feature mapping

A `RobustScaler` and `IsolationForest(n_estimators=200, contamination=0.05, random_state=42)` were fitted using only benign training rows. UNSW-NB15 flow fields were mapped into FlowCrypid's feature schema. The UNSW CSV contains no DNS query names, so `dns_domain_entropy` was set to zero for this benchmark; this is explicitly a limitation, not an inferred value.

The low recall and high false-negative rate are the measured outcome of this unsupervised detector and feature mapping. They should not be presented as evidence of production effectiveness. The machine-readable source of truth is `unsw_nb15_benchmark.json`.
