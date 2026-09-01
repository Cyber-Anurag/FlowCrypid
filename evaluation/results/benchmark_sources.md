# Benchmark provenance

The benchmark source is the official UNSW-NB15 dataset page maintained by UNSW Sydney:

- https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Official source-file folder linked by UNSW: https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/EnuQZZn3XuNBjgfcUu4DIVMBLCHyoLHqOswirpOQifr1ag?e=gKWkLS

The official page states that UNSW-NB15 includes labeled CSV files and a configured `UNSW_NB15_training-set.csv` with 175,341 records and `UNSW_NB15_testing-set.csv` with 82,332 records, covering normal and attack traffic. The accessible Figshare training CSV and public testing-split copy were byte-identical (SHA-256 `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559`). Therefore the benchmark does not claim to use the official testing split. Instead, `scripts/benchmark_unsw_nb15.py` creates a disjoint deterministic holdout from the published file using `id % 10 == 0` for evaluation and the remaining records for fitting. The measured result is reported as a single-published-split holdout, not as an official UNSW train/test result.
