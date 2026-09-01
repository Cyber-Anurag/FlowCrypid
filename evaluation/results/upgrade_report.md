# FlowCrypid upgrade report

## Implemented

The repository now contains deterministic train, validation, and test partitions of the licensed UNSW-NB15 labeled flow file. The split rule is `id % 10`: buckets 0–5 for training, 6–7 for validation, and 8–9 for test. Only benign training rows fit the Isolation Forest. Validation selects the anomaly threshold; test remains held out.

The live React SOC dashboard already consumes authenticated API results through the client API layer. The ingest control uploads a PCAP, polls the analysis job, replaces the demo snapshot with the API result, refreshes capture history and incidents, and renders detector findings, risk scores, evidence, and explanations.

Two labeled DNS PCAP fixtures are included for controlled feature verification: `evaluation/dns_benchmark/benign_dns.pcap` and `evaluation/dns_benchmark/malicious_dns_tunneling.pcap`. These are controlled fixtures with known labels, not claims about traffic captured from a real victim network. The production Shannon entropy helper measured mean left-most-label entropy of 1.2925 bits for benign DNS and 3.3350 bits for the controlled tunneling-like fixture, a measured separation of 2.0425 bits.

The backend Docker image now validates administrator credentials and model artifacts before starting the API or worker. `scripts/validate_environment.py` can be run locally before deployment.

## Measured benchmark

The held-out test result from `evaluation/results/benchmark_protocol.json` is: accuracy **70.7519%**, precision **69.9887%**, recall **82.0909%**, F1 **75.5583%**, FPR **43.1468%**, and FNR **17.9091%**. The confusion matrix is TN 4,206, FP 3,192, FN 1,624, TP 7,444. These values are measured on the documented mapped-flow protocol; they are not production performance claims.

Per-detector ablation results and limitations are in `benchmark_protocol.md`. Most heuristic detectors are uninformative on UNSW-NB15 CSV data because that file lacks the packet-level IP/DNS context those detectors require. DNS-specific measurements therefore use the separate labeled PCAP fixtures.

## Manual verification still required

The validation environment did not contain the Docker CLI, so `docker compose config` and an actual image build could not be executed here. Before submission, run `docker compose config`, `docker compose build`, and `docker compose up` on a machine with Docker installed. Then sign in through the dashboard, upload `demo/sample.pcap`, verify the returned findings, inspect the health/readiness endpoint, and confirm that real deployment secrets are supplied outside the repository.
