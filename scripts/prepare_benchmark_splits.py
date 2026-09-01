#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
import pandas as pd


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--input', type=Path, default=Path('evaluation/raw/UNSW_NB15_training-set.csv'))
    p.add_argument('--output-dir', type=Path, default=Path('evaluation/splits/unsw_nb15'))
    args = p.parse_args()
    df = pd.read_csv(args.input)
    ids = pd.to_numeric(df['id'], errors='coerce').fillna(-1).astype(int)
    # Disjoint, deterministic and label-preserving partitions. Validation/test are
    # never used for fitting; this is a holdout of the accessible labeled file.
    buckets = ids.mod(10)
    masks = {'train': buckets <= 5, 'validation': buckets.isin([6, 7]), 'test': buckets.isin([8, 9])}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {'dataset': 'UNSW-NB15', 'source': 'https://research.unsw.edu.au/projects/unsw-nb15-dataset', 'input_sha256': sha256(args.input), 'split_rule': 'id % 10: 0-5 train, 6-7 validation, 8-9 test', 'partitions': {}}
    for name, mask in masks.items():
        part = df[mask].copy()
        path = args.output_dir / f'{name}.csv'
        part.to_csv(path, index=False)
        manifest['partitions'][name] = {'records': len(part), 'benign': int((part.label == 0).sum()), 'malicious': int((part.label == 1).sum()), 'sha256': sha256(path)}
    (args.output_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))

if __name__ == '__main__':
    main()
