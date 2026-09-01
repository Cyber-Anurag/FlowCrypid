#!/usr/bin/env python3
from __future__ import annotations
import os, sys
from pathlib import Path

REQUIRED = ('FLOWCRYPID_ADMIN_EMAIL', 'FLOWCRYPID_ADMIN_PASSWORD')

def main():
    errors = []
    for name in REQUIRED:
        value = os.getenv(name, '')
        if not value or 'replace-with' in value or 'example.invalid' in value:
            errors.append(f'{name} must be set to a real value')
    password = os.getenv('FLOWCRYPID_ADMIN_PASSWORD', '')
    if password and len(password) < 12: errors.append('FLOWCRYPID_ADMIN_PASSWORD must be at least 12 characters')
    if os.getenv('FLOWCRYPID_WORKER_MODE', 'local') not in {'local', 'external'}: errors.append('FLOWCRYPID_WORKER_MODE must be local or external')
    model_dir = Path(os.getenv('FLOWCRYPID_MODEL_DIR', 'models'))
    for filename in ('isolation_forest.joblib', 'scaler.joblib'):
        if not (model_dir / filename).is_file(): errors.append(f'missing model artifact: {model_dir / filename}')
    if errors:
        print('Environment validation failed:'); print('\n'.join(f' - {e}' for e in errors)); return 1
    print('Environment validation passed')
    return 0
if __name__ == '__main__': sys.exit(main())
