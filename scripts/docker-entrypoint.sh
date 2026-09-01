#!/bin/sh
set -eu
python scripts/validate_environment.py
exec "$@"
