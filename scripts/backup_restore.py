from __future__ import annotations

import argparse
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path) -> None:
    if not path.exists():
        raise SystemExit(f"database not found: {path}")
    with sqlite3.connect(path) as connection:
        result = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise SystemExit(f"database integrity check failed: {result}")


def backup(source: Path, destination: Path) -> None:
    verify(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise SystemExit(f"refusing to overwrite existing backup: {destination}")
    with sqlite3.connect(source) as source_connection, sqlite3.connect(destination) as destination_connection:
        source_connection.backup(destination_connection)
    verify(destination)
    manifest = destination.with_suffix(destination.suffix + ".sha256")
    manifest.write_text(f"{checksum(destination)}  {destination.name}\n", encoding="utf-8")
    print(f"backup created: {destination}")
    print(f"sha256: {checksum(destination)}")


def restore(source: Path, destination: Path) -> None:
    verify(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise SystemExit(f"refusing to overwrite existing database: {destination}")
    with sqlite3.connect(source) as source_connection, sqlite3.connect(destination) as destination_connection:
        source_connection.backup(destination_connection)
    verify(destination)
    print(f"restore created: {destination}")


parser = argparse.ArgumentParser(description="FlowCrypid SQLite backup and restore utility")
subparsers = parser.add_subparsers(dest="command", required=True)
backup_parser = subparsers.add_parser("backup")
backup_parser.add_argument("--source", type=Path, default=Path("storage/flowcrypid.db"))
backup_parser.add_argument("--destination", type=Path, default=Path(f"backups/flowcrypid-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.db"))
restore_parser = subparsers.add_parser("restore")
restore_parser.add_argument("--source", type=Path, required=True)
restore_parser.add_argument("--destination", type=Path, default=Path("storage/flowcrypid-restored.db"))
args = parser.parse_args()
if args.command == "backup":
    backup(args.source, args.destination)
else:
    restore(args.source, args.destination)
