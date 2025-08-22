#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${1:-./scam_app.db}"
JSON_DIR="${2:-./data/history}"
CSV_PATH="${3:-./app/data/call_history.csv}"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 not found. Install it (Debian/Raspberry Pi OS):"
  echo "  sudo apt-get update && sudo apt-get install -y sqlite3"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found. Install it:"
  echo "  sudo apt-get update && sudo apt-get install -y python3"
  exit 1
fi

echo "[1/3] Initializing database schema at ${DB_PATH}"
sqlite3 "${DB_PATH}" < scripts/schema.sql

echo "[2/3] Running migration from JSON and CSV"
python3 scripts/migrate_to_sqlite.py --db "${DB_PATH}" --json-dir "${JSON_DIR}" --csv "${CSV_PATH}"

echo "[3/3] Done."
