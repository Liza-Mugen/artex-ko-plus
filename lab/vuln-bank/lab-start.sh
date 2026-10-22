#!/bin/sh
set -eu

# The Compose health gate normally waits for PostgreSQL. Bound this second
# check so a later DB failure cannot leave the web container hanging forever.
attempt=0
until pg_isready -h "${DB_HOST:-db}" -p "${DB_PORT:-5432}" \
  -U "${DB_USER:-postgres}" -d "${DB_NAME:-vulnerable_bank}" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo 'Vuln-Bank DB did not become ready within 120 seconds' >&2
    exit 1
  fi
  sleep 2
done

exec python -u /app/lab-log-runner.py
