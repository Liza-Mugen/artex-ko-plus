#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
docker compose -f docker-compose.diagnostics.yml stop
printf 'Diagnostic runner stopped; ARTEX, history and lab services are preserved.\n'
