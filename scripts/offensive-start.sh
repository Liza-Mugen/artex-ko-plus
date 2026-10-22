#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
./scripts/local-start.sh
printf '\nOriginal ARTEX task workflow: http://localhost:8787/function/tasks/\n'
