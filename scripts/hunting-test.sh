#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Each invocation owns a disposable, unpublished database and internal network.
hunt_test_project="artex-hunting-test-$$"
cleanup() { docker compose -p "$hunt_test_project" -f docker-compose.hunting-test.yml down --remove-orphans; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker compose -p "$hunt_test_project" -f docker-compose.hunting-test.yml up --build --abort-on-container-exit --exit-code-from tests
