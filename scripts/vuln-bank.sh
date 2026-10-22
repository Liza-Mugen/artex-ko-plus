#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

REVISION=4bb7cd5f46921959f034455e5615782481966177
SOURCE=.local-runtime/vuln-bank
ENV_FILE=.local-runtime/vuln-bank.env
COMPOSE=docker-compose.vuln-bank.yml

prepare() {
  umask 077
  mkdir -p .local-runtime
  if [ ! -d "$SOURCE/.git" ]; then
    if [ -e "$SOURCE" ]; then
      echo "VulnBank source path exists but is not a Git checkout: $SOURCE" >&2
      exit 1
    fi
    git clone https://github.com/Commando-X/vuln-bank.git "$SOURCE"
    git -C "$SOURCE" checkout --detach "$REVISION"
  fi
  actual=$(git -C "$SOURCE" rev-parse HEAD)
  if [ "$actual" != "$REVISION" ] || [ -n "$(git -C "$SOURCE" status --porcelain)" ]; then
    echo "VulnBank source must be a clean checkout of $REVISION" >&2
    exit 1
  fi
  if [ ! -s "$ENV_FILE" ]; then
    secret=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
    printf 'VULN_BANK_DB_PASSWORD=%s\n' "$secret" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  fi
  docker network inspect aegis-vuln-bank-lab >/dev/null 2>&1 || docker network create --internal aegis-vuln-bank-lab >/dev/null
}

case "${1:-}" in
  start)
    prepare
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d --build --wait --wait-timeout 240
    printf 'VulnBank: http://localhost:15000/\nARTEX target: http://vuln-bank:5000/\n'
    ;;
  status)
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE" ps
    ;;
  stop)
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE" down
    ;;
  *)
    echo "Usage: $0 start|status|stop" >&2
    exit 2
    ;;
esac
