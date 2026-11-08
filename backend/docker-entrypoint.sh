#!/bin/sh
# api: apply migrations (idempotent, `upgrade heads` per M1 §0.4), then serve.
# worker: the background worker (placeholder until M3).
# migrate: migrations only (Railway pre-deploy command, if preferred).
# seed: demo seed only (python -m app.demo; refuses production and unconfirmed remote DBs).
set -eu

case "${1:-api}" in
  api)
    alembic upgrade heads
    # Laptop fallback (M1 D-03): seed a fresh DB on start. Idempotent; secrets are kept.
    if [ "${AEGIS_SEED_ON_START:-0}" = "1" ]; then
      python -m app.demo
    fi
    exec uvicorn --factory app.main:create_app --host 0.0.0.0 --port "${PORT:-8000}" --no-server-header
    ;;
  worker)
    exec python -m app.workers
    ;;
  migrate)
    exec alembic upgrade heads
    ;;
  seed)
    shift
    exec python -m app.demo "$@"
    ;;
  *)
    echo "usage: $0 {api|worker|migrate|seed}" >&2
    exit 64
    ;;
esac
