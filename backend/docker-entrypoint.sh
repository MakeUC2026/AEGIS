#!/bin/sh
# api: apply migrations (idempotent, `upgrade heads` per M1 §0.4), then serve.
# worker: the background worker (placeholder until M3).
# migrate: migrations only (Railway pre-deploy command, if preferred).
set -eu

case "${1:-api}" in
  api)
    alembic upgrade heads
    exec uvicorn --factory app.main:create_app --host 0.0.0.0 --port "${PORT:-8000}" --no-server-header
    ;;
  worker)
    exec python -m app.workers
    ;;
  migrate)
    exec alembic upgrade heads
    ;;
  *)
    echo "usage: $0 {api|worker|migrate}" >&2
    exit 64
    ;;
esac
