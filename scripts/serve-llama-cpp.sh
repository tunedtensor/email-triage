#!/usr/bin/env bash
set -euo pipefail

: "${MODEL:?Set MODEL to a GGUF model path}"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8011}"
CTX_SIZE="${CTX_SIZE:-4096}"
PARALLEL="${PARALLEL:-1}"
TEMP="${TEMP:-0}"

email-triage serve "$MODEL" \
  --host "$HOST" \
  --port "$PORT" \
  --ctx-size "$CTX_SIZE" \
  --parallel "$PARALLEL" \
  --temperature "$TEMP"

