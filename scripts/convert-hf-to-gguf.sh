#!/usr/bin/env bash
set -euo pipefail

: "${LLAMA_CPP_DIR:?Set LLAMA_CPP_DIR to your llama.cpp checkout}"
: "${MODEL_DIR:?Set MODEL_DIR to the Hugging Face model directory}"

OUT_DIR="${OUT_DIR:-models}"
BASENAME="${BASENAME:-email-triage}"
QUANT="${QUANT:-Q5_K_M}"
DISABLE_MTP="${DISABLE_MTP:-auto}"

mkdir -p "$OUT_DIR"

F16_MODEL="$OUT_DIR/${BASENAME}-f16.gguf"
QUANT_MODEL="$OUT_DIR/${BASENAME}-${QUANT}.gguf"
CONVERT_MODEL_DIR="$MODEL_DIR"
TEMP_MODEL_DIR=""

cleanup() {
  if [[ -n "$TEMP_MODEL_DIR" && -d "$TEMP_MODEL_DIR" ]]; then
    rm -rf "$TEMP_MODEL_DIR"
  fi
}
trap cleanup EXIT

if [[ "$DISABLE_MTP" != "0" ]]; then
  TEMP_MODEL_DIR="$(mktemp -d)"
  if python3 - "$MODEL_DIR" "$TEMP_MODEL_DIR" "$DISABLE_MTP" <<'PY'
from __future__ import annotations

import json
import os
import sys

src, dst, mode = sys.argv[1], sys.argv[2], sys.argv[3]
with open(os.path.join(src, "config.json"), encoding="utf-8") as handle:
    config = json.load(handle)

text_config = config.get("text_config")
if not isinstance(text_config, dict):
    raise SystemExit(1)

mtp_layers = int(text_config.get("mtp_num_hidden_layers") or 0)
disable = mode == "1"
if mode == "auto" and mtp_layers:
    try:
        from safetensors import safe_open

        model_path = os.path.join(src, "model.safetensors")
        with safe_open(model_path, framework="pt", device="cpu") as handle:
            keys = list(handle.keys())
        n_layers = int(text_config.get("num_hidden_layers") or 0)
        has_mtp_tensors = any("mtp" in key.lower() for key in keys)
        has_extra_block = any(f"layers.{n_layers}." in key for key in keys)
        disable = not has_mtp_tensors and not has_extra_block
    except Exception:
        disable = False

if not disable:
    raise SystemExit(1)

os.makedirs(dst, exist_ok=True)
for name in os.listdir(src):
    if name == "config.json":
        continue
    os.symlink(os.path.join(src, name), os.path.join(dst, name))

text_config["mtp_num_hidden_layers"] = 0
config["text_config"] = text_config
with open(os.path.join(dst, "config.json"), "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
  then
    CONVERT_MODEL_DIR="$TEMP_MODEL_DIR"
    echo "Using temporary config with mtp_num_hidden_layers=0 for GGUF conversion." >&2
  else
    rm -rf "$TEMP_MODEL_DIR"
    TEMP_MODEL_DIR=""
  fi
fi

python3 "$LLAMA_CPP_DIR/convert_hf_to_gguf.py" \
  "$CONVERT_MODEL_DIR" \
  --outfile "$F16_MODEL" \
  --outtype f16

"$LLAMA_CPP_DIR/build/bin/llama-quantize" \
  "$F16_MODEL" \
  "$QUANT_MODEL" \
  "$QUANT"

echo "$QUANT_MODEL"
