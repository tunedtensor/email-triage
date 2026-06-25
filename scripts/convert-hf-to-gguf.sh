#!/usr/bin/env bash
set -euo pipefail

: "${LLAMA_CPP_DIR:?Set LLAMA_CPP_DIR to your llama.cpp checkout}"
: "${MODEL_DIR:?Set MODEL_DIR to the Hugging Face model directory}"

OUT_DIR="${OUT_DIR:-models}"
BASENAME="${BASENAME:-email-triage}"
QUANT="${QUANT:-Q5_K_M}"

mkdir -p "$OUT_DIR"

F16_MODEL="$OUT_DIR/${BASENAME}-f16.gguf"
QUANT_MODEL="$OUT_DIR/${BASENAME}-${QUANT}.gguf"

python3 "$LLAMA_CPP_DIR/convert_hf_to_gguf.py" \
  "$MODEL_DIR" \
  --outfile "$F16_MODEL" \
  --outtype f16

"$LLAMA_CPP_DIR/build/bin/llama-quantize" \
  "$F16_MODEL" \
  "$QUANT_MODEL" \
  "$QUANT"

echo "$QUANT_MODEL"

