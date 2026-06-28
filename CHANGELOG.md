# Changelog

All notable changes to Email Triage are recorded here.

## Unreleased

- No unreleased changes yet.

## 0.3.2 - 2026-06-28

- Removed post-model guardrail rewrites. Valid model JSON is now preserved after schema validation.
- Removed backend selection from the CLI and Python backend factory; the package now uses the OpenAI-compatible HTTP backend directly.
- Kept the pre-model heuristic prompt-injection gate for obvious instruction override and tool-abuse patterns.
- Updated docs to show the simplified validation-only post-model path.

## 0.3.1 - 2026-06-28

- Removed the classical prompt-injection classifier from the runtime path.
- Made the deterministic heuristic prompt-injection gate the default and only enabled gate mode.
- Removed classifier model and threshold CLI/API options, along with `joblib`, `scikit-learn`, and `scipy` dependencies.
- `email-triage serve` now passes `--cache-ram 0` to `llama-server` to disable prompt caching.

## 0.3.0 - 2026-06-28

- Updated the default GGUF preset to Email Triage v1, based on Tuned Tensor model `86fd9d01-87b8-4c34-ad70-c4264cd35eee`.
- Switched the public decision schema to `triage`, `priority`, `should_process`, `confidence`, `summary`, and `reason`.
- Removed `risk` from CLI/API outputs; security and prompt-injection handling remains a pre-triage gate and guardrail layer.
- Updated prompts, validation, docs, and tests for the v1 triage model.

## 0.2.0 - 2026-06-26

- Added a first-stage prompt-injection gate using `weijianzhg/prompt-injection-classifier`.
- Short-circuit prompt-injection risk before calling the LLM triage backend.
- Added `--prompt-injection-gate`, `--prompt-injection-model`, and `--prompt-injection-threshold` CLI options.
- Kept deterministic prompt-injection guardrails as a fallback safety layer.

## 0.1.0 - 2026-06-25

- Added the Email Triage CLI and Python API.
- Added strict JSON schema validation, response repair, and deterministic guardrails.
- Added `llama.cpp` serving support for the hosted GGUF model.
- Added automatic GGUF download from `tunedtensor/email-triage-gguf`.
- Added E2E benchmark tooling and CI across Python 3.10, 3.11, and 3.12.
- Added `skill.md` for agent-oriented setup, serving, testing, and usage.
