# Changelog

All notable changes to Email Triage are recorded here.

## Unreleased

- No unreleased changes yet.

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
