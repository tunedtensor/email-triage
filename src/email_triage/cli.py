from __future__ import annotations

import argparse
import json
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from .backends import BackendError, create_backend
from .guardrails import apply_guardrails
from .harness import EmailInput, EmailTriageHarness
from .models import (
    MODEL_PRESETS,
    ModelDownloadError,
    local_model_path,
    resolve_gguf_model_path,
)
from .prompt import build_prompt
from .schema import TriageValidationError, parse_decision
from .serve import ServeError, run_llama_server


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (BackendError, ModelDownloadError, ServeError, TriageValidationError, OSError, ValueError) as exc:
        print(f"email-triage: error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-triage",
        description="Classify email-like content into strict JSON triage decisions.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    triage = subparsers.add_parser("triage", help="classify one email")
    add_input_args(triage)
    add_backend_args(triage)
    triage.add_argument("--raw", action="store_true", help="print raw model output before validation")
    triage.set_defaults(func=run_triage)

    batch = subparsers.add_parser("batch", help="classify JSONL input")
    batch.add_argument("input", type=Path, help="JSONL file with subject/body rows")
    batch.add_argument("-o", "--output", type=Path, help="write JSONL output to this path")
    add_backend_args(batch)
    batch.set_defaults(func=run_batch)

    prompt = subparsers.add_parser("prompt", help="render the model prompt for an email")
    add_input_args(prompt)
    prompt.set_defaults(func=run_prompt)

    models = subparsers.add_parser("models", help="list model presets")
    models.set_defaults(func=run_models)

    download = subparsers.add_parser("download", help="download the default GGUF model from Hugging Face")
    download.add_argument("--model", default="small", help="GGUF preset name")
    download.add_argument("--cache-dir", type=Path, help="model cache directory")
    download.add_argument("--force", action="store_true", help="download even if the model is already cached")
    download.set_defaults(func=run_download)

    serve = subparsers.add_parser("serve", help="serve a local or cached GGUF model with llama.cpp")
    serve.add_argument("model_path", nargs="?", default="small", help="path to a GGUF model or preset name")
    serve.add_argument("--llama-server", help="path to llama.cpp llama-server binary")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8011)
    serve.add_argument("--ctx-size", type=int, default=4096)
    serve.add_argument("--gpu-layers", type=int)
    serve.add_argument("--cache-dir", type=Path, help="model cache directory")
    serve.add_argument("--force-download", action="store_true", help="download the GGUF again before serving")
    serve.add_argument("--parallel", type=int, default=1)
    serve.add_argument("--threads", type=int)
    serve.add_argument("--temperature", type=float, default=0.0)
    serve.add_argument(
        "--enable-reasoning",
        action="store_true",
        help="allow model thinking/reasoning output; disabled by default for JSON classification",
    )
    serve.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="extra argument passed through to llama-server; repeat for multiple args",
    )
    serve.set_defaults(func=run_serve)
    return parser


def add_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--subject", help="email subject")
    parser.add_argument("--body", help="email body text")
    parser.add_argument("--from", dest="sender", help="email sender")
    parser.add_argument("--content-type", default="email", help="content type label")
    parser.add_argument("--file", type=Path, help="read email content from .eml, JSON, or text file")


def add_backend_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend",
        choices=["auto", "openai", "rules"],
        default="auto",
        help="inference backend",
    )
    parser.add_argument("--model", default="small", help="model preset or model id")
    parser.add_argument("--api-base", help="OpenAI-compatible API base URL, e.g. http://127.0.0.1:8000/v1")
    parser.add_argument("--api-key-env", help="environment variable containing API key")
    parser.add_argument("--max-new-tokens", type=int, default=192)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--no-system-prompt",
        action="store_true",
        help="omit system message for OpenAI-compatible backend",
    )


def run_triage(args: argparse.Namespace) -> None:
    email_input = read_single_input(args)
    backend = create_backend_from_args(args)
    harness = EmailTriageHarness(
        backend,
        max_new_tokens=args.max_new_tokens,
        temperature=args.temperature,
    )
    if args.raw:
        raw = harness.generate_raw(email_input)
        try:
            decision = apply_guardrails(email_input, parse_decision(raw))
        except TriageValidationError as exc:
            print(
                json.dumps(
                    {"raw": raw, "validation_error": str(exc)},
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
            raise
        print(json.dumps({"raw": raw, "decision": decision}, separators=(",", ":"), ensure_ascii=False))
    else:
        decision = harness.triage(email_input)
        print(json.dumps(decision, separators=(",", ":"), ensure_ascii=False))


def run_batch(args: argparse.Namespace) -> None:
    backend = create_backend_from_args(args)
    harness = EmailTriageHarness(
        backend,
        max_new_tokens=args.max_new_tokens,
        temperature=args.temperature,
    )
    output_handle = args.output.open("w", encoding="utf-8") if args.output else sys.stdout
    close_output = args.output is not None
    try:
        with args.input.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    email_input = email_input_from_json(json.loads(line))
                    decision = harness.triage(email_input)
                    row = {"index": index, "decision": decision}
                except Exception as exc:  # noqa: BLE001 - batch mode should continue per row.
                    row = {"index": index, "error": str(exc)}
                print(json.dumps(row, separators=(",", ":"), ensure_ascii=False), file=output_handle)
    finally:
        if close_output:
            output_handle.close()


def run_prompt(args: argparse.Namespace) -> None:
    email_input = read_single_input(args)
    print(
        build_prompt(
            body=email_input.body,
            subject=email_input.subject,
            sender=email_input.sender,
            content_type=email_input.content_type,
        )
    )


def run_models(args: argparse.Namespace) -> None:
    del args
    rows = [
        {
            "preset": preset.name,
            "repo": preset.repo_id,
            "filename": preset.filename,
            "quantization": preset.quantization,
            "api_model": preset.api_model_id,
            "local_path": str(local_model_path(preset)),
            "description": preset.description,
        }
        for preset in MODEL_PRESETS.values()
    ]
    print(json.dumps(rows, indent=2))


def run_download(args: argparse.Namespace) -> None:
    path = resolve_gguf_model_path(
        args.model,
        cache_dir=args.cache_dir,
        force_download=args.force,
    )
    print(str(path))


def run_serve(args: argparse.Namespace) -> None:
    model_path = resolve_gguf_model_path(
        args.model_path,
        cache_dir=args.cache_dir,
        force_download=args.force_download,
    )
    raise SystemExit(
        run_llama_server(
            model_path=model_path,
            llama_server=args.llama_server,
            host=args.host,
            port=args.port,
            ctx_size=args.ctx_size,
            gpu_layers=args.gpu_layers,
            parallel=args.parallel,
            threads=args.threads,
            temperature=args.temperature,
            reasoning=args.enable_reasoning,
            extra_args=args.extra_arg,
        )
    )


def create_backend_from_args(args: argparse.Namespace):
    return create_backend(
        backend=args.backend,
        model=args.model,
        api_base=args.api_base,
        api_key_env=args.api_key_env,
        include_system_prompt=not args.no_system_prompt,
    )


def read_single_input(args: argparse.Namespace) -> EmailInput:
    if args.file:
        file_input = read_file_input(args.file)
        return EmailInput(
            body=args.body or file_input.body,
            subject=args.subject or file_input.subject,
            sender=args.sender or file_input.sender,
            content_type=args.content_type or file_input.content_type,
        )
    if not args.body:
        if sys.stdin.isatty():
            raise ValueError("provide --body, --file, or pipe body text on stdin")
        body = sys.stdin.read()
    else:
        body = args.body
    return EmailInput(
        body=body,
        subject=args.subject,
        sender=args.sender,
        content_type=args.content_type,
    )


def read_file_input(path: Path) -> EmailInput:
    if path.suffix.lower() == ".eml":
        return read_eml(path)
    if path.suffix.lower() == ".json":
        return email_input_from_json(json.loads(path.read_text(encoding="utf-8")))
    return EmailInput(body=path.read_text(encoding="utf-8"))


def read_eml(path: Path) -> EmailInput:
    with path.open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)
    body = message.get_body(preferencelist=("plain", "html"))
    return EmailInput(
        body=body.get_content() if body is not None else "",
        subject=message.get("subject"),
        sender=message.get("from"),
        content_type="email",
    )


def email_input_from_json(value: Any) -> EmailInput:
    if isinstance(value, str):
        return EmailInput(body=value)
    if not isinstance(value, dict):
        raise ValueError("JSON input row must be an object or string")
    body = value.get("body") or value.get("text") or value.get("content")
    if not isinstance(body, str) or not body.strip():
        raise ValueError("JSON input row must include a non-empty body/text/content field")
    subject = value.get("subject")
    sender = value.get("from") or value.get("sender")
    content_type = value.get("content_type") or "email"
    return EmailInput(
        body=body,
        subject=subject if isinstance(subject, str) else None,
        sender=sender if isinstance(sender, str) else None,
        content_type=content_type if isinstance(content_type, str) else "email",
    )
