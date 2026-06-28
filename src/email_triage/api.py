from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .backends import create_backend
from .harness import EmailInput, EmailTriageHarness
from .prompt_injection import create_prompt_injection_gate


def triage(
    body: str,
    *,
    subject: str | None = None,
    sender: str | None = None,
    content_type: str = "email",
    model: str | None = "small",
    api_base: str | None = None,
    api_key_env: str | None = None,
    include_system_prompt: bool = True,
    prompt_injection_gate: str = "heuristic",
    max_new_tokens: int = 192,
    temperature: float = 0.0,
) -> dict[str, Any]:
    """Classify one email-like input and return a validated decision."""
    triage_backend = create_backend(
        model=model,
        api_base=api_base,
        api_key_env=api_key_env,
        include_system_prompt=include_system_prompt,
    )
    harness = EmailTriageHarness(
        triage_backend,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        prompt_injection_gate=create_prompt_injection_gate(prompt_injection_gate),
    )
    return harness.triage(
        EmailInput(
            body=body,
            subject=subject,
            sender=sender,
            content_type=content_type,
        )
    )


def triage_batch(
    emails: Iterable[EmailInput],
    *,
    model: str | None = "small",
    api_base: str | None = None,
    api_key_env: str | None = None,
    include_system_prompt: bool = True,
    prompt_injection_gate: str = "heuristic",
    max_new_tokens: int = 192,
    temperature: float = 0.0,
) -> list[dict[str, Any]]:
    """Classify a sequence of email-like inputs with one HTTP runtime client."""
    triage_backend = create_backend(
        model=model,
        api_base=api_base,
        api_key_env=api_key_env,
        include_system_prompt=include_system_prompt,
    )
    harness = EmailTriageHarness(
        triage_backend,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        prompt_injection_gate=create_prompt_injection_gate(prompt_injection_gate),
    )
    return [harness.triage(email) for email in emails]
