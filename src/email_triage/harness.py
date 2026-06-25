from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .backends import TriageBackend
from .guardrails import apply_guardrails
from .prompt import build_prompt
from .schema import parse_decision


@dataclass(frozen=True)
class EmailInput:
    body: str
    subject: str | None = None
    sender: str | None = None
    content_type: str = "email"


class EmailTriageHarness:
    def __init__(
        self,
        backend: TriageBackend,
        *,
        max_new_tokens: int = 192,
        temperature: float = 0.0,
    ) -> None:
        self.backend = backend
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature

    def triage(self, email: EmailInput) -> dict[str, Any]:
        raw = self.generate_raw(email)
        return apply_guardrails(email, parse_decision(raw))

    def triage_with_raw(self, email: EmailInput) -> tuple[dict[str, Any], str]:
        raw = self.generate_raw(email)
        return apply_guardrails(email, parse_decision(raw)), raw

    def generate_raw(self, email: EmailInput) -> str:
        prompt = build_prompt(
            body=email.body,
            subject=email.subject,
            sender=email.sender,
            content_type=email.content_type,
        )
        raw = self.backend.generate(
            prompt,
            max_new_tokens=self.max_new_tokens,
            temperature=self.temperature,
        )
        return raw
