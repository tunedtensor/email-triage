from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .backends import TriageBackend
from .guardrails import apply_guardrails
from .guardrails import guardrail_decision
from .prompt_injection import PromptInjectionGate
from .prompt_injection import prompt_injection_decision
from .prompt import build_prompt
from .schema import TriageValidationError
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
        prompt_injection_gate: PromptInjectionGate | None = None,
    ) -> None:
        self.backend = backend
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self.prompt_injection_gate = prompt_injection_gate

    def triage(self, email: EmailInput) -> dict[str, Any]:
        gated = self._prompt_injection_decision(email)
        if gated is not None:
            return gated
        raw = self.generate_raw(email)
        return self._parse_or_guardrail(email, raw)

    def triage_with_raw(self, email: EmailInput) -> tuple[dict[str, Any], str]:
        gated = self._prompt_injection_decision(email)
        if gated is not None:
            return gated, ""
        raw = self.generate_raw(email)
        return self._parse_or_guardrail(email, raw), raw

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

    def _parse_or_guardrail(self, email: EmailInput, raw: str) -> dict[str, Any]:
        try:
            decision = parse_decision(raw)
        except TriageValidationError:
            override = guardrail_decision(email)
            if override is not None:
                return override
            raise
        return apply_guardrails(email, decision)

    def _prompt_injection_decision(self, email: EmailInput) -> dict[str, Any] | None:
        if self.prompt_injection_gate is None:
            return None
        result = self.prompt_injection_gate.check(email)
        if result.is_risky:
            return prompt_injection_decision(result)
        return None
