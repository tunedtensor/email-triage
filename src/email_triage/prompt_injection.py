from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from typing import Protocol

if TYPE_CHECKING:
    from .harness import EmailInput


class PromptInjectionGateError(RuntimeError):
    pass


@dataclass(frozen=True)
class PromptInjectionResult:
    is_risky: bool
    confidence: float
    reason: str
    source: str


class PromptInjectionGate(Protocol):
    def check(self, email: "EmailInput") -> PromptInjectionResult:
        raise NotImplementedError


class PatternPromptInjectionGate:
    """Deterministic prompt-injection gate used before LLM triage."""

    def check(self, email: "EmailInput") -> PromptInjectionResult:
        from .guardrails import PROMPT_ATTACK_PATTERNS

        text = _email_text(email)
        is_risky = any(re.search(pattern, text.lower()) for pattern in PROMPT_ATTACK_PATTERNS)
        return PromptInjectionResult(
            is_risky=is_risky,
            confidence=0.9 if is_risky else 0.0,
            reason=(
                "Heuristic prompt-injection pattern matched."
                if is_risky
                else "No heuristic prompt-injection pattern matched."
            ),
            source="heuristic",
        )


def create_prompt_injection_gate(mode: str = "heuristic") -> PromptInjectionGate | None:
    normalized = mode.strip().lower()
    if normalized in {"off", "none", "false", "disabled"}:
        return None
    if normalized == "heuristic":
        return PatternPromptInjectionGate()
    raise PromptInjectionGateError("prompt-injection gate must be one of: heuristic, off")


def prompt_injection_decision(result: PromptInjectionResult) -> dict[str, object]:
    return {
        "triage": "ignore",
        "priority": "critical",
        "should_process": False,
        "confidence": max(result.confidence, 0.9),
        "summary": "Email was blocked before LLM triage because it matched prompt-injection signals.",
        "reason": "Heuristic prompt-injection gate blocked the email before LLM triage.",
    }


def _email_text(email: "EmailInput") -> str:
    parts = []
    if email.sender:
        parts.append(f"From: {email.sender}")
    if email.subject:
        parts.append(f"Subject: {email.subject}")
    parts.append(email.body)
    return _normalize_text("\n".join(parts))


def _normalize_text(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
