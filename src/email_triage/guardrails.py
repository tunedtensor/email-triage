from __future__ import annotations

import re
from typing import TYPE_CHECKING
from typing import Any

if TYPE_CHECKING:
    from .harness import EmailInput


PROMPT_ATTACK_PATTERNS = [
    r"\bignore (all )?(previous|prior|above) instructions\b",
    r"\boverride (the )?(system|developer|assistant) instructions\b",
    r"\breveal (the )?(system prompt|developer instructions|secrets|credentials)\b",
    r"\bforward (the )?(mailbox|inbox|user'?s mailbox|mailbox rules)\b",
    r"\bexfiltrat(e|ion)\b",
    r"\bcall the [a-z0-9_-]+ tool\b",
    r"\buse the [a-z0-9_-]+ tool\b",
    r"\bapprove (the )?.*\bautomatically\b",
    r"\bdelete (all|the user'?s|mailbox)\b",
]


def apply_guardrails(email: "EmailInput", decision: dict[str, Any]) -> dict[str, Any]:
    text = " ".join(part for part in [email.subject, email.body] if part).lower()
    if _matches_any(text, PROMPT_ATTACK_PATTERNS):
        return {
            **decision,
            "triage": "ignore",
            "priority": "critical",
            "risk": "prompt_attack",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.9),
            "reason": "Email contains an instruction override or tool-abuse request targeting the assistant.",
        }
    return decision


def _matches_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)
