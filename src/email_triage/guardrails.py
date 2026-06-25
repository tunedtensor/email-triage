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

CREDENTIAL_REQUEST_PATTERNS = [
    r"\b(password|passcode|mfa code|2fa code|verification code)\b",
    r"\bverify your account\b",
    r"\blogin page\b",
    r"\bconfirm your credentials\b",
]

MALWARE_PATTERNS = [
    r"\b(executable|\.exe|installer|invoice viewer)\b",
    r"\benable macros\b",
    r"\bdisable (antivirus|security|defender)\b",
    r"\brun the attached\b",
]

SPAM_PATTERNS = [
    r"\blast chance offer\b",
    r"\blimited time offer\b",
    r"\bclick (this link|now)\b",
    r"\bclaim (your )?(prize|discount|reward)\b",
    r"\bunsubscribe never\b",
]

BILLING_ESCALATION_PATTERNS = [
    r"\bcharged twice\b",
    r"\bbilling error\b",
    r"\binvoice [a-z0-9_-]+.*\breview\b",
]

OPERATIONAL_SAFE_PATTERNS = [
    r"\binternal scan report\b",
    r"\bdry scan finished\b",
    r"\baudit log written\b",
    r"\bdelivery status notification\b",
    r"\bpackage [a-z0-9_-]+ was delivered\b",
    r"\bno action required\b",
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
    if _matches_any(text, CREDENTIAL_REQUEST_PATTERNS):
        return {
            **decision,
            "triage": "ignore",
            "priority": "critical",
            "risk": "credential_request",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.88),
            "reason": "Email asks for credentials or account verification.",
        }
    if _matches_any(text, MALWARE_PATTERNS):
        return {
            **decision,
            "triage": "ignore",
            "priority": "critical",
            "risk": "malware",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.88),
            "reason": "Email asks the user to run risky attachment content or enable macros.",
        }
    if decision.get("risk") in {"none", "spam", "suspicious"} and _matches_any(text, SPAM_PATTERNS):
        return {
            **decision,
            "triage": "archive",
            "priority": "low",
            "risk": "spam",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.86),
            "reason": "Unsolicited promotional content with spam indicators.",
        }
    if _matches_any(text, BILLING_ESCALATION_PATTERNS):
        return {
            **decision,
            "triage": "escalate",
            "priority": "high",
            "risk": "none",
            "should_process": True,
            "confidence": max(float(decision.get("confidence", 0)), 0.78),
            "reason": "Legitimate billing or invoice issue requiring review.",
        }
    if _matches_any(text, OPERATIONAL_SAFE_PATTERNS):
        return {
            **decision,
            "triage": "review",
            "priority": "normal",
            "risk": "none",
            "should_process": True,
            "confidence": max(float(decision.get("confidence", 0)), 0.74),
            "reason": "Operational status message with no concrete malicious signal.",
        }
    return decision


def _matches_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)
