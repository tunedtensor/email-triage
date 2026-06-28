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

ROUTINE_ARCHIVE_PATTERNS = [
    r"\bweekly (product )?digest\b",
    r"\bmonthly (product )?digest\b",
    r"\bnewsletter\b",
    r"\bcommunity links\b",
    r"\bproduct updates\b",
]

BILLING_ESCALATION_PATTERNS = [
    r"\bcharged twice\b",
    r"\bbilling error\b",
    r"\binvoice [a-z0-9_-]+.*\breview\b",
]

OPERATIONAL_SAFE_PATTERNS = [
    r"\binternal scan report\b",
    r"\b(automated|internal|scheduled) (status|summary|digest|report|scan)\b",
    r"\b(system|service|delivery) status (notification|report|summary)\b",
    r"\b(dry run|dry scan|scan) (finished|completed)\b",
    r"\bdry scan finished\b",
    r"\baudit log written\b",
    r"\bdelivery status notification\b",
    r"\bpackage [a-z0-9_-]+ was delivered\b",
    r"\bno action required\b",
]


def guardrail_decision(email: "EmailInput", decision: dict[str, Any] | None = None) -> dict[str, Any] | None:
    decision = {key: value for key, value in (decision or {}).items() if key != "risk"}
    text = " ".join(part for part in [email.sender, email.subject, email.body] if part).lower()
    if _matches_any(text, PROMPT_ATTACK_PATTERNS):
        return {
            **decision,
            "triage": "ignore",
            "priority": "critical",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.9),
            "summary": "Email contains instructions that try to override or misuse the triage assistant.",
            "reason": "Email contains an instruction override or tool-abuse request targeting the assistant.",
        }
    if _matches_any(text, CREDENTIAL_REQUEST_PATTERNS):
        return {
            **decision,
            "triage": "ignore",
            "priority": "critical",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.88),
            "summary": "Email asks for account credentials, verification, or login-page interaction.",
            "reason": "Email asks for credentials or account verification.",
        }
    if _matches_any(text, MALWARE_PATTERNS):
        return {
            **decision,
            "triage": "ignore",
            "priority": "critical",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.88),
            "summary": "Email asks the user to run risky attachment content or enable macros.",
            "reason": "Email asks the user to run risky attachment content or enable macros.",
        }
    if _matches_any(text, SPAM_PATTERNS):
        return {
            **decision,
            "triage": "ignore",
            "priority": "low",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.86),
            "summary": "Email contains unsolicited promotional language and spam indicators.",
            "reason": "Unsolicited promotional content with spam indicators.",
        }
    if _matches_any(text, ROUTINE_ARCHIVE_PATTERNS):
        return {
            **decision,
            "triage": "archive",
            "priority": "low",
            "should_process": False,
            "confidence": max(float(decision.get("confidence", 0)), 0.84),
            "summary": decision.get("summary") or "Routine digest or newsletter with no direct action required.",
            "reason": "Routine digest or newsletter can be archived.",
        }
    if _matches_any(text, BILLING_ESCALATION_PATTERNS):
        return {
            **decision,
            "triage": "escalate",
            "priority": "high",
            "should_process": True,
            "confidence": max(float(decision.get("confidence", 0)), 0.78),
            "summary": "Email describes a billing or invoice issue that needs routing for resolution.",
            "reason": "Legitimate billing or invoice issue requiring review.",
        }
    if _can_mark_operational_safe(decision) and _matches_any(text, OPERATIONAL_SAFE_PATTERNS):
        return _operational_safe_decision(decision)
    return None


def apply_guardrails(email: "EmailInput", decision: dict[str, Any]) -> dict[str, Any]:
    return guardrail_decision(email, decision) or decision


def _operational_safe_decision(decision: dict[str, Any]) -> dict[str, Any]:
    return {
        **decision,
        "triage": "archive",
        "priority": "low",
        "should_process": False,
        "confidence": max(float(decision.get("confidence", 0)), 0.74),
        "summary": "Routine operational status message with no action required.",
        "reason": "Routine operational notice can be archived.",
    }


def _can_mark_operational_safe(decision: dict[str, Any]) -> bool:
    triage = decision.get("triage")
    return triage in {None, "archive", "ignore", "review"}


def _matches_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)
