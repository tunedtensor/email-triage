from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

TRIAGE_VALUES = {"reply", "archive", "escalate", "ignore", "review"}
PRIORITY_VALUES = {"low", "normal", "high", "critical"}
RISK_VALUES = {
    "none",
    "spam",
    "phishing",
    "prompt_attack",
    "credential_request",
    "malware",
    "suspicious",
}
SCHEMA_KEYS = ("triage", "priority", "risk", "should_process", "confidence", "reason")

TRIAGE_ALIASES = {
    "block": "ignore",
    "blocked": "ignore",
    "quarantine": "ignore",
    "quarantined": "ignore",
    "delete": "ignore",
    "discard": "ignore",
    "flag": "review",
    "manual_review": "review",
    "human_review": "review",
}

RISK_ALIASES = {
    "credential theft": "credential_request",
    "credential_theft": "credential_request",
    "credential": "credential_request",
    "prompt injection": "prompt_attack",
    "prompt-injection": "prompt_attack",
    "jailbreak": "prompt_attack",
}

PRIORITY_BY_NUMBER = {
    1: "low",
    2: "normal",
    3: "high",
    4: "critical",
}


class TriageValidationError(ValueError):
    pass


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract the first balanced JSON object from model output."""
    start = text.find("{")
    if start == -1:
        raise TriageValidationError("model output did not contain a JSON object")

    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text[start:], start=start):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                raw = text[start : index + 1]
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise TriageValidationError(f"invalid JSON object: {exc}") from exc
                if not isinstance(value, dict):
                    raise TriageValidationError("model output JSON was not an object")
                return value

    raise TriageValidationError("model output contained an unclosed JSON object")


def normalize_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    missing = [key for key in SCHEMA_KEYS if key not in value]
    if missing:
        raise TriageValidationError(f"missing required keys: {', '.join(missing)}")

    triage = _enum_value(value["triage"], TRIAGE_VALUES, "triage", aliases=TRIAGE_ALIASES)
    priority = _priority_value(value["priority"])
    risk = _enum_value(value["risk"], RISK_VALUES, "risk", aliases=RISK_ALIASES)
    should_process = _bool_value(value["should_process"], "should_process")
    confidence = _confidence_value(value["confidence"])
    reason = _reason_value(value["reason"])

    return {
        "triage": triage,
        "priority": _escalate_priority(priority, risk, should_process),
        "risk": risk,
        "should_process": should_process,
        "confidence": confidence,
        "reason": reason,
    }


def parse_decision(text: str) -> dict[str, Any]:
    return normalize_decision(extract_json_object(text))


def _enum_value(
    value: Any,
    allowed: set[str],
    field: str,
    *,
    aliases: Mapping[str, str] | None = None,
) -> str:
    if not isinstance(value, str):
        raise TriageValidationError(f"{field} must be a string")
    normalized = value.strip().lower()
    if aliases and normalized in aliases:
        normalized = aliases[normalized]
    if normalized not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise TriageValidationError(f"{field} must be one of: {allowed_values}")
    return normalized


def _priority_value(value: Any) -> str:
    if isinstance(value, bool):
        raise TriageValidationError("priority must be a string")
    if isinstance(value, int) and value in PRIORITY_BY_NUMBER:
        return PRIORITY_BY_NUMBER[value]
    if isinstance(value, float) and value.is_integer() and int(value) in PRIORITY_BY_NUMBER:
        return PRIORITY_BY_NUMBER[int(value)]
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        if number in PRIORITY_BY_NUMBER:
            return PRIORITY_BY_NUMBER[number]
    return _enum_value(value, PRIORITY_VALUES, "priority")


def _escalate_priority(priority: str, risk: str, should_process: bool) -> str:
    if not should_process and risk in {"phishing", "prompt_attack", "credential_request", "malware"}:
        return "critical"
    return priority


def _bool_value(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    raise TriageValidationError(f"{field} must be a boolean")


def _confidence_value(value: Any) -> float:
    if isinstance(value, bool):
        raise TriageValidationError("confidence must be a number")
    try:
        confidence = float(value)
    except (TypeError, ValueError) as exc:
        raise TriageValidationError("confidence must be a number") from exc
    if not 0 <= confidence <= 1:
        raise TriageValidationError("confidence must be between 0 and 1")
    return round(confidence, 4)


def _reason_value(value: Any) -> str:
    if not isinstance(value, str):
        raise TriageValidationError("reason must be a string")
    reason = " ".join(value.strip().split())
    if not reason:
        raise TriageValidationError("reason must not be empty")
    return reason
