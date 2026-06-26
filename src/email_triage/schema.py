from __future__ import annotations

import json
import re
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
    "action": "review",
    "action_required": "review",
    "allow": "review",
    "allowed": "review",
    "block": "ignore",
    "blocked": "ignore",
    "business": "review",
    "clean": "review",
    "quarantine": "ignore",
    "quarantined": "ignore",
    "delete": "ignore",
    "discard": "ignore",
    "forward": "review",
    "forwarded": "review",
    "spam": "archive",
    "flag": "review",
    "important": "review",
    "inbox": "review",
    "legitimate": "review",
    "marketing": "archive",
    "manual_review": "review",
    "human_review": "review",
    "newsletter": "archive",
    "normal": "review",
    "ok": "review",
    "pass": "review",
    "passed": "review",
    "process": "review",
    "processed": "review",
    "promote": "archive",
    "promotional": "archive",
    "respond": "reply",
    "response": "reply",
    "safe": "review",
    "security_review": "review",
    "through": "review",
}

RISK_ALIASES = {
    "benign": "none",
    "clean": "none",
    "credential theft": "credential_request",
    "credential_theft": "credential_request",
    "credential": "credential_request",
    "credential phishing": "credential_request",
    "credential_phishing": "credential_request",
    "credentials": "credential_request",
    "none detected": "none",
    "no risk": "none",
    "no_risk": "none",
    "not suspicious": "none",
    "not_suspicious": "none",
    "ok": "none",
    "false": "none",
    "prompt injection": "prompt_attack",
    "prompt_injection": "prompt_attack",
    "prompt-injection": "prompt_attack",
    "prompt abuse": "prompt_attack",
    "prompt_abuse": "prompt_attack",
    "prompt-abuse": "prompt_attack",
    "prompt attack": "prompt_attack",
    "prompt-attack": "prompt_attack",
    "safe": "none",
    "scam": "phishing",
    "tool abuse": "prompt_attack",
    "tool_abuse": "prompt_attack",
    "tool-abuse": "prompt_attack",
    "jailbreak": "prompt_attack",
    "virus": "malware",
}

PRIORITY_ALIASES = {
    "medium": "normal",
    "moderate": "normal",
    "standard": "normal",
    "urgent": "critical",
}

PRIORITY_BY_NUMBER = {
    0: "low",
    1: "low",
    2: "normal",
    3: "high",
    4: "critical",
}

RISK_BY_NUMBER = {
    0: "none",
    1: "suspicious",
    2: "spam",
    3: "phishing",
    4: "prompt_attack",
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
                    try:
                        value = json.loads(_repair_common_json_drift(raw))
                    except json.JSONDecodeError:
                        raise TriageValidationError(f"invalid JSON object: {exc}") from exc
                if not isinstance(value, dict):
                    raise TriageValidationError("model output JSON was not an object")
                return value

    raise TriageValidationError("model output contained an unclosed JSON object")


def _repair_common_json_drift(raw: str) -> str:
    return re.sub(r'"(risk|triage|priority)"\s*:\s*"([^"]+),""([a-z_]+)"\s*:', r'"\1":"\2","\3":', raw)


def normalize_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    value = _repair_missing_fields(dict(value))
    missing = [key for key in SCHEMA_KEYS if key not in value]
    if missing:
        raise TriageValidationError(f"missing required keys: {', '.join(missing)}")

    risk = _risk_value(value["risk"])
    should_process = _bool_value(value["should_process"], "should_process")
    triage = _triage_value(value["triage"], risk, should_process)
    priority = _priority_value(value["priority"])
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


def _repair_missing_fields(value: dict[str, Any]) -> dict[str, Any]:
    if "risk" in value and "triage" not in value:
        risk = str(value["risk"]).strip().lower()
        risk = RISK_ALIASES.get(risk, risk)
        should_process = value.get("should_process")
        if risk in {"phishing", "prompt_attack", "credential_request", "malware"}:
            value["triage"] = "ignore"
        elif risk == "spam":
            value["triage"] = "archive"
        elif should_process is False or str(should_process).strip().lower() == "false":
            value["triage"] = "archive"
        else:
            value["triage"] = "review"

    if "risk" not in value and "triage" in value:
        triage = str(value["triage"]).strip().lower()
        value["risk"] = "spam" if triage == "spam" else "none"

    if "should_process" not in value and "risk" in value:
        risk = str(value["risk"]).strip().lower()
        risk = RISK_ALIASES.get(risk, risk)
        value["should_process"] = risk not in {
            "spam",
            "phishing",
            "prompt_attack",
            "credential_request",
            "malware",
        }

    if "priority" not in value and "risk" in value:
        risk = str(value["risk"]).strip().lower()
        risk = RISK_ALIASES.get(risk, risk)
        value["priority"] = "critical" if risk in {
            "phishing",
            "prompt_attack",
            "credential_request",
            "malware",
        } else "normal"

    if "confidence" not in value:
        value["confidence"] = 0.5

    if "reason" not in value:
        value["reason"] = "Model omitted a reason."

    return value


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


def _triage_value(value: Any, risk: str, should_process: bool) -> str:
    if risk in {"phishing", "prompt_attack", "credential_request", "malware"}:
        return "ignore"
    if risk == "spam" or not should_process:
        return "archive"
    try:
        return _enum_value(value, TRIAGE_VALUES, "triage", aliases=TRIAGE_ALIASES)
    except TriageValidationError:
        return "review"


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
    return _enum_value(value, PRIORITY_VALUES, "priority", aliases=PRIORITY_ALIASES)


def _risk_value(value: Any) -> str:
    if isinstance(value, bool):
        raise TriageValidationError("risk must be a string")
    if isinstance(value, int) and value in RISK_BY_NUMBER:
        return RISK_BY_NUMBER[value]
    if isinstance(value, float) and value.is_integer() and int(value) in RISK_BY_NUMBER:
        return RISK_BY_NUMBER[int(value)]
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        if number in RISK_BY_NUMBER:
            return RISK_BY_NUMBER[number]
    return _enum_value(value, RISK_VALUES, "risk", aliases=RISK_ALIASES)


def _escalate_priority(priority: str, risk: str, should_process: bool) -> str:
    if not should_process and risk in {"phishing", "prompt_attack", "credential_request", "malware"}:
        return "critical"
    return priority


def _bool_value(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1", "process", "should_process"}:
            return True
        if normalized in {"false", "no", "n", "0", "do_not_process", "do not process"}:
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
