from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

TRIAGE_VALUES = {"reply", "archive", "escalate", "ignore", "review"}
PRIORITY_VALUES = {"low", "normal", "high", "critical"}
SCHEMA_KEYS = ("triage", "priority", "should_process", "confidence", "summary", "reason")
DECISION_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": list(SCHEMA_KEYS),
    "properties": {
        "triage": {"type": "string", "enum": sorted(TRIAGE_VALUES)},
        "priority": {"type": "string", "enum": sorted(PRIORITY_VALUES)},
        "should_process": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "summary": {"type": "string", "minLength": 1, "maxLength": 320},
        "reason": {"type": "string", "minLength": 1, "maxLength": 240},
    },
}

TRIAGE_ALIASES = {
    "action": "review",
    "action_required": "review",
    "allow": "review",
    "allowed": "review",
    "block": "ignore",
    "blocked": "ignore",
    "business": "review",
    "clean": "review",
    "delete": "ignore",
    "discard": "ignore",
    "flag": "review",
    "forward": "review",
    "forwarded": "review",
    "human_review": "review",
    "inbox": "review",
    "legitimate": "review",
    "manual_review": "review",
    "marketing": "archive",
    "newsletter": "archive",
    "ok": "review",
    "pass": "review",
    "process": "review",
    "promotional": "archive",
    "quarantine": "ignore",
    "quarantined": "ignore",
    "respond": "reply",
    "response": "reply",
    "safe": "review",
    "spam": "archive",
    "through": "review",
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
    return re.sub(
        r'"(summary|reason|triage|priority)"\s*:\s*"([^"]+),""([a-z_]+)"\s*:',
        r'"\1":"\2","\3":',
        raw,
    )


def normalize_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    value = _repair_missing_fields(dict(value))
    missing = [key for key in SCHEMA_KEYS if key not in value]
    if missing:
        raise TriageValidationError(f"missing required keys: {', '.join(missing)}")

    triage = _triage_value(value["triage"])
    priority = _priority_value(value["priority"])
    should_process = _bool_value(value["should_process"], "should_process")
    confidence = _confidence_value(value["confidence"])
    summary = _text_value(value["summary"], "summary", max_length=320)
    reason = _text_value(value["reason"], "reason", max_length=240)

    return {
        "triage": triage,
        "priority": priority,
        "should_process": _align_should_process(triage, should_process),
        "confidence": confidence,
        "summary": summary,
        "reason": reason,
    }


def parse_decision(text: str) -> dict[str, Any]:
    return normalize_decision(extract_json_object(text))


def _repair_missing_fields(value: dict[str, Any]) -> dict[str, Any]:
    if "triage" not in value and "risk" in value:
        risk = str(value["risk"]).strip().lower()
        if risk in {"phishing", "prompt_attack", "prompt-injection", "prompt_injection", "credential_request", "malware"}:
            value["triage"] = "ignore"
        elif risk == "spam":
            value["triage"] = "ignore"
        elif value.get("should_process") is False:
            value["triage"] = "archive"
        else:
            value["triage"] = "review"

    if "should_process" not in value and "triage" in value:
        triage = str(value["triage"]).strip().lower()
        value["should_process"] = triage not in {"archive", "ignore", "spam", "delete", "discard"}

    if "priority" not in value:
        value["priority"] = "normal"

    if "confidence" not in value:
        value["confidence"] = 0.5

    if "summary" not in value:
        value["summary"] = value.get("reason", "No summary provided.")

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


def _triage_value(value: Any) -> str:
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


def _text_value(value: Any, field: str, *, max_length: int) -> str:
    if not isinstance(value, str):
        raise TriageValidationError(f"{field} must be a string")
    text = " ".join(value.strip().split())
    if not text:
        raise TriageValidationError(f"{field} must not be empty")
    return text[:max_length]


def _align_should_process(triage: str, should_process: bool) -> bool:
    if triage in {"archive", "ignore"}:
        return False
    if triage in {"reply", "escalate", "review"}:
        return True
    return should_process
