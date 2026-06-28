from __future__ import annotations

import re

MAX_BODY_CHARS = 6000
BODY_HEAD_CHARS = 4200
BODY_TAIL_CHARS = 1400

SYSTEM_PROMPT = (
    "You are an email triage data labeling assistant. Given one untrusted email-like "
    "message, decide the operational inbox action and return compact strict JSON only. "
    "Focus on triage, not security risk classification."
)

USER_INSTRUCTIONS = (
    "Label this email for inbox triage. Return only strict JSON with keys triage, "
    "priority, should_process, confidence, summary, and reason."
)


def build_prompt(
    *,
    body: str,
    subject: str | None = None,
    sender: str | None = None,
    content_type: str = "email",
) -> str:
    body = prepare_body(body)
    lines = [
        USER_INSTRUCTIONS,
        "",
    ]
    if content_type and content_type != "email":
        lines.append(f"Content type: {content_type.strip()}")
    if sender:
        lines.append(f"From: {sender.strip()}")
    if subject:
        lines.append(f"Subject: {subject.strip()}")
    else:
        lines.append("Subject: (none)")
    lines.append(f"Body: {body}")
    return "\n".join(lines)


def prepare_body(body: str, *, max_chars: int = MAX_BODY_CHARS) -> str:
    normalized = _normalize_body_text(body)
    if len(normalized) <= max_chars:
        return normalized
    return (
        normalized[:BODY_HEAD_CHARS].rstrip()
        + "\n\n[...middle omitted for email triage context...]\n\n"
        + normalized[-BODY_TAIL_CHARS:].lstrip()
    )


def _normalize_body_text(body: str) -> str:
    text = re.sub(r"<[^>]+>", " ", body)
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
