from __future__ import annotations


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
