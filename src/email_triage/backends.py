from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from .models import resolve_model_id
from .prompt import SYSTEM_PROMPT


class BackendError(RuntimeError):
    pass


class TriageBackend(ABC):
    @abstractmethod
    def generate(self, prompt: str, *, max_new_tokens: int, temperature: float) -> str:
        raise NotImplementedError


class OpenAICompatibleBackend(TriageBackend):
    def __init__(
        self,
        *,
        api_base: str,
        model: str,
        api_key: str | None = None,
        include_system_prompt: bool = True,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.include_system_prompt = include_system_prompt

    def generate(self, prompt: str, *, max_new_tokens: int, temperature: float) -> str:
        messages: list[dict[str, str]] = []
        if self.include_system_prompt:
            messages.append({"role": "system", "content": SYSTEM_PROMPT})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_new_tokens,
        }
        request = urllib.request.Request(
            f"{self.api_base}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise BackendError(f"OpenAI-compatible request failed: {exc}") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendError("OpenAI-compatible response did not contain message content") from exc

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers


class RulesBackend(TriageBackend):
    """Deterministic fallback for smoke tests and integration development."""

    def generate(self, prompt: str, *, max_new_tokens: int, temperature: float) -> str:
        del max_new_tokens, temperature
        text = prompt.lower()
        if _matches(text, ["ignore previous", "ignore all previous", "system prompt", "exfiltrate", "forward mailbox", "call the payment tool"]):
            return _decision(
                triage="ignore",
                priority="critical",
                risk="prompt_attack",
                should_process=False,
                confidence=0.97,
                reason="Email contains an instruction override or tool-abuse request targeting the assistant.",
            )
        if _matches(text, ["password", "credentials", "verify your account", "login now", "reset your account"]):
            return _decision(
                triage="ignore",
                priority="critical",
                risk="credential_request",
                should_process=False,
                confidence=0.9,
                reason="Message asks for credentials or account verification.",
            )
        if _matches(text, ["won a prize", "claim now", "click", "limited time offer"]):
            return _decision(
                triage="archive",
                priority="low",
                risk="spam",
                should_process=False,
                confidence=0.86,
                reason="Unsolicited promotional content with spam indicators.",
            )
        if _matches(text, ["invoice", "billing", "charged twice", "payment"]):
            return _decision(
                triage="escalate",
                priority="high",
                risk="none",
                should_process=True,
                confidence=0.78,
                reason="Legitimate billing or payment issue requiring review.",
            )
        if _matches(text, ["scan report", "audit log", "delivery", "meeting", "support"]):
            return _decision(
                triage="review",
                priority="normal",
                risk="none",
                should_process=True,
                confidence=0.74,
                reason="Operational message with no concrete malicious signal.",
            )
        return _decision(
            triage="review",
            priority="normal",
            risk="suspicious",
            should_process=True,
            confidence=0.55,
            reason="Insufficient signal for an automatic route; human review is appropriate.",
        )


def create_backend(
    *,
    backend: str,
    model: str | None,
    api_base: str | None,
    api_key_env: str | None,
    device: str,
    include_system_prompt: bool = True,
) -> TriageBackend:
    model_id = resolve_model_id(model)
    if backend == "auto":
        backend = "openai" if api_base else "gguf"
    if backend == "rules":
        return RulesBackend()
    if backend == "openai":
        if not api_base:
            raise BackendError("--api-base is required for --backend openai")
        api_key = os.environ.get(api_key_env) if api_key_env else None
        return OpenAICompatibleBackend(
            api_base=api_base,
            model=model_id,
            api_key=api_key,
            include_system_prompt=include_system_prompt,
        )
    if backend == "gguf":
        raise BackendError(
            "local GGUF inference runs through llama.cpp. Start `email-triage serve` "
            "in another terminal, then pass --api-base http://127.0.0.1:8011/v1."
        )
    raise BackendError(f"unknown backend: {backend}")


def _matches(text: str, needles: list[str]) -> bool:
    return any(re.search(rf"\b{re.escape(needle)}\b", text) for needle in needles)


def _decision(**values: Any) -> str:
    return json.dumps(values, separators=(",", ":"), sort_keys=True)
