from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

from .models import resolve_model_id
from .prompt import SYSTEM_PROMPT
from .schema import DECISION_JSON_SCHEMA


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
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "email_triage_decision",
                    "schema": DECISION_JSON_SCHEMA,
                    "strict": True,
                },
            },
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


def create_backend(
    *,
    model: str | None,
    api_base: str | None,
    api_key_env: str | None,
    include_system_prompt: bool = True,
) -> TriageBackend:
    model_id = resolve_model_id(model)
    if not api_base:
        raise BackendError(
            "local GGUF inference runs through llama.cpp. Start `email-triage serve` "
            "in another terminal, then pass --api-base http://127.0.0.1:8011/v1."
        )
    api_key = os.environ.get(api_key_env) if api_key_env else None
    return OpenAICompatibleBackend(
        api_base=api_base,
        model=model_id,
        api_key=api_key,
        include_system_prompt=include_system_prompt,
    )
