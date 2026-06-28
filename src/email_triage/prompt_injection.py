from __future__ import annotations

import os
import re
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Protocol

if TYPE_CHECKING:
    from .harness import EmailInput


DEFAULT_PROMPT_INJECTION_REPO = "weijianzhg/prompt-injection-classifier"
DEFAULT_PROMPT_INJECTION_FILENAME = "model.joblib"
DEFAULT_PROMPT_INJECTION_REVISION = "main"
DEFAULT_PROMPT_INJECTION_THRESHOLD = 0.8
DEFAULT_TEXT_CHUNK_CHARS = 6000
DEFAULT_TEXT_CHUNK_OVERLAP = 400
DEFAULT_CACHE_ENV = "EMAIL_TRIAGE_CACHE_DIR"


class PromptInjectionGateError(RuntimeError):
    pass


@dataclass(frozen=True)
class PromptInjectionResult:
    is_risky: bool
    confidence: float
    reason: str
    source: str


class PromptInjectionGate(Protocol):
    def check(self, email: "EmailInput") -> PromptInjectionResult:
        raise NotImplementedError


class PatternPromptInjectionGate:
    """Small deterministic fallback for tests and offline smoke checks."""

    def check(self, email: "EmailInput") -> PromptInjectionResult:
        from .guardrails import PROMPT_ATTACK_PATTERNS

        text = _email_text(email)
        is_risky = any(re.search(pattern, text.lower()) for pattern in PROMPT_ATTACK_PATTERNS)
        return PromptInjectionResult(
            is_risky=is_risky,
            confidence=0.9 if is_risky else 0.0,
            reason=(
                "Heuristic prompt-injection pattern matched."
                if is_risky
                else "No heuristic prompt-injection pattern matched."
            ),
            source="heuristic",
        )


class SklearnPromptInjectionGate:
    def __init__(
        self,
        *,
        repo_id: str = DEFAULT_PROMPT_INJECTION_REPO,
        filename: str = DEFAULT_PROMPT_INJECTION_FILENAME,
        revision: str = DEFAULT_PROMPT_INJECTION_REVISION,
        cache_dir: Path | None = None,
        threshold: float = DEFAULT_PROMPT_INJECTION_THRESHOLD,
        chunk_chars: int = DEFAULT_TEXT_CHUNK_CHARS,
        chunk_overlap: int = DEFAULT_TEXT_CHUNK_OVERLAP,
    ) -> None:
        self.repo_id = repo_id
        self.filename = filename
        self.revision = revision
        self.cache_dir = cache_dir
        self.threshold = threshold
        self.chunk_chars = chunk_chars
        self.chunk_overlap = chunk_overlap
        self._model = None

    def check(self, email: "EmailInput") -> PromptInjectionResult:
        chunks = _text_chunks(_email_text(email), chunk_chars=self.chunk_chars, overlap=self.chunk_overlap)
        model = self._load_model()
        labels = list(model.predict(chunks))
        scores = _malicious_scores(model, chunks)
        best_score = max(scores) if scores else 0.0
        classifier_risky = any(
            _is_malicious_label(label) and score >= self.threshold
            for label, score in zip(labels, scores, strict=False)
        )
        heuristic = PatternPromptInjectionGate().check(email)
        is_risky = classifier_risky or heuristic.is_risky
        confidence = max(best_score, heuristic.confidence if heuristic.is_risky else 0.0)
        blocked_chunks = sum(
            score >= self.threshold and _is_malicious_label(label)
            for label, score in zip(labels, scores, strict=False)
        )
        return PromptInjectionResult(
            is_risky=is_risky,
            confidence=_clamp(confidence if is_risky else 1.0 - best_score),
            reason=(
                f"Prompt-injection classifier blocked {blocked_chunks} of {len(labels)} text chunk(s)."
                if is_risky
                else f"Prompt-injection classifier found no risky chunks across {len(labels)} text chunk(s)."
            ),
            source=self.repo_id,
        )

    def _load_model(self):
        if self._model is not None:
            return self._model
        _install_pickle_compat_classes()
        try:
            import joblib
            from huggingface_hub import hf_hub_download
            from sklearn.exceptions import InconsistentVersionWarning
        except Exception as exc:  # noqa: BLE001 - turn optional import details into one useful error.
            raise PromptInjectionGateError(
                "prompt-injection classifier requires joblib, scikit-learn, and huggingface-hub"
            ) from exc

        cache_dir = self.cache_dir or _default_classifier_cache_dir()
        path = hf_hub_download(
            repo_id=self.repo_id,
            filename=self.filename,
            revision=self.revision,
            cache_dir=str(cache_dir) if cache_dir else None,
            token=_hf_token(),
        )
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InconsistentVersionWarning)
                self._model = joblib.load(path)
        except Exception as exc:  # noqa: BLE001 - joblib can raise several pickle/sklearn errors.
            raise PromptInjectionGateError(f"failed to load prompt-injection classifier from {path}: {exc}") from exc
        return self._model


class ConservativeEnsemble:
    """Compatibility class for the Hugging Face joblib artifact."""

    def predict(self, values):
        svc_predictions = self.svc_.predict(values)
        lr_predictions = self.lr_.predict(values)
        return ((svc_predictions + lr_predictions) >= 2).astype(int)

    def predict_proba(self, values):
        return self.lr_.predict_proba(values)


class TextFeatures:
    """Compatibility transformer for the classifier's hand-written features."""

    INJECTION_KEYWORDS = [
        "ignore",
        "disregard",
        "forget",
        "pretend",
        "roleplay",
        "jailbreak",
        "bypass",
        "override",
        "sudo",
        "admin",
        "system prompt",
        "instructions",
        "do anything now",
        "dan",
        "previous instructions",
        "new instructions",
    ]

    def fit(self, values, y=None):
        del values, y
        return self

    def transform(self, values):
        import numpy as np
        from scipy.sparse import csr_matrix

        n_base = 7
        features = np.zeros((len(values), n_base + len(self.INJECTION_KEYWORDS)), dtype=np.float64)
        for index, value in enumerate(values):
            text = str(value)
            lower = text.lower()
            words = text.split()
            features[index, 0] = len(text)
            features[index, 1] = sum(
                1 for char in text if not char.isalnum() and not char.isspace()
            ) / max(len(text), 1)
            features[index, 2] = sum(1 for char in text if char.isupper()) / max(len(text), 1)
            features[index, 3] = text.count("\n")
            features[index, 4] = len(re.findall(r"[{}()\[\]<>]", text)) / max(len(text), 1)
            features[index, 5] = len(words)
            features[index, 6] = np.mean([len(word) for word in words]) if words else 0
            for keyword_index, keyword in enumerate(self.INJECTION_KEYWORDS):
                features[index, n_base + keyword_index] = 1.0 if keyword in lower else 0.0
        return csr_matrix(features)


def create_prompt_injection_gate(
    mode: str = "classifier",
    *,
    model_repo: str = DEFAULT_PROMPT_INJECTION_REPO,
    cache_dir: Path | None = None,
    threshold: float = DEFAULT_PROMPT_INJECTION_THRESHOLD,
) -> PromptInjectionGate | None:
    normalized = mode.strip().lower()
    if normalized in {"off", "none", "false", "disabled"}:
        return None
    if normalized == "heuristic":
        return PatternPromptInjectionGate()
    if normalized == "classifier":
        return SklearnPromptInjectionGate(repo_id=model_repo, cache_dir=cache_dir, threshold=threshold)
    raise PromptInjectionGateError("prompt-injection gate must be one of: classifier, heuristic, off")


def prompt_injection_decision(result: PromptInjectionResult) -> dict[str, object]:
    return {
        "triage": "ignore",
        "priority": "critical",
        "should_process": False,
        "confidence": max(result.confidence, 0.9),
        "summary": "Email was blocked before LLM triage because it matched prompt-injection signals.",
        "reason": "Prompt-injection gate blocked the email before LLM triage.",
    }


def _install_pickle_compat_classes() -> None:
    main = sys.modules.get("__main__")
    if main is None:
        return
    setattr(main, "ConservativeEnsemble", ConservativeEnsemble)
    setattr(main, "TextFeatures", TextFeatures)


def _email_text(email: "EmailInput") -> str:
    parts = []
    if email.sender:
        parts.append(f"From: {email.sender}")
    if email.subject:
        parts.append(f"Subject: {email.subject}")
    parts.append(email.body)
    return _normalize_text("\n".join(parts))


def _normalize_text(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _text_chunks(text: str, *, chunk_chars: int, overlap: int) -> list[str]:
    if not text:
        return [""]
    if len(text) <= chunk_chars:
        return [text]
    chunks = []
    start = 0
    step = max(chunk_chars - overlap, 1)
    while start < len(text):
        chunks.append(text[start : start + chunk_chars])
        start += step
    return chunks


def _malicious_scores(model, chunks: list[str]) -> list[float]:
    if hasattr(model, "predict_proba"):
        try:
            return [_clamp(float(row[1])) for row in model.predict_proba(chunks)]
        except Exception:
            pass
    return [0.9 if _is_malicious_label(label) else 0.1 for label in model.predict(chunks)]


def _is_malicious_label(label: object) -> bool:
    try:
        return int(label) == 1
    except (TypeError, ValueError):
        return str(label).strip().lower() in {"malicious", "prompt_injection", "prompt_attack", "jailbreak"}


def _default_classifier_cache_dir() -> Path | None:
    root = os.environ.get(DEFAULT_CACHE_ENV)
    return Path(root).expanduser() / "hf-cache" if root else None


def _hf_token() -> str | bool:
    return os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN") or False


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
