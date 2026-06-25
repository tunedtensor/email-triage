from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelPreset:
    name: str
    model_id: str
    description: str


MODEL_PRESETS: dict[str, ModelPreset] = {
    "small": ModelPreset(
        name="small",
        model_id="weijianzhg/email-safety-triage-qwen3.5-2b",
        description="Qwen 3.5 2B fine-tuned for strict JSON email safety triage.",
    ),
}


def resolve_model_id(model: str | None) -> str:
    if not model:
        return MODEL_PRESETS["small"].model_id
    preset = MODEL_PRESETS.get(model)
    return preset.model_id if preset else model

